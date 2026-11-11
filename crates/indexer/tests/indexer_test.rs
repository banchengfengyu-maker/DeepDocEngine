use deepdoc_indexer::IndexStore;
use deepdoc_protocol::{
    ExtractedDocument, RuleDefinition, RuleMatchMode, RuleSet, SearchQuery, SegmentScope,
    TextSegment,
};
use deepdoc_rule_engine::CompiledRuleSet;

#[test]
fn large_doc_no_truncation_jieba_ngram_and_rule_cache() {
    let tmp = std::env::temp_dir().join(format!("deepdoc_idx_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let store = IndexStore::open(&tmp).unwrap();

    // > 150 KB body to prove zero 100KB truncation
    let mut big_body = "前面是常规项目技术说明书内容。\n".repeat(4000);
    big_body.push_str("\n关键条款：内部绝密采购预算金额为 8800 万元。\n");

    let doc = ExtractedDocument {
        virtual_path: r"D:\docs\archive.zip!\工程说明.docx".into(),
        file_name: "工程说明.docx".into(),
        detected_format: "docx".into(),
        blake3_hex: "hash_large_001".into(),
        byte_size: big_body.len() as u64,
        encrypted: false,
        segments: vec![
            TextSegment {
                scope: SegmentScope::HeadTail,
                location_label: "文档首尾行".into(),
                text: "绝密 ★ 工程说明书\n末行条款".into(),
            },
            TextSegment {
                scope: SegmentScope::Body,
                location_label: "正文 (word/document.xml)".into(),
                text: big_body,
            },
        ],
        metadata: vec![("author".into(), "test".into())],
        warnings: vec![],
    };

    let doc_id = store.upsert_document(r"D:\docs", &doc, 123456, "ok").unwrap();
    store.commit().unwrap();

    // Search tail phrase beyond 100KB boundary via Tantivy
    let (total, hits) = store
        .search(&SearchQuery {
            text: "8800".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(hits[0].doc_id, doc_id);
    assert!(hits[0].snippets[0].snippet.contains("8800"));

    // Preview must retrieve untruncated tail text too
    let prev = store
        .get_preview(doc_id, &["8800".into()], 500_000)
        .unwrap();
    assert!(!prev.truncated);
    assert!(prev.segments[1].text.contains("8800"));

    // Rule evaluation + rule_hit_cache
    let rs = RuleSet {
        ruleset_id: "t1".into(),
        rules: vec![RuleDefinition {
            id: "r1".into(),
            name: "涉密采购".into(),
            category: "涉密".into(),
            severity: "Critical".into(),
            expression: r#"scope:head_tail(re:/绝密\s*★/) & "预算金额""#.into(),
            mode: RuleMatchMode::FullHits,
        }],
    };
    let compiled = CompiledRuleSet::compile(&rs).unwrap();
    let eval1 = store.evaluate_rules_over_store(&compiled, None).unwrap();
    assert_eq!(eval1.len(), 1);
    let eval2 = store.evaluate_rules_over_store(&compiled, None).unwrap();
    assert_eq!(eval2.len(), 1);

    drop(store);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn chinese_long_compound_and_filename_tokenization() {
    let tmp = std::env::temp_dir().join(format!("deepdoc_idx_tok_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let store = IndexStore::open(&tmp).unwrap();

    let doc = ExtractedDocument {
        virtual_path: r"D:\00.zip!/申请报告-新.docx".into(),
        file_name: "申请报告-新.docx".into(),
        detected_format: "docx".into(),
        blake3_hex: "hash_tok_001".into(),
        byte_size: 128,
        encrypted: false,
        segments: vec![TextSegment {
            scope: SegmentScope::Body,
            location_label: "正文".into(),
            text: "2026关于暴雨强度公式拟合的给排水项目申报材料，含太原武宿国际机场西边指廊数据。".into(),
        }],
        metadata: vec![],
        warnings: vec![],
    };

    store.upsert_document(r"D:\00.zip", &doc, 100, "ok").unwrap();
    store.commit().unwrap();

    for q in [
        "申请报告",
        "申请报告-新",
        "暴雨强度",
        "机场西边指廊",
        "申请 报告",
        "排水",
        "西边指",
        "2026 排水",
        "docx",
    ] {
        let (total, _) = store
            .search(&SearchQuery {
                text: q.into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 1, "expected 1 hit for query {q:?}, got {total}");
    }

    for neg_q in ["申请报告-旧", "机场东边指廊", "申请请报"] {
        let (total, _) = store
            .search(&SearchQuery {
                text: neg_q.into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 0, "expected 0 false positives for {neg_q:?}, got {total}");
    }

    drop(store);
    let _ = std::fs::remove_dir_all(&tmp);
}
