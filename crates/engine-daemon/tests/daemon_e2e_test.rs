#[cfg(windows)]
mod windows_e2e {
    use deepdoc_protocol::framing::async_codec::{read_frame_async, write_frame_async};
    use deepdoc_protocol::{
        ClientEnvelope, ClientRequest, DaemonMessage, RuleDefinition, RuleMatchMode, RuleSet,
        ScanOptions, SearchQuery,
    };
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use tokio::net::windows::named_pipe::ClientOptions;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cur = std::io::Cursor::new(Vec::new());
        {
            let mut zw = ZipWriter::new(&mut cur);
            let opts = SimpleFileOptions::default();
            for (name, data) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(data).unwrap();
            }
            zw.finish().unwrap();
        }
        cur.into_inner()
    }

    fn workspace_bin(name: &str) -> PathBuf {
        let test_exe = std::env::current_exe().unwrap();
        // target/debug/deps/test.exe -> target/debug/<name>
        test_exe.parent().unwrap().parent().unwrap().join(name)
    }

    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[tokio::test]
    async fn full_daemon_pipe_worker_tantivy_e2e() {
        let daemon_exe = workspace_bin("engine-daemon.exe");
        let parser_exe = workspace_bin("parser-worker.exe");
        let ext_exe = workspace_bin("ext-worker.exe");
        if !daemon_exe.exists() || !parser_exe.exists() {
            // Skip gracefully if `cargo test` was invoked before binaries were built
            eprintln!("skipping daemon_e2e_test: build workspace binaries first");
            return;
        }
        assert!(ext_exe.exists(), "ext-worker.exe should exist next to engine-daemon.exe");

        let pid = std::process::id();
        let tmp_root = std::env::temp_dir().join(format!("deepdoc_e2e_{pid}"));
        let _ = std::fs::remove_dir_all(&tmp_root);
        let docs_dir = tmp_root.join("docs");
        let data_dir = tmp_root.join("data");
        std::fs::create_dir_all(&docs_dir).unwrap();

        // Populate test documents: TXT (GBK), DOCX, OFD, ZIP, DXF, DWG header
        let (gbk_txt, _, _) = encoding_rs::GB18030.encode("绝密 ★ 2026\n内部采购方案预算总额5000万\n末行归档");
        std::fs::write(docs_dir.join("notice.txt"), &gbk_txt).unwrap();

        let docx = make_zip(&[(
            "word/document.xml",
            r#"<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>本项目招标采购预算需要严格保密</w:t></w:r></w:p></w:body></w:document>"#.as_bytes(),
        )]);
        std::fs::write(docs_dir.join("plan.docx"), &docx).unwrap();

        let inner_zip = make_zip(&[(
            "nested.txt",
            "压缩包内的隐藏招标预算参数".as_bytes(),
        )]);
        std::fs::write(docs_dir.join("bundle.zip"), &inner_zip).unwrap();

        std::fs::write(
            docs_dir.join("drawing.dxf"),
            b"0\nSECTION\n2\nENTITIES\n0\nTEXT\n8\nWALL\n10\n0\n20\n0\n40\n1\n1\nCAD_BUDGET_KEY\n0\nENDSEC\n0\nEOF\n",
        )
        .unwrap();
        std::fs::write(docs_dir.join("sample.dwg"), b"AC1032\x00\x00\x00\x00").unwrap();

        let pipe_name = format!(r"\\.\pipe\DeepDocEngine.test.{pid}");
        let mut child_guard = ChildGuard(
            Command::new(&daemon_exe)
                .arg("--pipe")
                .arg(&pipe_name)
                .arg("--data-dir")
                .arg(&data_dir)
                .arg("--workers")
                .arg("2")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn engine-daemon"),
        );

        // Wait for Named Pipe
        let mut client = None;
        for _ in 0..40 {
            match ClientOptions::new().open(&pipe_name) {
                Ok(c) => {
                    client = Some(c);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
        let pipe = client.expect("connect to daemon pipe");
        let (mut reader, mut writer) = tokio::io::split(pipe);

        // 1. Ping
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 1,
                request: ClientRequest::Ping,
            },
        )
        .await
        .unwrap();
        let pong: DaemonMessage = read_frame_async(&mut reader).await.unwrap();
        match pong {
            DaemonMessage::Pong {
                worker_engines,
                ext_worker_engines,
                ..
            } => {
                assert!(!worker_engines.is_empty());
                assert!(!ext_worker_engines.is_empty());
            }
            other => panic!("expected Pong, got {other:?}"),
        }

        // 2. StartScan with RuleSet
        let rs = RuleSet {
            ruleset_id: "e2e-rs".into(),
            rules: vec![RuleDefinition {
                id: "r-budget".into(),
                name: "招标预算".into(),
                category: "涉密".into(),
                severity: "Critical".into(),
                expression: r#"(招标 | 采购方案) & 预算"#.into(),
                mode: RuleMatchMode::FullHits,
            }],
        };

        // Ignored lock temp file (filtered by excluded_name_globs)
        std::fs::write(docs_dir.join("~$lock_temp.txt"), "应被过滤的临时文件招标预算".as_bytes()).unwrap();

        let mut scan_opts = ScanOptions::default();
        scan_opts.excluded_name_globs = vec!["~$*".into()];

        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 2,
                request: ClientRequest::StartScan {
                    job_id: "job-1".into(),
                    roots: vec![docs_dir.to_string_lossy().into_owned()],
                    ruleset: Some(rs.clone()),
                    options: scan_opts.clone(),
                },
            },
        )
        .await
        .unwrap();

        let mut hit_count = 0usize;
        let summary;
        loop {
            let msg: DaemonMessage = read_frame_async(&mut reader).await.unwrap();
            match msg {
                DaemonMessage::Ack { ok, .. } => assert!(ok),
                DaemonMessage::ScanProgress { .. } => {}
                DaemonMessage::ScanHit { .. } => hit_count += 1,
                DaemonMessage::ScanCompleted { summary: s, .. } => {
                    summary = s;
                    break;
                }
                other => panic!("unexpected during scan: {other:?}"),
            }
        }
        assert_eq!(summary.scanned_files, 5);
        assert_eq!(summary.parsed_ok, 5);
        assert_eq!(summary.child_docs_indexed, 1); // nested.txt inside bundle.zip
        assert!(hit_count >= 3, "expected >=3 hits across txt/docx/bundle.zip, got {hit_count}");

        // 3. Search via Tantivy
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 3,
                request: ClientRequest::Search {
                    query: SearchQuery {
                        text: "CAD_BUDGET_KEY".into(),
                        ..Default::default()
                    },
                },
            },
        )
        .await
        .unwrap();
        let search_resp: DaemonMessage = read_frame_async(&mut reader).await.unwrap();
        let doc_id = match search_resp {
            DaemonMessage::SearchResult {
                total_hits, items, ..
            } => {
                assert_eq!(total_hits, 1);
                items[0].doc_id
            }
            other => panic!("expected SearchResult, got {other:?}"),
        };

        // 4. Preview
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 4,
                request: ClientRequest::GetDocumentPreview {
                    doc_id,
                    highlight_terms: vec!["CAD_BUDGET_KEY".into()],
                    max_chars: 50_000,
                },
            },
        )
        .await
        .unwrap();
        let prev_resp: DaemonMessage = read_frame_async(&mut reader).await.unwrap();
        match prev_resp {
            DaemonMessage::PreviewResult { doc, .. } => {
                assert_eq!(doc.detected_format, "dxf");
                assert!(doc.segments.iter().any(|s| !s.highlight_ranges.is_empty()));
            }
            other => panic!("expected PreviewResult, got {other:?}"),
        }

        // 5. Ad-hoc NEAR expression query via EvaluateRules
        let near_rs = RuleSet {
            ruleset_id: "near-rs".into(),
            rules: vec![RuleDefinition {
                id: "r-near".into(),
                name: "招标保密邻近检索".into(),
                category: "检索".into(),
                severity: "High".into(),
                expression: "NEAR(招标采购预算, 严格保密, 10)".into(),
                mode: RuleMatchMode::FirstHit,
            }],
        };
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 5,
                request: ClientRequest::EvaluateRules {
                    ruleset: near_rs,
                    doc_ids: None,
                    path_prefix: Some(docs_dir.to_string_lossy().into_owned()),
                    file_ext_filter: Some("docx,txt".into()),
                },
            },
        )
        .await
        .unwrap();
        match read_frame_async::<_, DaemonMessage>(&mut reader).await.unwrap() {
            DaemonMessage::RuleEvalResult { hits, .. } => {
                assert!(
                    hits.iter().any(|h| h.file_name == "plan.docx" && h.rule_id == "r-near"),
                    "expected NEAR match in plan.docx, got {hits:?}"
                );
            }
            other => panic!("expected RuleEvalResult, got {other:?}"),
        }

        // 6. Second incremental scan skips unchanged cached docs in O(1) snapshot
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 6,
                request: ClientRequest::StartScan {
                    job_id: "job-inc".into(),
                    roots: vec![docs_dir.to_string_lossy().into_owned()],
                    ruleset: None,
                    options: scan_opts.clone(),
                },
            },
        )
        .await
        .unwrap();
        loop {
            match read_frame_async::<_, DaemonMessage>(&mut reader).await.unwrap() {
                DaemonMessage::ScanCompleted { summary: s, .. } => {
                    assert_eq!(s.scanned_files, 5);
                    assert_eq!(s.skipped_cached, 5);
                    break;
                }
                DaemonMessage::Ack { .. } | DaemonMessage::ScanProgress { .. } => {}
                other => panic!("unexpected during incremental scan: {other:?}"),
            }
        }

        // 7. Ephemeral DirectSearch ("ripgrep-all" style) must find matches without touching DB/Tantivy
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 7,
                request: ClientRequest::GetStats,
            },
        )
        .await
        .unwrap();
        let docs_before_direct = match read_frame_async::<_, DaemonMessage>(&mut reader).await.unwrap() {
            DaemonMessage::StatsResult { stats, .. } => stats.total_documents,
            other => panic!("expected StatsResult, got {other:?}"),
        };

        let ephemeral_dir = tmp_root.join("ephemeral_usb");
        std::fs::create_dir_all(&ephemeral_dir).unwrap();
        let eph_zip = make_zip(&[("nested_usb.txt", "U盘压缩包 EPHEMERAL_DIRECT_KEY 机密".as_bytes())]);
        std::fs::write(ephemeral_dir.join("usb_bundle.zip"), &eph_zip).unwrap();
        std::fs::write(ephemeral_dir.join("notes.txt"), "普通日志无敏感字".as_bytes()).unwrap();

        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 8,
                request: ClientRequest::DirectSearch {
                    job_id: "job-direct".into(),
                    roots: vec![ephemeral_dir.to_string_lossy().into_owned()],
                    query: "EPHEMERAL_DIRECT_KEY".into(),
                    use_regex: false,
                    file_ext_filter: Some("txt".into()),
                    options: scan_opts.clone(),
                },
            },
        )
        .await
        .unwrap();

        let mut direct_hits = Vec::new();
        loop {
            match read_frame_async::<_, DaemonMessage>(&mut reader).await.unwrap() {
                DaemonMessage::Ack { ok, .. } => assert!(ok),
                DaemonMessage::ScanProgress { .. } => {}
                DaemonMessage::ScanHit { hit, .. } => direct_hits.push(hit),
                DaemonMessage::ScanCompleted { summary: s, .. } => {
                    assert_eq!(s.rule_hits, 1);
                    break;
                }
                other => panic!("unexpected during direct search: {other:?}"),
            }
        }
        assert_eq!(direct_hits.len(), 1);
        assert!(direct_hits[0].doc_id >= 1_000_000_000);
        assert_eq!(direct_hits[0].file_name, "nested_usb.txt");

        // Ephemeral preview works via cached ExtractedDocument in RAM
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 9,
                request: ClientRequest::GetDocumentPreview {
                    doc_id: direct_hits[0].doc_id,
                    highlight_terms: vec!["EPHEMERAL_DIRECT_KEY".into()],
                    max_chars: 10_000,
                },
            },
        )
        .await
        .unwrap();
        match read_frame_async::<_, DaemonMessage>(&mut reader).await.unwrap() {
            DaemonMessage::PreviewResult { doc, .. } => {
                assert!(doc.segments.iter().any(|s| !s.highlight_ranges.is_empty()));
            }
            other => panic!("expected ephemeral PreviewResult, got {other:?}"),
        }

        // Index count MUST remain completely unchanged after DirectSearch
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 10,
                request: ClientRequest::GetStats,
            },
        )
        .await
        .unwrap();
        match read_frame_async::<_, DaemonMessage>(&mut reader).await.unwrap() {
            DaemonMessage::StatsResult { stats, .. } => {
                assert_eq!(stats.total_documents, docs_before_direct);
            }
            other => panic!("expected StatsResult after direct search, got {other:?}"),
        }

        // 8. Directory filter, multi-ext filter, OR multi-keyword search, ResetIndexKeepOcr & DeepDeleteFiles
        let sub_dir = tmp_root.join("sub_folder_test");
        std::fs::create_dir_all(&sub_dir).unwrap();
        let victim_file = sub_dir.join("sensitive_secret.txt");
        std::fs::write(&victim_file, "保密项目 ALPHA_BETA_TOKEN 需要彻底销毁".as_bytes()).unwrap();

        // Incremental scan includes sub_folder_test
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 11,
                request: ClientRequest::StartScan {
                    job_id: "job-sub".into(),
                    roots: vec![sub_dir.to_string_lossy().into_owned()],
                    ruleset: None,
                    options: scan_opts,
                },
            },
        )
        .await
        .unwrap();
        loop {
            match read_frame_async::<_, DaemonMessage>(&mut reader).await.unwrap() {
                DaemonMessage::ScanCompleted { .. } => break,
                DaemonMessage::Ack { .. } | DaemonMessage::ScanProgress { .. } | DaemonMessage::ScanHit { .. } => {}
                other => panic!("unexpected during job-sub: {other:?}"),
            }
        }

        // Search scoped strictly to sub_folder_test with OR mode ("NO_SUCH_WORD ALPHA_BETA_TOKEN") + multi-ext
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 12,
                request: ClientRequest::Search {
                    query: SearchQuery {
                        text: "NO_SUCH_WORD ALPHA_BETA_TOKEN".into(),
                        file_ext_filter: Some("pdf,txt".into()),
                        path_prefix: Some(sub_dir.to_string_lossy().into_owned()),
                        match_all_terms: false,
                        ..Default::default()
                    },
                },
            },
        )
        .await
        .unwrap();
        match read_frame_async::<_, DaemonMessage>(&mut reader).await.unwrap() {
            DaemonMessage::SearchResult { total_hits, items, .. } => {
                assert_eq!(total_hits, 1);
                assert_eq!(items[0].file_name, "sensitive_secret.txt");
            }
            other => panic!("expected SearchResult for OR+dir+multi-ext, got {other:?}"),
        }

        // DeepDelete removes disk file gently AND purges it from index
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 13,
                request: ClientRequest::DeepDeleteFiles {
                    job_id: "job-del".into(),
                    paths: vec![victim_file.to_string_lossy().into_owned()],
                },
            },
        )
        .await
        .unwrap();
        loop {
            match read_frame_async::<_, DaemonMessage>(&mut reader).await.unwrap() {
                DaemonMessage::Ack { ok, .. } => assert!(ok),
                DaemonMessage::DeepDeleteProgress { .. } => {}
                DaemonMessage::DeepDeleteCompleted {
                    deleted_files,
                    purged_index_docs,
                    skipped_or_failed,
                    ..
                } => {
                    assert_eq!(deleted_files, 1);
                    assert_eq!(purged_index_docs, 1);
                    assert_eq!(skipped_or_failed, 0);
                    break;
                }
                other => panic!("unexpected during DeepDeleteFiles: {other:?}"),
            }
        }
        assert!(!victim_file.exists(), "victim_file must be wiped off disk");

        // Verify deleted document is also gone from search index
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 14,
                request: ClientRequest::Search {
                    query: SearchQuery {
                        text: "ALPHA_BETA_TOKEN".into(),
                        ..Default::default()
                    },
                },
            },
        )
        .await
        .unwrap();
        match read_frame_async::<_, DaemonMessage>(&mut reader).await.unwrap() {
            DaemonMessage::SearchResult { total_hits, .. } => assert_eq!(total_hits, 0),
            other => panic!("expected 0 hits after deep delete, got {other:?}"),
        }

        // Verify ResetIndexKeepOcr ack succeeds cleanly
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 15,
                request: ClientRequest::ResetIndexKeepOcr,
            },
        )
        .await
        .unwrap();
        match read_frame_async::<_, DaemonMessage>(&mut reader).await.unwrap() {
            DaemonMessage::Ack { ok, .. } => assert!(ok),
            other => panic!("expected Ack for ResetIndexKeepOcr, got {other:?}"),
        }

        // 9. Shutdown cleanly
        write_frame_async(
            &mut writer,
            &ClientEnvelope {
                req_id: 16,
                request: ClientRequest::Shutdown,
            },
        )
        .await
        .unwrap();
        let _ = read_frame_async::<_, DaemonMessage>(&mut reader).await;
        let _ = child_guard.0.wait();
        let _ = std::fs::remove_dir_all(&tmp_root);
    }
}
