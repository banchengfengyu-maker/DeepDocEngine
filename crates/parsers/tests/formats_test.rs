use deepdoc_parsers::{parse_bytes, ParserContext};
use deepdoc_protocol::{FailureKind, ParseOptions, SegmentScope};
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default();
        for (name, data) in entries {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap();
    }
    buf.into_inner()
}

fn make_png(width: u32, height: u32, striped: bool) -> Vec<u8> {
    use image::{ImageBuffer, Rgba};
    let img = ImageBuffer::from_fn(width, height, |x, y| {
        if striped && ((x + y) % 3 == 0) {
            Rgba([10u8, 20, 30, 255])
        } else {
            Rgba([240u8, 240, 240, 255])
        }
    });
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, image::ImageFormat::Png).unwrap();
    out.into_inner()
}

#[test]
fn parses_gbk_text_and_head_tail() {
    let ctx = ParserContext::new();
    let (gbk_bytes, _, _) = encoding_rs::GB18030.encode("绝密 ★ 内部采购预算方案\n第二行正文内容\n最后一行落款");
    let (doc, children) = parse_bytes(&ctx, &gbk_bytes, r"C:\test\notice.txt", &ParseOptions::default()).unwrap();
    assert!(children.is_empty());
    assert_eq!(doc.detected_format, "txt");
    assert!(doc.segments.iter().any(|s| s.scope == SegmentScope::HeadTail && s.text.contains("绝密")));
    assert!(doc.segments.iter().any(|s| s.scope == SegmentScope::Body && s.text.contains("内部采购预算方案")));
}

#[test]
fn parses_docx_with_comments_and_filters_small_icons() {
    let ctx = ParserContext::new();
    let doc_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
          <w:body><w:p><w:r><w:t>这是核心设计方案正文</w:t></w:r></w:p></w:body>
        </w:document>"#
    .as_bytes();
    let comments_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
          <w:comment><w:p><w:r><w:t>批注：请核对招标预算</w:t></w:r></w:p></w:comment>
        </w:comments>"#
    .as_bytes();
    let tiny_icon = make_png(12, 12, true);
    let real_img = make_png(64, 64, true);

    let docx = make_zip(&[
        ("word/document.xml", doc_xml),
        ("word/comments.xml", comments_xml),
        ("word/media/icon.png", &tiny_icon),
        ("word/media/seal.png", &real_img),
    ]);

    let (doc, _) = parse_bytes(&ctx, &docx, r"C:\test\plan.docx", &ParseOptions::default()).unwrap();
    assert_eq!(doc.detected_format, "docx");
    assert!(doc.segments.iter().any(|s| s.scope == SegmentScope::Body && s.text.contains("核心设计方案")));
    assert!(doc.segments.iter().any(|s| s.scope == SegmentScope::Comment && s.text.contains("招标预算")));
    // Tiny 12x12 icon must be filtered out while 64x64 non-solid image passes inspection
    assert_eq!(
        deepdoc_parsers::ocr::inspect_image(&tiny_icon, 24).unwrap().skip_reason,
        Some("below_min_dimensions")
    );
    assert_eq!(
        deepdoc_parsers::ocr::inspect_image(&real_img, 24).unwrap().skip_reason,
        None
    );
    assert!(!doc.segments.iter().any(|s| s.location_label.contains("icon.png")));
}

#[test]
fn parses_ofd_in_reading_order() {
    let ctx = ParserContext::new();
    let ofd_xml = br#"<?xml version="1.0" encoding="UTF-8"?><ofd:OFD xmlns:ofd="http://www.ofdspec.org/2016"/>"#;
    let content_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <ofd:Page xmlns:ofd="http://www.ofdspec.org/2016">
          <ofd:Content>
            <ofd:Layer>
              <ofd:TextObject Boundary="20 40 100 10"><ofd:TextCode X="0" Y="0">第二行内容</ofd:TextCode></ofd:TextObject>
              <ofd:TextObject Boundary="20 10 100 10"><ofd:TextCode X="0" Y="0">第一行标题</ofd:TextCode></ofd:TextObject>
            </ofd:Layer>
          </ofd:Content>
        </ofd:Page>"#
    .as_bytes();
    let ofd = make_zip(&[
        ("OFD.xml", ofd_xml),
        ("Doc_0/Pages/Page_0/Content.xml", content_xml),
    ]);
    let (doc, _) = parse_bytes(&ctx, &ofd, r"C:\test\gongwen.ofd", &ParseOptions::default()).unwrap();
    assert_eq!(doc.detected_format, "ofd");
    let body = doc.segments.iter().find(|s| s.scope == SegmentScope::Body).unwrap();
    let pos1 = body.text.find("第一行标题").unwrap();
    let pos2 = body.text.find("第二行内容").unwrap();
    assert!(pos1 < pos2, "OFD reading order must sort Y=10 before Y=40");
}

#[test]
fn parses_nested_zip_and_eml_attachment() {
    let ctx = ParserContext::new();
    let inner_txt = "附件秘密参数：TX-9900".as_bytes();
    let inner_zip = make_zip(&[("secret.txt", inner_txt)]);
    let b64 = {
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for chunk in inner_zip.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let n = (b0 << 16) | (b1 << 8) | b2;
            s.push(ALPHA[((n >> 18) & 63) as usize] as char);
            s.push(ALPHA[((n >> 12) & 63) as usize] as char);
            s.push(if chunk.len() > 1 { ALPHA[((n >> 6) & 63) as usize] as char } else { '=' });
            s.push(if chunk.len() > 2 { ALPHA[(n & 63) as usize] as char } else { '=' });
        }
        s
    };
    let eml = format!(
        "From: a@example.com\r\nTo: b@example.com\r\nSubject: 内部测试邮件\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"bnd\"\r\n\r\n--bnd\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n请查收附件。\r\n--bnd\r\nContent-Type: application/zip; name=\"pkg.zip\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"pkg.zip\"\r\n\r\n{b64}\r\n--bnd--\r\n"
    );
    let (doc, children) = parse_bytes(&ctx, eml.as_bytes(), r"C:\mail\test.eml", &ParseOptions::default()).unwrap();
    assert_eq!(doc.detected_format, "eml");
    assert!(children.iter().any(|c| c.virtual_path == r"C:\mail\test.eml!/pkg.zip!/secret.txt"));
    let secret_child = children.iter().find(|c| c.file_name == "secret.txt").unwrap();
    assert!(secret_child.segments.iter().any(|s| s.text.contains("TX-9900")));
}

#[test]
fn parses_dxf_and_detects_encrypted_pdf_and_zip_bomb() {
    let ctx = ParserContext::new();
    let dxf = b"0\nSECTION\n2\nENTITIES\n0\nTEXT\n8\nPLAN_LAYER\n10\n0.0\n20\n0.0\n40\n2.5\n1\nCAD_SECRET_NOTE\n0\nENDSEC\n0\nEOF\n";
    let (dxf_doc, _) = parse_bytes(&ctx, dxf, r"C:\cad\plan.dxf", &ParseOptions::default()).unwrap();
    assert_eq!(dxf_doc.detected_format, "dxf");
    assert!(dxf_doc.segments.iter().any(|s| s.text.contains("CAD_SECRET_NOTE")));

    let enc_pdf = b"%PDF-1.7\n1 0 obj\n<< /Filter /Standard /Encrypt 2 0 R >>\nendobj";
    let (pdf_doc, _) = parse_bytes(&ctx, enc_pdf, r"C:\sec\locked.pdf", &ParseOptions::default()).unwrap();
    assert!(pdf_doc.encrypted);

    // Zip bomb budget cap check
    let big_payload = vec![b'A'; 4096];
    let bomb_zip = make_zip(&[("big.txt", &big_payload)]);
    let opts = ParseOptions {
        max_single_file_bytes: 512,
        ..ParseOptions::default()
    };
    let err = parse_bytes(&ctx, &bomb_zip, r"C:\sec\bomb.zip", &opts).unwrap_err();
    assert_eq!(err.kind, FailureKind::ZipBombTripped);
}

#[test]
fn parses_compressed_lopdf_xps_vsdx_fb2_svg_sqlite_zst_and_ole_ppt() {
    let ctx = ParserContext::new();

    // 1. Compressed PDF via lopdf (FlateDecode stream + /Info metadata)
    {
        use lopdf::{dictionary, content::{Content, Operation}, Document, Object, Stream};
        let mut pdf = Document::with_version("1.5");
        let pages_id = pdf.new_object_id();
        let font_id = pdf.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources_id = pdf.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 12.into()]),
                Operation::new("Td", vec![50.into(), 700.into()]),
                Operation::new("Tj", vec![Object::string_literal("TOP_SECRET_FLATED_PDF")]),
                Operation::new("ET", vec![]),
            ],
        };
        let mut stream = Stream::new(dictionary! {}, content.encode().unwrap());
        let _ = stream.compress();
        let content_id = pdf.add_object(stream);
        let page_id = pdf.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        });
        pdf.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page_id.into()],
                "Count" => 1,
            }),
        );
        let catalog_id = pdf.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        let info_id = pdf.add_object(dictionary! {
            "Title" => Object::string_literal("Confidential Tender Spec"),
        });
        pdf.trailer.set("Root", catalog_id);
        pdf.trailer.set("Info", info_id);
        let mut pdf_bytes = Vec::new();
        pdf.save_to(&mut pdf_bytes).unwrap();

        let (doc, _) = parse_bytes(&ctx, &pdf_bytes, r"C:\pdf\compressed.pdf", &ParseOptions::default()).unwrap();
        assert_eq!(doc.detected_format, "pdf");
        assert!(doc.segments.iter().any(|s| s.text.contains("TOP_SECRET_FLATED_PDF")));
        assert!(doc.segments.iter().any(|s| s.scope == SegmentScope::Metadata && s.text.contains("Confidential Tender Spec")));
    }

    // 2. Legacy OLE2 PPT with TextCharsAtom (UTF-16LE) + carved PNG
    {
        let mut ole_cur = Cursor::new(Vec::new());
        {
            let mut comp = cfb::CompoundFile::create(&mut ole_cur).unwrap();
            let txt_u16: Vec<u8> = "机密PPT汇报材料"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            let mut ppt_stream = Vec::new();
            ppt_stream.extend_from_slice(&0x0000u16.to_le_bytes()); // ver_inst
            ppt_stream.extend_from_slice(&0x0FA0u16.to_le_bytes()); // TextCharsAtom
            ppt_stream.extend_from_slice(&(txt_u16.len() as u32).to_le_bytes());
            ppt_stream.extend_from_slice(&txt_u16);
            let mut s1 = comp.create_stream("PowerPoint Document").unwrap();
            s1.write_all(&ppt_stream).unwrap();
            let png = include_bytes!("fixtures/ocr_cn.png");
            let mut s2 = comp.create_stream("Pictures").unwrap();
            s2.write_all(png).unwrap();
        }
        let ppt_bytes = ole_cur.into_inner();
        let (doc, _) = parse_bytes(&ctx, &ppt_bytes, r"C:\old\deck.ppt", &ParseOptions::default()).unwrap();
        assert_eq!(doc.detected_format, "ppt");
        assert!(doc.segments.iter().any(|s| s.text.contains("机密PPT汇报材料")));
        assert!(doc.segments.iter().any(|s| s.scope == SegmentScope::Ocr && s.text.contains("2026")));
    }

    // 3. XPS, VSDX, FB2, SVG
    {
        let xps = make_zip(&[(
            "Documents/1/Pages/1.fpage",
            r#"<FixedPage><Glyphs UnicodeString="XPS内部审定稿"/></FixedPage>"#.as_bytes(),
        )]);
        let (xps_doc, _) = parse_bytes(&ctx, &xps, r"C:\doc\out.xps", &ParseOptions::default()).unwrap();
        assert_eq!(xps_doc.detected_format, "xps");
        assert!(xps_doc.segments.iter().any(|s| s.text.contains("XPS内部审定稿")));

        let vsdx = make_zip(&[(
            "visio/pages/page1.xml",
            r#"<PageContents><Shapes><Shape><Text>网络拓扑核心节点</Text></Shape></Shapes></PageContents>"#.as_bytes(),
        )]);
        let (vsdx_doc, _) = parse_bytes(&ctx, &vsdx, r"C:\doc\net.vsdx", &ParseOptions::default()).unwrap();
        assert_eq!(vsdx_doc.detected_format, "vsdx");
        assert!(vsdx_doc.segments.iter().any(|s| s.text.contains("网络拓扑核心节点")));

        let fb2 = r#"<?xml version="1.0"?><FictionBook><body><section><p>电子书加密章节</p></section></body></FictionBook>"#.as_bytes();
        let (fb2_doc, _) = parse_bytes(&ctx, fb2, r"C:\book\novel.fb2", &ParseOptions::default()).unwrap();
        assert_eq!(fb2_doc.detected_format, "fb2");
        assert!(fb2_doc.segments.iter().any(|s| s.text.contains("电子书加密章节")));

        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><text>矢量图纸密级标注</text></svg>"#.as_bytes();
        let (svg_doc, _) = parse_bytes(&ctx, svg, r"C:\img\diagram.svg", &ParseOptions::default()).unwrap();
        assert_eq!(svg_doc.detected_format, "svg");
        assert!(svg_doc.segments.iter().any(|s| s.text.contains("矢量图纸密级标注")));
    }

    // 4. SQLite DB & Zstd archive
    {
        let tmp_db = std::env::temp_dir().join(format!("deepdoc_fmt_db_{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&tmp_db);
        {
            let conn = rusqlite::Connection::open(&tmp_db).unwrap();
            conn.execute("CREATE TABLE secrets (id INT, note TEXT)", []).unwrap();
            conn.execute("INSERT INTO secrets VALUES (1, 'SQLITE_ROW_SECRET_88')", []).unwrap();
        }
        let db_bytes = std::fs::read(&tmp_db).unwrap();
        let _ = std::fs::remove_file(&tmp_db);
        let (db_doc, _) = parse_bytes(&ctx, &db_bytes, r"C:\data\app.sqlite", &ParseOptions::default()).unwrap();
        assert_eq!(db_doc.detected_format, "sqlite");
        assert!(db_doc.segments.iter().any(|s| s.text.contains("SQLITE_ROW_SECRET_88")));

        let zst_bytes = zstd::bulk::compress("ZSTD压缩内部文档内容".as_bytes(), 3).unwrap();
        let (zst_doc, zst_children) = parse_bytes(&ctx, &zst_bytes, r"C:\arch\note.txt.zst", &ParseOptions::default()).unwrap();
        assert_eq!(zst_doc.detected_format, "zst");
        assert_eq!(zst_children.len(), 1);
        assert!(zst_children[0].segments.iter().any(|s| s.text.contains("ZSTD压缩内部文档内容")));
    }

    // 5. Multi-page TIFF (rendered text OCR across pages) + GBK DXF
    {
        let frame1 = render_banner_gray("PAGE 1 TOP");
        let frame2 = render_banner_gray("PAGE 2 SEC");
        let (fw, fh) = (frame1.width(), frame1.height());
        let mut tif_buf = Cursor::new(Vec::new());
        {
            let mut enc = tiff::encoder::TiffEncoder::new(&mut tif_buf).unwrap();
            enc.write_image::<tiff::encoder::colortype::Gray8>(fw, fh, frame1.as_raw()).unwrap();
            enc.write_image::<tiff::encoder::colortype::Gray8>(fw, fh, frame2.as_raw()).unwrap();
        }
        let tif_bytes = tif_buf.into_inner();
        let (tif_doc, _) = parse_bytes(&ctx, &tif_bytes, r"C:\scan\multipage.tif", &ParseOptions::default()).unwrap();
        assert_eq!(tif_doc.detected_format, "tif");
        let ocr_texts: String = tif_doc
            .segments
            .iter()
            .filter(|s| s.scope == SegmentScope::Ocr)
            .map(|s| format!("{}::{}", s.location_label, s.text))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            ocr_texts.contains("第1页") && ocr_texts.contains("第2页"),
            "Expected multi-page TIFF OCR segments, got:\n{ocr_texts}\nwarnings={:?}",
            tif_doc.warnings
        );

        let (gbk_dxf, _, _) = encoding_rs::GB18030.encode("0\nSECTION\n2\nHEADER\n9\n$DWGCODEPAGE\n3\nANSI_936\n0\nENDSEC\n0\nSECTION\n2\nENTITIES\n0\nTEXT\n8\n图层1\n10\n0\n20\n0\n40\n2\n1\n中文CAD地下管网图纸\n0\nENDSEC\n0\nEOF\n");
        let (dxf_doc, _) = parse_bytes(&ctx, &gbk_dxf, r"C:\cad\gbk.dxf", &ParseOptions::default()).unwrap();
        assert!(dxf_doc.segments.iter().any(|s| s.text.contains("中文CAD地下管网图纸")));
    }
}

#[test]
fn parses_mht_mbox_vcf_ics_tnef_3dgis_dbf_iso_and_ole_wps() {
    let ctx = ParserContext::new();

    // 1. MHT / MHTML
    let mht = concat!(
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/related; boundary=\"B1\"\r\n\r\n",
        "--B1\r\n",
        "Content-Type: text/html; charset=utf-8\r\n\r\n",
        "<html><body><p>MHT网页归档机密正文</p></body></html>\r\n",
        "--B1--\r\n"
    )
    .as_bytes();
    let (mht_doc, _) = parse_bytes(&ctx, mht, r"C:\web\snap.mht", &ParseOptions::default()).unwrap();
    assert_eq!(mht_doc.detected_format, "mht");
    assert!(mht_doc.segments.iter().any(|s| s.text.contains("MHT网页归档机密正文")));

    // 2. MBOX -> multiple EML children
    let mbox = concat!(
        "From a@example.com Mon Nov 11 10:00:00 2026\r\n",
        "Subject: MBOX_MSG_ONE\r\n\r\n",
        "First mailbox payload.\r\n",
        "From b@example.com Mon Nov 11 10:05:00 2026\r\n",
        "Subject: MBOX_MSG_TWO\r\n\r\n",
        "Second mailbox payload.\r\n"
    )
    .as_bytes();
    let (mbox_doc, mbox_children) = parse_bytes(&ctx, mbox, r"C:\mail\archive.mbox", &ParseOptions::default()).unwrap();
    assert_eq!(mbox_doc.detected_format, "mbox");
    assert_eq!(mbox_children.len(), 2);
    assert!(mbox_children.iter().any(|c| c.segments.iter().any(|s| s.text.contains("First mailbox payload"))));
    assert!(mbox_children.iter().any(|c| c.segments.iter().any(|s| s.text.contains("Second mailbox payload"))));

    // 3. VCF & ICS
    let vcf = "BEGIN:VCARD\r\nFN:秘密联系人张三\r\nTEL:13800138000\r\nEND:VCARD\r\n".as_bytes();
    let (vcf_doc, _) = parse_bytes(&ctx, vcf, r"C:\pim\contacts.vcf", &ParseOptions::default()).unwrap();
    assert_eq!(vcf_doc.detected_format, "vcf");
    assert!(vcf_doc.segments.iter().any(|s| s.text.contains("秘密联系人张三")));

    let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:内部安全评审会议\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n".as_bytes();
    let (ics_doc, _) = parse_bytes(&ctx, ics, r"C:\pim\meeting.ics", &ParseOptions::default()).unwrap();
    assert_eq!(ics_doc.detected_format, "ics");
    assert!(ics_doc.segments.iter().any(|s| s.text.contains("内部安全评审会议")));

    // 4. TNEF (winmail.dat) with subject + embedded text attachment
    {
        let mut tnef = Vec::new();
        tnef.extend_from_slice(&0x223E_9F78u32.to_le_bytes()); // signature
        tnef.extend_from_slice(&0x0001u16.to_le_bytes()); // key
        let mut push_attr = |id: u32, val: &[u8]| {
            tnef.push(0x01); // lvlMessage
            tnef.extend_from_slice(&id.to_le_bytes());
            tnef.extend_from_slice(&(val.len() as u32).to_le_bytes());
            tnef.extend_from_slice(val);
            tnef.extend_from_slice(&0u16.to_le_bytes()); // checksum
        };
        push_attr(0x8004, b"TNEF_SUBJECT_HEADER\0");
        push_attr(0x8010, b"attached_note.txt\0");
        push_attr(0x800F, "TNEF附件内部明文".as_bytes());

        let (tnef_doc, tnef_children) = parse_bytes(&ctx, &tnef, r"C:\mail\winmail.dat", &ParseOptions::default()).unwrap();
        assert_eq!(tnef_doc.detected_format, "tnef");
        assert!(tnef_doc.segments.iter().any(|s| s.text.contains("TNEF_SUBJECT_HEADER")));
        assert_eq!(tnef_children.len(), 1);
        assert!(tnef_children[0].segments.iter().any(|s| s.text.contains("TNEF附件内部明文")));
    }

    // 5. 3D GIS (B3DM, GLB, LAS) & DBF
    {
        let ft_json = br#"{"BATCH_LENGTH":1}"#;
        let bt_json = br#"{"name":"CONFIDENTIAL_BUILDING_3D"}"#;
        let mut b3dm = Vec::new();
        b3dm.extend_from_slice(b"b3dm");
        b3dm.extend_from_slice(&1u32.to_le_bytes());
        let total = 28 + ft_json.len() + bt_json.len();
        b3dm.extend_from_slice(&(total as u32).to_le_bytes());
        b3dm.extend_from_slice(&(ft_json.len() as u32).to_le_bytes());
        b3dm.extend_from_slice(&0u32.to_le_bytes());
        b3dm.extend_from_slice(&(bt_json.len() as u32).to_le_bytes());
        b3dm.extend_from_slice(&0u32.to_le_bytes());
        b3dm.extend_from_slice(ft_json);
        b3dm.extend_from_slice(bt_json);
        let (b3dm_doc, _) = parse_bytes(&ctx, &b3dm, r"C:\gis\tile.b3dm", &ParseOptions::default()).unwrap();
        assert_eq!(b3dm_doc.detected_format, "b3dm");
        assert!(b3dm_doc.segments.iter().any(|s| s.text.contains("CONFIDENTIAL_BUILDING_3D")));

        let gltf_json = br#"{"asset":{"version":"2.0","generator":"SECRET_GIS_EXPORTER"}}"#;
        let mut glb = Vec::new();
        glb.extend_from_slice(b"glTF");
        glb.extend_from_slice(&2u32.to_le_bytes());
        glb.extend_from_slice(&((12 + 8 + gltf_json.len()) as u32).to_le_bytes());
        glb.extend_from_slice(&(gltf_json.len() as u32).to_le_bytes());
        glb.extend_from_slice(b"JSON");
        glb.extend_from_slice(gltf_json);
        let (glb_doc, _) = parse_bytes(&ctx, &glb, r"C:\gis\scene.glb", &ParseOptions::default()).unwrap();
        assert_eq!(glb_doc.detected_format, "glb");
        assert!(glb_doc.segments.iter().any(|s| s.text.contains("SECRET_GIS_EXPORTER")));

        let vlr_payload = b"EPSG_4326_CHINA_ZONE";
        let mut las = vec![0u8; 227];
        las[0..4].copy_from_slice(b"LASF");
        las[26..37].copy_from_slice(b"SURVEY_UAV1");
        las[58..71].copy_from_slice(b"LIDAR_SCANNER");
        las[94..96].copy_from_slice(&227u16.to_le_bytes()); // header size
        las[100..104].copy_from_slice(&1u32.to_le_bytes()); // num VLRs
        let mut vlr = vec![0u8; 54];
        vlr[2..10].copy_from_slice(b"LASF_Prj");
        vlr[20..22].copy_from_slice(&(vlr_payload.len() as u16).to_le_bytes());
        vlr[22..30].copy_from_slice(b"GeoTiff ");
        las.extend_from_slice(&vlr);
        las.extend_from_slice(vlr_payload);
        let (las_doc, _) = parse_bytes(&ctx, &las, r"C:\gis\cloud.las", &ParseOptions::default()).unwrap();
        assert_eq!(las_doc.detected_format, "las");
        assert!(las_doc.segments.iter().any(|s| s.text.contains("EPSG_4326_CHINA_ZONE")));

        // Minimal dBASE III file
        let mut dbf = vec![0u8; 65 + 21 + 1];
        dbf[0] = 0x03;
        dbf[1] = 26;
        dbf[2] = 11;
        dbf[3] = 11;
        dbf[4..8].copy_from_slice(&1u32.to_le_bytes()); // 1 record
        dbf[8..10].copy_from_slice(&65u16.to_le_bytes()); // header len
        dbf[10..12].copy_from_slice(&21u16.to_le_bytes()); // record len (1 + 20)
        dbf[32..36].copy_from_slice(b"NAME");
        dbf[43] = b'C';
        dbf[48] = 20;
        dbf[64] = 0x0D; // header terminator
        dbf[65] = b' '; // active record
        dbf[66..80].copy_from_slice(b"SECRET_SITE_09");
        dbf[80..86].fill(b' ');
        dbf[86] = 0x1A; // EOF
        let (dbf_doc, _) = parse_bytes(&ctx, &dbf, r"C:\gis\points.dbf", &ParseOptions::default()).unwrap();
        assert_eq!(dbf_doc.detected_format, "dbf");
        assert!(dbf_doc.segments.iter().any(|s| s.text.contains("SECRET_SITE_09")));
    }

    // 6. ISO-9660 + Joliet (UTF-16BE) optical image
    {
        const SECTOR: usize = 2048;
        let mut iso = vec![0u8; 22 * SECTOR];
        // Sector 16: PVD
        let pvd = &mut iso[16 * SECTOR..17 * SECTOR];
        pvd[0] = 1;
        pvd[1..6].copy_from_slice(b"CD001");
        pvd[156] = 34;
        pvd[156 + 2..156 + 6].copy_from_slice(&19u32.to_le_bytes());
        pvd[156 + 10..156 + 14].copy_from_slice(&(SECTOR as u32).to_le_bytes());
        // Sector 17: SVD Joliet
        let svd = &mut iso[17 * SECTOR..18 * SECTOR];
        svd[0] = 2;
        svd[1..6].copy_from_slice(b"CD001");
        svd[88..91].copy_from_slice(b"%/@");
        svd[156] = 34;
        svd[156 + 2..156 + 6].copy_from_slice(&20u32.to_le_bytes());
        svd[156 + 10..156 + 14].copy_from_slice(&(SECTOR as u32).to_le_bytes());
        // Sector 18: End VD
        iso[18 * SECTOR] = 255;
        iso[18 * SECTOR + 1..18 * SECTOR + 6].copy_from_slice(b"CD001");
        // Sector 20: Joliet root dir record for "绝密光盘文件.txt;1" -> LBA 21
        let payload = "ISO_JOLIET_CONTENT_777".as_bytes();
        let name_u16be: Vec<u8> = "绝密光盘文件.txt;1"
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .collect();
        let rec_len = 33 + name_u16be.len() + ((33 + name_u16be.len()) % 2);
        let dir = &mut iso[20 * SECTOR..21 * SECTOR];
        dir[0] = rec_len as u8;
        dir[2..6].copy_from_slice(&21u32.to_le_bytes());
        dir[10..14].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        dir[25] = 0; // regular file
        dir[32] = name_u16be.len() as u8;
        dir[33..33 + name_u16be.len()].copy_from_slice(&name_u16be);
        // Sector 21: file data
        iso[21 * SECTOR..21 * SECTOR + payload.len()].copy_from_slice(payload);

        let (iso_doc, iso_children) = parse_bytes(&ctx, &iso, r"C:\disc\backup.iso", &ParseOptions::default()).unwrap();
        assert_eq!(iso_doc.detected_format, "iso");
        assert_eq!(iso_children.len(), 1);
        assert!(iso_children[0].virtual_path.contains("绝密光盘文件.txt"));
        assert!(iso_children[0].segments.iter().any(|s| s.text.contains("ISO_JOLIET_CONTENT_777")));
    }

    // 7. Native OLE2 .wps / .doc fallback
    {
        let mut ole_cur = Cursor::new(Vec::new());
        {
            let mut comp = cfb::CompoundFile::create(&mut ole_cur).unwrap();
            let txt_u16: Vec<u8> = "WPS绝密公文原生回退抽取"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            let mut s = comp.create_stream("WordDocument").unwrap();
            s.write_all(&txt_u16).unwrap();
        }
        let wps_bytes = ole_cur.into_inner();
        let (wps_doc, _) = parse_bytes(&ctx, &wps_bytes, r"C:\old\notice.wps", &ParseOptions::default()).unwrap();
        assert_eq!(wps_doc.detected_format, "wps");
        assert!(wps_doc.segments.iter().any(|s| s.text.contains("WPS绝密公文原生回退抽取")));
    }
}

fn glyph_5x7(ch: char) -> [u8; 7] {
    match ch {
        'A' => [0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
        'B' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110],
        'C' => [0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110],
        'D' => [0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110],
        'E' => [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111],
        'F' => [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000],
        'G' => [0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01110],
        'I' => [0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b11111],
        'L' => [0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111],
        'N' => [0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001],
        'O' => [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
        'P' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000],
        'R' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001],
        'S' => [0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110],
        'T' => [0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100],
        'U' => [0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
        '0' => [0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110],
        '1' => [0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
        '2' => [0b01110, 0b10001, 0b00001, 0b00110, 0b01000, 0b10000, 0b11111],
        '6' => [0b01110, 0b10000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110],
        '8' => [0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110],
        _ => [0; 7],
    }
}

fn render_banner_gray(text: &str) -> image::GrayImage {
    let scale = 6u32;
    let margin = 24u32;
    let char_adv = 6 * scale;
    let w = (text.chars().count() as u32 * char_adv + margin * 2).max(128);
    let h = 7 * scale + margin * 2;
    let mut img = image::GrayImage::from_pixel(w, h, image::Luma([255u8]));
    for (ci, ch) in text.chars().enumerate() {
        let rows = glyph_5x7(ch.to_ascii_uppercase());
        let x0 = margin + ci as u32 * char_adv;
        for (ry, bits) in rows.iter().enumerate() {
            for rx in 0..5u32 {
                if (bits >> (4 - rx)) & 1 == 1 {
                    for sy in 0..scale {
                        for sx in 0..scale {
                            img.put_pixel(
                                x0 + rx * scale + sx,
                                margin + ry as u32 * scale + sy,
                                image::Luma([0u8]),
                            );
                        }
                    }
                }
            }
        }
    }
    img
}

fn render_banner_png(text: &str) -> Vec<u8> {
    let gray = render_banner_gray(text);
    let mut out = Cursor::new(Vec::new());
    image::DynamicImage::ImageLuma8(gray)
        .write_to(&mut out, image::ImageFormat::Png)
        .unwrap();
    out.into_inner()
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn push_vint(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

fn push_rar5_block(arc: &mut Vec<u8>, header_type: u64, header_flags: u64, extra: &[u8], body: &[u8]) {
    let mut hdr_inner = Vec::new();
    push_vint(&mut hdr_inner, header_type);
    push_vint(&mut hdr_inner, header_flags);
    if (header_flags & 0x02) != 0 {
        push_vint(&mut hdr_inner, body.len() as u64);
    }
    hdr_inner.extend_from_slice(extra);

    let mut hdr = Vec::new();
    push_vint(&mut hdr, hdr_inner.len() as u64);
    hdr.extend_from_slice(&hdr_inner);
    let crc = crc32_ieee(&hdr);
    arc.extend_from_slice(&crc.to_le_bytes());
    arc.extend_from_slice(&hdr);
    arc.extend_from_slice(body);
}

fn make_rar5_stored_archive(file_name: &str, payload: &[u8]) -> Vec<u8> {
    let mut arc = Vec::new();
    arc.extend_from_slice(b"Rar!\x1A\x07\x01\x00");
    // MAIN header (type=1, flags=0, arch_flags=0)
    push_rar5_block(&mut arc, 1, 0, &[0x00], &[]);
    // FILE header (type=2, flags=0x02 data area present)
    let mut extra = Vec::new();
    push_vint(&mut extra, 0x04); // file_flags: CRC32 present
    push_vint(&mut extra, payload.len() as u64); // unpacked_size
    push_vint(&mut extra, 0x20); // attributes
    extra.extend_from_slice(&crc32_ieee(payload).to_le_bytes());
    push_vint(&mut extra, 0x00); // compression: store (method 0)
    push_vint(&mut extra, 0x00); // host OS: Windows
    push_vint(&mut extra, file_name.len() as u64);
    extra.extend_from_slice(file_name.as_bytes());
    push_rar5_block(&mut arc, 2, 0x02, &extra, payload);
    // ENDARC header (type=5, flags=0, end_flags=0)
    push_rar5_block(&mut arc, 5, 0, &[0x00], &[]);
    arc
}

#[test]
fn verifies_deep_ocr_pdfium_x2t_and_rar5() {
    let ctx = ParserContext::new();
    assert!(ctx.ocr.is_ready(), "Offline OCR must be ready (ONNX or WinRT)");

    // 1. Offline OCR on Chinese + English rendered fixture (`ocr_cn.png`) & cache reuse
    let cn_png = include_bytes!("fixtures/ocr_cn.png");
    let (ocr_doc, _) = parse_bytes(&ctx, cn_png, r"C:\scan\ocr_cn.png", &ParseOptions::default()).unwrap();
    assert_eq!(ocr_doc.detected_format, "png");
    let ocr_text: String = ocr_doc
        .segments
        .iter()
        .filter(|s| s.scope == SegmentScope::Ocr)
        .map(|s| s.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        ocr_text.contains("2026") && (ocr_text.contains("绝密") || ocr_text.contains("预算") || ocr_text.contains("CONFIDENTIAL")),
        "Real offline OCR failed on ocr_cn.png; got: {ocr_text:?}, warnings={:?}",
        ocr_doc.warnings
    );

    // Second identical image must hit BLAKE3 OCR cache
    let (ocr_doc2, _) = parse_bytes(&ctx, cn_png, r"C:\scan\ocr_cn_copy.png", &ParseOptions::default()).unwrap();
    assert!(ocr_doc2.segments.iter().any(|s| s.location_label.contains("OCR缓存复用")));

    // 2. PDFium full-font extraction AND scanned-page rasterization -> OCR
    assert!(
        deepdoc_parsers::adapters::find_pdfium_dll().is_some(),
        "pdfium.dll must be staged in native_deps/libs/pdfium.dll or libs/pdfium.dll"
    );
    {
        use lopdf::{dictionary, content::{Content, Operation}, Document, Object, Stream};
        let mut pdf = Document::with_version("1.5");
        let pages_id = pdf.new_object_id();
        let rgb = image::load_from_memory(cn_png).unwrap().to_rgb8();
        let (gw, gh) = (rgb.width(), rgb.height());
        let im_dict = dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => gw as i64,
            "Height" => gh as i64,
            "ColorSpace" => "DeviceRGB",
            "BitsPerComponent" => 8,
        };
        let im_stream = Stream::new(im_dict, rgb.into_raw());
        let im_id = pdf.add_object(im_stream);
        let resources_id = pdf.add_object(dictionary! {
            "XObject" => dictionary! { "Im1" => im_id },
        });
        let content = Content {
            operations: vec![
                Operation::new("q", vec![]),
                Operation::new("cm", vec![480.into(), 0.into(), 0.into(), 135.into(), 40.into(), 600.into()]),
                Operation::new("Do", vec!["Im1".into()]),
                Operation::new("Q", vec![]),
            ],
        };
        let content_id = pdf.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
        let page_id = pdf.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        });
        pdf.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page_id.into()],
                "Count" => 1,
            }),
        );
        let catalog_id = pdf.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        let info_id = pdf.add_object(dictionary! { "Title" => Object::string_literal("ScannedPDFMetaTitle") });
        pdf.trailer.set("Root", catalog_id);
        pdf.trailer.set("Info", info_id);
        let mut pdf_bytes = Vec::new();
        pdf.save_to(&mut pdf_bytes).unwrap();

        let (scan_pdf_doc, _) = parse_bytes(&ctx, &pdf_bytes, r"C:\pdf\scanned.pdf", &ParseOptions::default()).unwrap();
        assert_eq!(scan_pdf_doc.detected_format, "pdf");
        assert!(scan_pdf_doc.segments.iter().any(|s| s.scope == SegmentScope::Metadata && s.text.contains("ScannedPDFMetaTitle")));
        let scan_ocr: String = scan_pdf_doc
            .segments
            .iter()
            .filter(|s| s.scope == SegmentScope::Ocr)
            .map(|s| s.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        eprintln!("[OCR cn_png]={ocr_text:?}\n[PDFium scan_ocr]={scan_ocr:?}");
        assert!(
            scan_ocr.contains("2026") && (scan_ocr.contains("预算") || scan_ocr.contains("绝密") || scan_ocr.contains("CONFIDENTIAL")),
            "Scanned PDF via PDFium->OCR failed; segments={:?} warnings={:?}",
            scan_pdf_doc.segments,
            scan_pdf_doc.warnings
        );
    }

    // 3. Fast Pure-Rust OLE2 .doc & .ppt extraction (no 183MB x2t subprocess overhead)
    let sample_doc = include_bytes!("fixtures/SampleDoc.doc");
    let (doc_doc, _) = parse_bytes(&ctx, sample_doc, r"C:\office\SampleDoc.doc", &ParseOptions::default()).unwrap();
    assert_eq!(doc_doc.detected_format, "doc");
    assert!(
        doc_doc.metadata.iter().any(|(k, v)| k == "parsed_by" && v == "native-ole2"),
        "Expected fast native-ole2 on SampleDoc.doc, got metadata={:?} warnings={:?}",
        doc_doc.metadata,
        doc_doc.warnings
    );
    assert!(!doc_doc.segments.is_empty());

    let sample_ppt = include_bytes!("fixtures/SampleShow.ppt");
    let (ppt_doc, _) = parse_bytes(&ctx, sample_ppt, r"C:\office\SampleShow.ppt", &ParseOptions::default()).unwrap();
    assert_eq!(ppt_doc.detected_format, "ppt");
    assert!(ppt_doc.metadata.iter().any(|(k, v)| k == "parsed_by" && v == "native-ole2"));
    assert!(!ppt_doc.segments.is_empty());

    // 4. Native RAR5 archive unpacking via UnRAR
    let rar5 = make_rar5_stored_archive("secret_rar5.txt", "RAR5内部涉密压缩包内容_888".as_bytes());
    let (rar_doc, rar_children) = parse_bytes(&ctx, &rar5, r"C:\arch\bundle.rar", &ParseOptions::default()).unwrap();
    assert_eq!(rar_doc.detected_format, "rar");
    assert_eq!(rar_children.len(), 1, "RAR5 child missing, warnings={:?}", rar_doc.warnings);
    assert_eq!(rar_children[0].file_name, "secret_rar5.txt");
    assert!(rar_children[0].segments.iter().any(|s| s.text.contains("RAR5内部涉密压缩包内容_888")));

    // 5. Native Pure-Rust DWG parsing via acadrust (no DXF export subprocess)
    let sample_dwg = include_bytes!("../../ext-worker/tests/fixtures/testDWG2004.dwg");
    let (dwg_doc, _) = parse_bytes(&ctx, sample_dwg, r"C:\cad\sample2004.dwg", &ParseOptions::default()).unwrap();
    assert_eq!(dwg_doc.detected_format, "dwg");
    assert!(
        dwg_doc.metadata.iter().any(|(k, v)| k == "dwg_engine" && v == "acadrust"),
        "Expected native acadrust DWG engine, got metadata={:?} warnings={:?}",
        dwg_doc.metadata,
        dwg_doc.warnings
    );
    assert!(dwg_doc.segments.iter().any(|s| s.scope == SegmentScope::Metadata && s.text.contains("AC1018")));

    let _ = render_banner_png("OK");
}

#[test]
fn metadata_fast_skip_and_oversized_file_and_image_guard_do_not_fail() {
    use deepdoc_parsers::parse_file;

    let ctx = ParserContext::new();
    let dir = std::env::temp_dir().join(format!("deepdoc_fastskip_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // 1. Metadata-only binary extensions (.dll / .rvt) skip disk content read cleanly
    let fake_dll = dir.join("kernel_mod.dll");
    std::fs::write(&fake_dll, b"MZ\x90\x00FAKE_DLL_BYTES").unwrap();
    let (dll_doc, dll_children) = parse_file(
        &ctx,
        &fake_dll,
        &fake_dll.to_string_lossy(),
        &ParseOptions::default(),
    )
    .expect("dll metadata-only parse should succeed");
    assert!(dll_children.is_empty());
    assert!(dll_doc.metadata.iter().any(|(k, v)| k == "indexed_mode" && v == "metadata_only"));

    // 2. Oversized regular file (> max_single_file_bytes) returns metadata-only Ok instead of ZipBombTripped
    let big_bin = dir.join("large_model.rvt");
    std::fs::write(&big_bin, vec![b'R'; 2048]).unwrap();
    let mut small_cap = ParseOptions::default();
    small_cap.max_single_file_bytes = 512;
    let (big_doc, _) = parse_file(&ctx, &big_bin, &big_bin.to_string_lossy(), &small_cap)
        .expect("oversized file should gracefully index metadata");
    assert!(big_doc.metadata.iter().any(|(k, v)| k == "indexed_mode" && v == "metadata_only"));

    // 3. Large CAD/map raster (6000x4000 = 24M <= 120M) is allowed for tiled OCR (not rejected),
    //    while true pixel-bomb PNG (12500x10000 = 125M > 120M) is skipped before full RGB allocation
    let make_white_gray_png = |w: u32, h: u32| -> Vec<u8> {
        let mut buf = Vec::new();
        let mut enc = png::Encoder::new(&mut buf, w, h);
        enc.set_color(png::ColorType::Grayscale);
        enc.set_depth(png::BitDepth::Eight);
        if let Ok(mut writer) = enc.write_header() {
            let full = vec![255u8; (w as usize) * (h as usize)];
            let _ = writer.write_image_data(&full);
        }
        buf
    };
    let map_png = make_white_gray_png(4000, 3000);
    let (map_doc, _) = parse_bytes(&ctx, &map_png, r"C:\cad\large_topo_map.png", &ParseOptions::default()).unwrap();
    assert!(
        !map_doc.warnings.iter().any(|w| w.contains("分辨率超过安全上限")),
        "Large map sheet <= 120M pixels must be allowed for tiled OCR, got {:?}",
        map_doc.warnings
    );

    let huge_png = make_white_gray_png(12500, 10000);
    let (png_doc, _) = parse_bytes(&ctx, &huge_png, r"C:\cad\huge_sheet.png", &ParseOptions::default()).unwrap();
    assert_eq!(png_doc.detected_format, "png");
    assert!(
        png_doc.warnings.iter().any(|w| w.contains("分辨率超过安全上限")),
        "Expected oversized pixel guard warning (>120M pixels), got {:?}",
        png_doc.warnings
    );

    let _ = std::fs::remove_dir_all(&dir);
}
