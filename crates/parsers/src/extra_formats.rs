use crate::office::OfficeParseResult;
use crate::text::{build_head_tail_segment, decode_base64, decode_text_auto, extract_html_text_and_images, extract_xml_text};
use deepdoc_protocol::{SegmentScope, TextSegment};
use dxf::entities::EntityType;
use dxf::Drawing;
use mail_parser::{MessageParser, MimeHeaders};
use quick_xml::events::Event;
use quick_xml::Reader;
use rusqlite::{Connection, OpenFlags};
use std::io::{Cursor, Read};
use zip::ZipArchive;

/// Parse MHT / MHTML (MIME HTML Web Archive) properly using `mail_parser`.
pub fn parse_mht(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Some(msg) = MessageParser::default().parse(bytes) else {
        let (txt, imgs) = extract_html_text_and_images(bytes);
        if !txt.trim().is_empty() {
            res.segments.push(TextSegment {
                scope: SegmentScope::Body,
                location_label: "MHT 文本回退".into(),
                text: txt,
            });
        }
        res.embedded_images.extend(imgs);
        return res;
    };

    let mut combined = String::new();
    for (idx, part) in msg.parts.iter().enumerate() {
        let ct = part
            .content_type()
            .map(|c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or("")).to_ascii_lowercase())
            .unwrap_or_default();
        let data = part.contents();
        if ct.contains("html") {
            let (txt, imgs) = extract_html_text_and_images(data);
            if !txt.trim().is_empty() {
                combined.push_str(txt.trim());
                combined.push('\n');
            }
            res.embedded_images.extend(imgs);
        } else if ct.starts_with("text/plain") {
            let (txt, _) = decode_text_auto(data);
            if !txt.trim().is_empty() {
                combined.push_str(txt.trim());
                combined.push('\n');
            }
        } else if ct.starts_with("image/") {
            let ext = ct.split('/').nth(1).unwrap_or("png");
            res.embedded_images
                .push((format!("mht_part_{idx}.{ext}"), data.to_vec()));
        }
    }

    if let Some(ht) = build_head_tail_segment(&combined) {
        res.segments.push(ht);
    }
    if !combined.trim().is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "MHT 网页归档正文".into(),
            text: combined.trim().to_string(),
        });
    }
    res
}

/// Split an `.mbox` mailbox into individual RFC-822 messages (child docs).
pub fn parse_mbox(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let (raw, _) = decode_text_auto(bytes);
    let mut cur = String::new();
    let mut msg_idx = 0usize;
    for line in raw.lines() {
        if line.starts_with("From ") && !cur.trim().is_empty() {
            msg_idx += 1;
            res.embedded_files
                .push((format!("msg_{msg_idx:04}.eml"), cur.as_bytes().to_vec()));
            cur.clear();
            continue;
        }
        if cur.is_empty() && line.starts_with("From ") {
            continue;
        }
        cur.push_str(line);
        cur.push('\n');
    }
    if !cur.trim().is_empty() {
        msg_idx += 1;
        res.embedded_files
            .push((format!("msg_{msg_idx:04}.eml"), cur.as_bytes().to_vec()));
    }
    res.segments.push(TextSegment {
        scope: SegmentScope::Metadata,
        location_label: "MBOX 邮箱归档".into(),
        text: format!("共拆分出 {msg_idx} 封邮件"),
    });
    res
}

/// Parse Microsoft OpenXPS / XPS (`Documents/*/Pages/*.fpage` `<Glyphs UnicodeString="..."/>` + images).
pub fn parse_xps(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) else {
        res.warnings.push("invalid XPS zip".into());
        return res;
    };

    let mut fpages = Vec::new();
    let mut img_names = Vec::new();
    for i in 0..zip.len() {
        if let Some(name) = zip.name_for_index(i) {
            let nl = name.to_ascii_lowercase();
            if nl.ends_with(".fpage") {
                fpages.push(name.to_string());
            } else if nl.ends_with(".png") || nl.ends_with(".jpg") || nl.ends_with(".jpeg") || nl.ends_with(".tif") {
                img_names.push(name.to_string());
            }
        }
    }
    fpages.sort();

    let mut all = String::new();
    for (pidx, fp) in fpages.iter().enumerate() {
        if let Ok(mut f) = zip.by_name(fp) {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() {
                let (s, _) = decode_text_auto(&buf);
                let mut reader = Reader::from_str(&s);
                let mut rbuf = Vec::new();
                let mut page_txt = String::new();
                loop {
                    match reader.read_event_into(&mut rbuf) {
                        Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                            let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                            if tag.ends_with("Glyphs") {
                                for attr in e.attributes().flatten() {
                                    if attr.key.as_ref() == b"UnicodeString" {
                                        if let Ok(v) = attr.decode_and_unescape_value(&reader) {
                                            if !v.trim().is_empty() {
                                                page_txt.push_str(v.trim());
                                                page_txt.push('\n');
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Ok(Event::Eof) | Err(_) => break,
                        _ => {}
                    }
                    rbuf.clear();
                }
                if !page_txt.trim().is_empty() {
                    all.push_str(page_txt.trim());
                    all.push('\n');
                    res.segments.push(TextSegment {
                        scope: SegmentScope::Body,
                        location_label: format!("XPS 第{}页", pidx + 1),
                        text: page_txt.trim().to_string(),
                    });
                }
            }
        }
    }
    if let Some(ht) = build_head_tail_segment(&all) {
        res.segments.insert(0, ht);
    }
    for im in img_names {
        if let Ok(mut f) = zip.by_name(&im) {
            if f.size() <= 32 * 1024 * 1024 {
                let mut buf = Vec::new();
                if f.read_to_end(&mut buf).is_ok() {
                    res.embedded_images.push((im, buf));
                }
            }
        }
    }
    res
}

/// Parse Microsoft Visio `.vsdx` / `.vsdm` (`visio/pages/page*.xml` + `visio/media/*`).
pub fn parse_vsdx(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) else {
        res.warnings.push("invalid VSDX zip".into());
        return res;
    };
    let mut pages = Vec::new();
    let mut media = Vec::new();
    for i in 0..zip.len() {
        if let Some(name) = zip.name_for_index(i) {
            let nl = name.to_ascii_lowercase();
            if nl.starts_with("visio/pages/page") && nl.ends_with(".xml") {
                pages.push(name.to_string());
            } else if nl.starts_with("visio/media/") && !nl.ends_with('/') {
                media.push(name.to_string());
            }
        }
    }
    pages.sort();
    for (idx, p) in pages.iter().enumerate() {
        if let Ok(mut f) = zip.by_name(p) {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() {
                let txt = extract_xml_text(&buf);
                if !txt.trim().is_empty() {
                    res.segments.push(TextSegment {
                        scope: SegmentScope::Body,
                        location_label: format!("Visio 画布第{}页", idx + 1),
                        text: txt.trim().to_string(),
                    });
                }
            }
        }
    }
    for m in media {
        if let Ok(mut f) = zip.by_name(&m) {
            if f.size() <= 32 * 1024 * 1024 {
                let mut buf = Vec::new();
                if f.read_to_end(&mut buf).is_ok() {
                    res.embedded_images.push((m, buf));
                }
            }
        }
    }
    res
}

/// Parse MindManager `.mmap` (`Document.xml`).
pub fn parse_mmap(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) else {
        return res;
    };
    if let Ok(mut f) = zip.by_name("Document.xml") {
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_ok() {
            let (s, _) = decode_text_auto(&buf);
            let mut reader = Reader::from_str(&s);
            let mut rbuf = Vec::new();
            let mut topics = Vec::new();
            loop {
                match reader.read_event_into(&mut rbuf) {
                    Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"PlainText" {
                                if let Ok(v) = attr.decode_and_unescape_value(&reader) {
                                    if !v.trim().is_empty() {
                                        topics.push(v.trim().to_string());
                                    }
                                }
                            }
                        }
                    }
                    Ok(Event::Eof) | Err(_) => break,
                    _ => {}
                }
                rbuf.clear();
            }
            if !topics.is_empty() {
                res.segments.push(TextSegment {
                    scope: SegmentScope::Body,
                    location_label: "MindManager 导图主题".into(),
                    text: topics.join("\n"),
                });
            }
        }
    }
    res
}

/// Parse Apple iWork (`.pages`, `.numbers`, `.key`): extracts embedded Preview.pdf / QuickLook images & readable IWA text runs.
pub fn parse_iwork(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) else {
        return res;
    };
    let mut names = Vec::new();
    for i in 0..zip.len() {
        if let Some(n) = zip.name_for_index(i) {
            names.push(n.to_string());
        }
    }
    let mut iwa_strings = Vec::new();
    for name in names {
        let nl = name.to_ascii_lowercase();
        if nl == "quicklook/preview.pdf" || nl == "preview.pdf" {
            if let Ok(mut f) = zip.by_name(&name) {
                let mut buf = Vec::new();
                if f.read_to_end(&mut buf).is_ok() {
                    res.embedded_files.push((name, buf));
                }
            }
        } else if (nl.starts_with("data/") || nl.starts_with("quicklook/"))
            && (nl.ends_with(".png") || nl.ends_with(".jpg") || nl.ends_with(".jpeg"))
        {
            if let Ok(mut f) = zip.by_name(&name) {
                if f.size() <= 16 * 1024 * 1024 {
                    let mut buf = Vec::new();
                    if f.read_to_end(&mut buf).is_ok() {
                        res.embedded_images.push((name, buf));
                    }
                }
            }
        } else if nl.ends_with(".iwa") {
            if let Ok(mut f) = zip.by_name(&name) {
                if f.size() <= 16 * 1024 * 1024 {
                    let mut buf = Vec::new();
                    if f.read_to_end(&mut buf).is_ok() {
                        collect_printable_utf8_runs(&buf, 6, &mut iwa_strings);
                    }
                }
            }
        }
    }
    if !iwa_strings.is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "iWork 文档文本片段".into(),
            text: iwa_strings.join("\n"),
        });
    }
    res
}

/// Parse FictionBook 2.0 XML (`.fb2`) including embedded `<binary>` base64 images.
pub fn parse_fb2(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let (s, _) = decode_text_auto(bytes);
    let mut reader = Reader::from_str(&s);
    reader.trim_text(true);
    let mut buf = Vec::new();
    let mut out = String::new();
    let mut in_binary = false;
    let mut bin_id = String::new();
    let mut bin_buf = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_ascii_lowercase();
                if tag.ends_with("binary") {
                    in_binary = true;
                    bin_buf.clear();
                    bin_id = format!("fb2_img_{}.bin", res.embedded_images.len() + 1);
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"id" {
                            bin_id = String::from_utf8_lossy(&attr.value).to_string();
                        }
                    }
                }
            }
            Ok(Event::Text(e)) => {
                if let Ok(t) = e.unescape() {
                    if in_binary {
                        bin_buf.push_str(t.trim());
                    } else if !t.trim().is_empty() {
                        out.push_str(t.trim());
                        out.push(' ');
                    }
                }
            }
            Ok(Event::End(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_ascii_lowercase();
                if tag.ends_with("binary") && in_binary {
                    in_binary = false;
                    if let Some(decoded) = decode_base64(&bin_buf) {
                        res.embedded_images.push((bin_id.clone(), decoded));
                    }
                    bin_buf.clear();
                } else if matches!(tag.as_str(), "p" | "v" | "subtitle" | "title" | "section") {
                    if !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    if !out.trim().is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "FB2 电子书正文".into(),
            text: out.trim().to_string(),
        });
    }
    res
}

/// Parse SVG vector graphics (`<text>`, `<tspan>`, `<title>`, `<desc>` + inline base64 images).
pub fn parse_svg(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let (_, imgs) = extract_html_text_and_images(bytes);
    res.embedded_images.extend(imgs);
    let txt = extract_xml_text(bytes);
    if !txt.trim().is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "SVG 矢量图文本".into(),
            text: txt.trim().to_string(),
        });
    }
    res
}

/// Parse vCard (`.vcf`) and iCalendar (`.ics`) with RFC-5545 folded-line unfolding.
pub fn parse_vcf_or_ics(bytes: &[u8], kind: &str) -> OfficeParseResult {
    let (raw, _) = decode_text_auto(bytes);
    let unfolded = raw.replace("\r\n ", "").replace("\r\n\t", "").replace("\n ", "").replace("\n\t", "");
    OfficeParseResult {
        segments: vec![TextSegment {
            scope: SegmentScope::Body,
            location_label: format!("{kind} 结构化记录"),
            text: unfolded,
        }],
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Parse ESRI `.kmz` (ZIP containing `doc.kml` + images).
pub fn parse_kmz(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) else {
        return res;
    };
    let mut kmls = Vec::new();
    let mut imgs = Vec::new();
    for i in 0..zip.len() {
        if let Some(n) = zip.name_for_index(i) {
            let nl = n.to_ascii_lowercase();
            if nl.ends_with(".kml") {
                kmls.push(n.to_string());
            } else if nl.ends_with(".png") || nl.ends_with(".jpg") || nl.ends_with(".jpeg") {
                imgs.push(n.to_string());
            }
        }
    }
    for k in kmls {
        if let Ok(mut f) = zip.by_name(&k) {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() {
                let txt = extract_xml_text(&buf);
                if !txt.trim().is_empty() {
                    res.segments.push(TextSegment {
                        scope: SegmentScope::Body,
                        location_label: format!("KMZ 图层 ({k})"),
                        text: txt.trim().to_string(),
                    });
                }
            }
        }
    }
    for im in imgs {
        if let Ok(mut f) = zip.by_name(&im) {
            if f.size() <= 16 * 1024 * 1024 {
                let mut buf = Vec::new();
                if f.read_to_end(&mut buf).is_ok() {
                    res.embedded_images.push((im, buf));
                }
            }
        }
    }
    res
}

/// Parse 3D GIS `.b3dm`, `.glb`, `.las` metadata/BatchTable JSON without scanning raw vertex floats.
pub fn parse_3d_gis(bytes: &[u8], kind: &str) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    if kind == "b3dm" && bytes.len() >= 28 && &bytes[0..4] == b"b3dm" {
        let ft_json_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let ft_bin_len = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
        let bt_json_len = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]) as usize;
        let ft_start: usize = 28;
        let bt_start = ft_start.saturating_add(ft_json_len).saturating_add(ft_bin_len);
        if ft_start + ft_json_len <= bytes.len() && ft_json_len > 0 {
            let s = String::from_utf8_lossy(&bytes[ft_start..ft_start + ft_json_len]).trim().to_string();
            if !s.is_empty() {
                res.segments.push(TextSegment {
                    scope: SegmentScope::Metadata,
                    location_label: "B3DM FeatureTable JSON".into(),
                    text: s,
                });
            }
        }
        if bt_start + bt_json_len <= bytes.len() && bt_json_len > 0 {
            let s = String::from_utf8_lossy(&bytes[bt_start..bt_start + bt_json_len]).trim().to_string();
            if !s.is_empty() {
                res.segments.push(TextSegment {
                    scope: SegmentScope::Table,
                    location_label: "B3DM BatchTable 属性".into(),
                    text: s,
                });
            }
        }
        return res;
    }

    if kind == "glb" && bytes.len() >= 20 && &bytes[0..4] == b"glTF" {
        let chunk_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let chunk_type = &bytes[16..20];
        if chunk_type == b"JSON" && 20 + chunk_len <= bytes.len() {
            let s = String::from_utf8_lossy(&bytes[20..20 + chunk_len]).trim().to_string();
            res.segments.push(TextSegment {
                scope: SegmentScope::Metadata,
                location_label: "glTF JSON 元数据".into(),
                text: s,
            });
        }
        return res;
    }

    if kind == "las" && bytes.len() >= 227 && &bytes[0..4] == b"LASF" {
        let sys_id = String::from_utf8_lossy(&bytes[26..58]).trim_end_matches('\0').trim().to_string();
        let gen_sw = String::from_utf8_lossy(&bytes[58..90]).trim_end_matches('\0').trim().to_string();
        let header_size = u16::from_le_bytes([bytes[94], bytes[95]]) as usize;
        let num_vlrs = u32::from_le_bytes([bytes[100], bytes[101], bytes[102], bytes[103]]) as usize;
        let mut meta = vec![format!("SystemIdentifier: {sys_id}"), format!("GeneratingSoftware: {gen_sw}")];
        let mut pos = header_size;
        for _ in 0..num_vlrs.min(32) {
            if pos + 54 > bytes.len() {
                break;
            }
            let user_id = String::from_utf8_lossy(&bytes[pos + 2..pos + 18]).trim_end_matches('\0').to_string();
            let rec_len = u16::from_le_bytes([bytes[pos + 20], bytes[pos + 21]]) as usize;
            let desc = String::from_utf8_lossy(&bytes[pos + 22..pos + 54]).trim_end_matches('\0').to_string();
            pos += 54;
            if pos + rec_len <= bytes.len() {
                let body = &bytes[pos..pos + rec_len];
                let txt = String::from_utf8_lossy(body);
                if txt.chars().filter(|c| !c.is_control()).count() >= 4 {
                    meta.push(format!("VLR[{user_id}/{desc}]: {}", txt.trim_end_matches('\0')));
                }
                pos += rec_len;
            } else {
                break;
            }
        }
        res.segments.push(TextSegment {
            scope: SegmentScope::Metadata,
            location_label: "LAS 点云文件头与 VLR".into(),
            text: meta.join("\n"),
        });
    }
    res
}

/// Read-only SQLite `.sqlite` / `.db` / `.sqlite3` table & row extractor (bounded to avoid OOM on huge DBs).
pub fn parse_sqlite_db(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let tmp = std::env::temp_dir().join(format!(
        "deepdoc_sqlite_{}_{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    if let Err(e) = std::fs::write(&tmp, bytes) {
        res.warnings.push(format!("sqlite temp write failed: {e}"));
        return res;
    }

    if let Ok(conn) = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        let mut tables = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 100",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))) {
                for r in rows.flatten() {
                    tables.push(r);
                }
            }
        }

        let mut schema_lines = Vec::new();
        for (tname, sql_opt) in tables {
            if let Some(sql) = sql_opt {
                schema_lines.push(sql);
            }
            let safe_name = tname.replace('"', "\"\"");
            let q = format!("SELECT * FROM \"{safe_name}\" LIMIT 2000");
            if let Ok(mut stmt) = conn.prepare(&q) {
                let col_count = stmt.column_count();
                let mut rows_out = String::new();
                if let Ok(mut rows) = stmt.query([]) {
                    let mut r_idx = 0usize;
                    while let Ok(Some(row)) = rows.next() {
                        r_idx += 1;
                        let mut vals = Vec::new();
                        for ci in 0..col_count {
                            if let Ok(v) = row.get_ref(ci) {
                                let s = match v {
                                    rusqlite::types::ValueRef::Null => String::new(),
                                    rusqlite::types::ValueRef::Integer(i) => i.to_string(),
                                    rusqlite::types::ValueRef::Real(f) => f.to_string(),
                                    rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                                    rusqlite::types::ValueRef::Blob(b) => format!("[BLOB {}B]", b.len()),
                                };
                                if !s.trim().is_empty() {
                                    vals.push(s.trim().to_string());
                                }
                            }
                        }
                        if !vals.is_empty() {
                            rows_out.push_str(&format!("行{r_idx}: {}\n", vals.join(" | ")));
                        }
                        if rows_out.len() > 512 * 1024 {
                            rows_out.push_str("...(单表抽样截断)\n");
                            break;
                        }
                    }
                }
                if !rows_out.is_empty() {
                    res.segments.push(TextSegment {
                        scope: SegmentScope::Table,
                        location_label: format!("SQLite 表[{tname}]"),
                        text: rows_out,
                    });
                }
            }
        }
        if !schema_lines.is_empty() {
            res.segments.insert(
                0,
                TextSegment {
                    scope: SegmentScope::Metadata,
                    location_label: "SQLite 表结构".into(),
                    text: schema_lines.join("\n"),
                },
            );
        }
    } else {
        res.warnings.push("无法以只读模式打开 SQLite（可能已加密如 SQLCipher）".into());
    }

    let _ = std::fs::remove_file(&tmp);
    res
}

/// Parse `.dbf` (dBASE / FoxPro / ESRI Shapefile attribute tables) using `dbase` crate.
pub fn parse_dbf(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut reader) = dbase::Reader::new(Cursor::new(bytes)) else {
        res.warnings.push("dbase failed to parse DBF".into());
        return res;
    };

    let field_names: Vec<String> = reader.fields().iter().map(|f| f.name().to_string()).collect();
    if !field_names.is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Metadata,
            location_label: "DBF 字段定义".into(),
            text: field_names.join(", "),
        });
    }

    let mut rows_txt = String::new();
    for (idx, rec_res) in reader.iter_records().enumerate() {
        if idx >= 10_000 {
            rows_txt.push_str("...(超过10000行截断)\n");
            break;
        }
        if let Ok(rec) = rec_res {
            let mut vals = Vec::new();
            for fname in &field_names {
                if let Some(v) = rec.get(fname) {
                    let s = match v {
                        dbase::FieldValue::Character(Some(t)) => t.clone(),
                        dbase::FieldValue::Numeric(Some(n)) => format!("{n}"),
                        dbase::FieldValue::Float(Some(n)) => format!("{n}"),
                        dbase::FieldValue::Integer(n) => format!("{n}"),
                        dbase::FieldValue::Double(n) => format!("{n}"),
                        dbase::FieldValue::Logical(Some(b)) => format!("{b}"),
                        dbase::FieldValue::Date(Some(d)) => format!("{d:?}"),
                        dbase::FieldValue::Memo(m) => m.clone(),
                        _ => String::new(),
                    };
                    if !s.trim().is_empty() {
                        vals.push(format!("{fname}={}", s.trim()));
                    }
                }
            }
            if !vals.is_empty() {
                rows_txt.push_str(&format!("行{}: {}\n", idx + 1, vals.join(" | ")));
            }
        }
    }
    if !rows_txt.is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Table,
            location_label: "DBF / Shapefile 属性表".into(),
            text: rows_txt,
        });
    }
    res
}

/// Parse Kindle/Mobipocket `.mobi` / `.azw` / `.prc` using `mobi` crate.
pub fn parse_mobi(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(m) = mobi::Mobi::new(bytes.to_vec()) else {
        res.warnings.push("mobi failed to parse".into());
        return res;
    };
    let mut meta = Vec::new();
    meta.push(format!("Title: {}", m.title()));
    if let Some(author) = m.author() {
        meta.push(format!("Author: {author}"));
    }
    res.segments.push(TextSegment {
        scope: SegmentScope::Metadata,
        location_label: "MOBI 元数据".into(),
        text: meta.join("\n"),
    });
    let raw_html = m.content_as_string_lossy();
    let (txt, imgs) = extract_html_text_and_images(raw_html.as_bytes());
    if !txt.trim().is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "MOBI 正文".into(),
            text: txt.trim().to_string(),
        });
    }
    res.embedded_images.extend(imgs);
    res
}

/// Parse TNEF (`winmail.dat` signature `0x223E9F78`) extracting subject/attachments/body runs.
pub fn parse_tnef(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    if bytes.len() < 6 || u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != 0x223E_9F78 {
        return res;
    }
    let mut pos = 6usize;
    let mut cur_attach_name = String::new();
    let mut meta = Vec::new();

    while pos + 9 <= bytes.len() {
        let _lvl = bytes[pos];
        let id = u32::from_le_bytes([bytes[pos + 1], bytes[pos + 2], bytes[pos + 3], bytes[pos + 4]]);
        let len = u32::from_le_bytes([bytes[pos + 5], bytes[pos + 6], bytes[pos + 7], bytes[pos + 8]]) as usize;
        pos += 9;
        if pos.saturating_add(len).saturating_add(2) > bytes.len() {
            break;
        }
        let val = &bytes[pos..pos + len];
        pos += len + 2; // skip 2-byte checksum
        let attr_id = id & 0xFFFF;
        match attr_id {
            0x8004 => {
                // attSubject
                let (s, _) = decode_text_auto(val);
                meta.push(format!("Subject: {}", s.trim_end_matches('\0')));
            }
            0x8010 => {
                // attAttachTitle
                let (s, _) = decode_text_auto(val);
                cur_attach_name = s.trim_end_matches('\0').trim().to_string();
            }
            0x800F => {
                // attAttachData
                let fname = if cur_attach_name.is_empty() {
                    format!("tnef_att_{}.bin", res.embedded_files.len() + 1)
                } else {
                    std::mem::take(&mut cur_attach_name)
                };
                res.embedded_files.push((fname, val.to_vec()));
            }
            _ => {}
        }
    }
    if !meta.is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Metadata,
            location_label: "TNEF (winmail.dat) 头".into(),
            text: meta.join("\n"),
        });
    }
    res
}

/// Extract audio/video metadata tags (ID3, RIFF INFO, FLAC Vorbis, MP4 ilst strings) + FFmpeg/ASR slot notice.
pub fn parse_av_metadata(bytes: &[u8], kind: &str) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let mut tags = Vec::new();
    match kind {
        "mp3" => {
            if bytes.starts_with(b"ID3") && bytes.len() > 10 {
                let sz = ((bytes[6] as usize & 0x7F) << 21)
                    | ((bytes[7] as usize & 0x7F) << 14)
                    | ((bytes[8] as usize & 0x7F) << 7)
                    | (bytes[9] as usize & 0x7F);
                let end = (10 + sz).min(bytes.len());
                collect_printable_utf8_runs(&bytes[10..end], 4, &mut tags);
            }
        }
        "mp4" | "m4a" | "mov" => {
            if let Some(pos) = bytes.windows(4).position(|w| w == b"udta" || w == b"meta") {
                let slice = &bytes[pos..bytes.len().min(pos + 256 * 1024)];
                collect_printable_utf8_runs(slice, 4, &mut tags);
            }
        }
        "wav" | "avi" | "flac" | "mkv" | "ogg" => {
            let slice = &bytes[..bytes.len().min(256 * 1024)];
            collect_printable_utf8_runs(slice, 5, &mut tags);
        }
        _ => {}
    }
    if !tags.is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Metadata,
            location_label: format!("音视频元数据 ({kind})"),
            text: tags.into_iter().take(200).collect::<Vec<_>>().join("\n"),
        });
    }
    res.warnings.push(format!(
        "音视频 `{kind}` 已提取容器标签；部署 FFmpeg 与 sherpa-onnx 后可自动执行关键帧 OCR 与语音转文字"
    ));
    res
}

/// Enhanced DXF parser handling Chinese `$DWGCODEPAGE` (`ANSI_936` -> GB18030) reliably.
pub fn parse_dxf_smart(bytes: &[u8]) -> OfficeParseResult {
    let raw_ascii = String::from_utf8_lossy(&bytes[..bytes.len().min(32 * 1024)]);
    if raw_ascii.contains("ANSI_936") || raw_ascii.contains("GB2312") || raw_ascii.contains("GBK") {
        let (decoded, _, _) = encoding_rs::GB18030.decode(bytes);
        return parse_dxf_group_codes(&decoded);
    }
    if raw_ascii.contains("ANSI_950") {
        let (decoded, _, _) = encoding_rs::BIG5.decode(bytes);
        return parse_dxf_group_codes(&decoded);
    }
    if std::str::from_utf8(bytes).is_err() {
        let (decoded, _) = decode_text_auto(bytes);
        return parse_dxf_group_codes(&decoded);
    }

    if let Ok(drawing) = Drawing::load(&mut Cursor::new(bytes)) {
        return extract_from_drawing(&drawing);
    }
    let (decoded, _) = decode_text_auto(bytes);
    parse_dxf_group_codes(&decoded)
}

fn extract_from_drawing(drawing: &Drawing) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let layers: Vec<String> = drawing.layers().map(|l| l.name.clone()).collect();
    if !layers.is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Metadata,
            location_label: "CAD 图层".into(),
            text: layers.join(", "),
        });
    }
    let mut texts = Vec::new();
    for entity in drawing.entities() {
        let layer = &entity.common.layer;
        match &entity.specific {
            EntityType::Text(t) if !t.value.trim().is_empty() => {
                let txt = crate::dwg::decode_acad_text(&t.value, false);
                if !txt.is_empty() {
                    texts.push(format!("[{layer}] {txt}"));
                }
            }
            EntityType::MText(m) if !m.text.trim().is_empty() => {
                let txt = crate::dwg::decode_acad_text(&m.text, true);
                if !txt.is_empty() {
                    texts.push(format!("[{layer}] {txt}"));
                }
            }
            EntityType::Attribute(a) if !a.value.trim().is_empty() => {
                let txt = crate::dwg::decode_acad_text(&a.value, false);
                if !txt.is_empty() {
                    texts.push(format!("[{layer}] {}={txt}", a.attribute_tag));
                }
            }
            EntityType::AttributeDefinition(a) if !a.value.trim().is_empty() => {
                let txt = crate::dwg::decode_acad_text(&a.value, false);
                if !txt.is_empty() {
                    texts.push(format!("[{layer}] {txt}"));
                }
            }
            _ => {}
        }
    }
    if !texts.is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "DXF 标注与文字实体".into(),
            text: texts.join("\n"),
        });
    }
    res
}

fn parse_dxf_group_codes(text: &str) -> OfficeParseResult {
    let lines: Vec<&str> = text.lines().collect();
    let mut texts = Vec::new();
    let mut i = 0usize;
    while i + 1 < lines.len() {
        let code = lines[i].trim();
        let val = lines[i + 1].trim();
        if matches!(code, "1" | "3") && !val.is_empty() {
            let cleaned = crate::dwg::decode_acad_text(val, true);
            if !cleaned.is_empty() {
                texts.push(cleaned);
            }
        }
        i += 2;
    }
    OfficeParseResult {
        segments: if texts.is_empty() {
            Vec::new()
        } else {
            vec![TextSegment {
                scope: SegmentScope::Body,
                location_label: "DXF 组码文本".into(),
                text: texts.join("\n"),
            }]
        },
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    }
}

fn collect_printable_utf8_runs(bytes: &[u8], min_chars: usize, out: &mut Vec<String>) {
    let mut cur = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b >= 0x20 && b != 0x7F {
            cur.push(b);
            i += 1;
        } else {
            if cur.len() >= min_chars {
                if let Ok(s) = std::str::from_utf8(&cur) {
                    let trimmed = s.trim();
                    if trimmed.chars().count() >= min_chars {
                        out.push(trimmed.to_string());
                    }
                }
            }
            cur.clear();
            i += 1;
        }
    }
    if cur.len() >= min_chars {
        if let Ok(s) = std::str::from_utf8(&cur) {
            let trimmed = s.trim();
            if trimmed.chars().count() >= min_chars {
                out.push(trimmed.to_string());
            }
        }
    }
}

pub fn parse_access_db(bytes: &[u8], passwords: &[String]) -> (OfficeParseResult, bool, Vec<(String, String)>) {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let mut meta = Vec::new();
    let buf = bytes.to_vec();
    let mut reader_opt: Option<jetdb::PageReader> = None;
    let mut saw_encrypted = false;

    match jetdb::PageReader::open_reader_with_password(std::io::Cursor::new(buf.clone()), None) {
        Ok(r) => reader_opt = Some(r),
        Err(jetdb::FileError::PasswordRequired | jetdb::FileError::InvalidPassword) => {
            saw_encrypted = true;
            for pw in passwords {
                if let Ok(r) = jetdb::PageReader::open_reader_with_password(
                    std::io::Cursor::new(buf.clone()),
                    Some(pw.as_str()),
                ) {
                    reader_opt = Some(r);
                    meta.push(("access_decrypted_with_password".into(), "true".into()));
                    break;
                }
            }
            if reader_opt.is_none() {
                res.warnings.push("Access 数据库已加密，需要有效数据库密码".into());
                return (res, true, meta);
            }
        }
        Err(e) => {
            res.warnings.push(format!("Access 数据库打开失败: {e}"));
            return (res, false, meta);
        }
    }

    let mut reader = match reader_opt {
        Some(r) => r,
        None => return (res, saw_encrypted, meta),
    };
    let catalog = match jetdb::read_catalog(&mut reader) {
        Ok(c) => c,
        Err(e) => {
            res.warnings.push(format!("Access 目录解析失败: {e}"));
            return (res, saw_encrypted, meta);
        }
    };

    let tables: Vec<_> = catalog
        .iter()
        .filter(|e| e.object_type == jetdb::ObjectType::Table && !e.is_system_or_hidden())
        .cloned()
        .collect();
    meta.push(("access_tables".into(), tables.len().to_string()));

    let mut total_emitted = 0usize;
    let total_budget = 8 * 1024 * 1024usize;
    let csv_opts = jetdb::CsvOptions::default();

    for entry in tables {
        if total_emitted >= total_budget {
            res.warnings.push("Access 导出达到单库文本预算上限，已截断后续表".into());
            break;
        }
        let Ok(tdef) = jetdb::read_table_def(&mut reader, &entry.name, entry.table_page) else {
            continue;
        };
        let mut csv_bytes: Vec<u8> = Vec::new();
        if let Err(e) = jetdb::write_csv(
            &mut reader,
            &catalog,
            &tdef,
            &csv_opts,
            &mut csv_bytes,
            None,
        ) {
            res.warnings
                .push(format!("Access 表 `{}` 导出异常: {e}", entry.name));
            continue;
        }
        if !csv_bytes.is_empty() {
            let mut text = String::from_utf8_lossy(&csv_bytes).into_owned();
            let remaining = total_budget.saturating_sub(total_emitted);
            if text.len() > remaining {
                let mut end = remaining;
                while end > 0 && !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
            }
            total_emitted += text.len();
            if !text.trim().is_empty() {
                res.segments.push(TextSegment {
                    scope: SegmentScope::Table,
                    location_label: format!("Access[{}]", entry.name),
                    text,
                });
            }
        }
    }

    (res, saw_encrypted, meta)
}
