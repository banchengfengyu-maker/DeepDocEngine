use crate::office::OfficeParseResult;
use crate::text::{build_head_tail_segment, decode_text_auto, extract_xml_text};
use deepdoc_protocol::{SegmentScope, TextSegment};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::io::{Cursor, Read};
use zip::ZipArchive;

/// Parse Chinese national standard OFD (Open Fixed-layout Document):
/// Reads pages, sorts `ofd:TextObject` by `(y, x)` to reconstruct reading order,
/// and extracts `Res/` / `Signs/` embedded images for OCR.
pub fn parse_ofd(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) else {
        res.warnings.push("invalid OFD zip".into());
        return res;
    };

    let mut content_xmls = Vec::new();
    let mut image_paths = Vec::new();
    for i in 0..zip.len() {
        if let Some(name) = zip.name_for_index(i) {
            let nl = name.to_ascii_lowercase();
            if nl.ends_with("/content.xml") || nl == "content.xml" {
                content_xmls.push(name.to_string());
            } else if (nl.contains("/res/") || nl.contains("/signs/"))
                && (nl.ends_with(".png")
                    || nl.ends_with(".jpg")
                    || nl.ends_with(".jpeg")
                    || nl.ends_with(".bmp")
                    || nl.ends_with(".tif")
                    || nl.ends_with(".webp"))
            {
                image_paths.push(name.to_string());
            }
        }
    }
    content_xmls.sort();

    let mut all_text = String::new();
    for (page_idx, name) in content_xmls.iter().enumerate() {
        if let Ok(mut f) = zip.by_name(name) {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() {
                let page_txt = extract_ofd_page_text(&buf);
                if !page_txt.is_empty() {
                    all_text.push_str(&page_txt);
                    all_text.push('\n');
                    res.segments.push(TextSegment {
                        scope: SegmentScope::Body,
                        location_label: format!("OFD 第{}页 ({name})", page_idx + 1),
                        text: page_txt,
                    });
                }
            }
        }
    }

    if let Some(ht) = build_head_tail_segment(&all_text) {
        res.segments.insert(0, ht);
    }

    for img_path in image_paths {
        if let Ok(mut f) = zip.by_name(&img_path) {
            if f.size() <= 32 * 1024 * 1024 {
                let mut buf = Vec::new();
                if f.read_to_end(&mut buf).is_ok() {
                    res.embedded_images.push((img_path, buf));
                }
            }
        }
    }
    res
}

fn extract_ofd_page_text(xml_bytes: &[u8]) -> String {
    let (s, _) = decode_text_auto(xml_bytes);
    let mut reader = Reader::from_str(&s);
    reader.trim_text(false);
    let mut buf = Vec::new();

    #[derive(Clone)]
    struct TextRun {
        y: f64,
        x: f64,
        text: String,
    }

    let mut runs: Vec<TextRun> = Vec::new();
    let mut cur_x = 0.0f64;
    let mut cur_y = 0.0f64;
    let mut in_text_code = false;
    let mut cur_buf = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name.ends_with("TextObject") {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"Boundary" {
                            let v = String::from_utf8_lossy(&attr.value);
                            let nums: Vec<f64> = v
                                .split_whitespace()
                                .filter_map(|p| p.parse::<f64>().ok())
                                .collect();
                            if nums.len() >= 2 {
                                cur_x = nums[0];
                                cur_y = nums[1];
                            }
                        }
                    }
                } else if name.ends_with("TextCode") {
                    in_text_code = true;
                    cur_buf.clear();
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"Y" {
                            let v = String::from_utf8_lossy(&attr.value);
                            if let Ok(dy) = v.trim().parse::<f64>() {
                                cur_y += dy;
                            }
                        } else if attr.key.as_ref() == b"X" {
                            let v = String::from_utf8_lossy(&attr.value);
                            if let Ok(dx) = v.trim().parse::<f64>() {
                                cur_x += dx;
                            }
                        }
                    }
                }
            }
            Ok(Event::Text(e)) if in_text_code => {
                if let Ok(t) = e.unescape() {
                    cur_buf.push_str(&t);
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name.ends_with("TextCode") && in_text_code {
                    in_text_code = false;
                    let t = cur_buf.trim();
                    if !t.is_empty() {
                        runs.push(TextRun {
                            y: cur_y,
                            x: cur_x,
                            text: t.to_string(),
                        });
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    runs.sort_by(|a, b| {
        let bucket_a = (a.y / 2.0).round() as i64;
        let bucket_b = (b.y / 2.0).round() as i64;
        bucket_a
            .cmp(&bucket_b)
            .then_with(|| a.x.partial_cmp(&b.x).unwrap_or(std::cmp::Ordering::Equal))
    });

    let mut out = String::new();
    let mut last_bucket: Option<i64> = None;
    for run in runs {
        let bucket = (run.y / 2.0).round() as i64;
        if let Some(lb) = last_bucket {
            if lb != bucket {
                out.push('\n');
            }
        }
        out.push_str(&run.text);
        last_bucket = Some(bucket);
    }
    out
}

/// Parse Chinese national standard UOF / UOT XML or ZIP+XML document.
pub fn parse_uof(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    if bytes.starts_with(b"PK\x03\x04") {
        if let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) {
            let mut all_txt = String::new();
            for i in 0..zip.len() {
                let name_opt = zip.name_for_index(i).map(|s| s.to_string());
                if let Some(name) = name_opt {
                    let nl = name.to_ascii_lowercase();
                    if nl.ends_with(".xml") {
                        if let Ok(mut f) = zip.by_name(&name) {
                            let mut buf = Vec::new();
                            if f.read_to_end(&mut buf).is_ok() {
                                let txt = extract_xml_text(&buf);
                                if !txt.trim().is_empty() {
                                    all_txt.push_str(txt.trim());
                                    all_txt.push('\n');
                                }
                            }
                        }
                    } else if nl.ends_with(".png") || nl.ends_with(".jpg") || nl.ends_with(".jpeg") {
                        if let Ok(mut f) = zip.by_name(&name) {
                            let mut buf = Vec::new();
                            if f.read_to_end(&mut buf).is_ok() {
                                res.embedded_images.push((name, buf));
                            }
                        }
                    }
                }
            }
            if let Some(ht) = build_head_tail_segment(&all_txt) {
                res.segments.push(ht);
            }
            if !all_txt.trim().is_empty() {
                res.segments.push(TextSegment {
                    scope: SegmentScope::Body,
                    location_label: "UOF 文档正文".into(),
                    text: all_txt.trim().to_string(),
                });
            }
            return res;
        }
    }

    let txt = extract_xml_text(bytes);
    if let Some(ht) = build_head_tail_segment(&txt) {
        res.segments.push(ht);
    }
    if !txt.trim().is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "UOF XML 正文".into(),
            text: txt.trim().to_string(),
        });
    }
    res
}
