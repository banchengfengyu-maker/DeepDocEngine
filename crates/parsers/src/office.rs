use crate::text::{build_head_tail_segment, decode_text_auto, extract_html_text_and_images, extract_xml_text};
use calamine::{open_workbook_auto_from_rs, Data, Reader};
use deepdoc_protocol::{SegmentScope, TextSegment};
use serde_json::Value;
use std::io::{Cursor, Read};
use zip::ZipArchive;

pub struct OfficeParseResult {
    pub segments: Vec<TextSegment>,
    pub embedded_images: Vec<(String, Vec<u8>)>,
    pub embedded_files: Vec<(String, Vec<u8>)>,
    pub warnings: Vec<String>,
}

pub fn parse_spreadsheet_calamine(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };

    let Ok(mut wb) = open_workbook_auto_from_rs(Cursor::new(bytes)) else {
        res.warnings.push("calamine failed to open spreadsheet".into());
        return res;
    };

    let names = wb.sheet_names().to_vec();
    for sheet_name in names {
        if let Ok(range) = wb.worksheet_range(&sheet_name) {
            let mut rows_text = String::new();
            for (r_idx, row) in range.rows().enumerate() {
                let mut cells = Vec::new();
                for c in row {
                    let s = match c {
                        Data::Empty => String::new(),
                        Data::String(v) => v.clone(),
                        Data::Int(v) => v.to_string(),
                        Data::Float(v) => format!("{v}"),
                        Data::Bool(v) => v.to_string(),
                        Data::DateTime(v) => format!("{v}"),
                        Data::DateTimeIso(v) => v.clone(),
                        Data::DurationIso(v) => v.clone(),
                        Data::Error(e) => format!("{e:?}"),
                    };
                    if !s.trim().is_empty() {
                        cells.push(s.trim().to_string());
                    }
                }
                if !cells.is_empty() {
                    rows_text.push_str(&format!("行{}: {}\n", r_idx + 1, cells.join(" | ")));
                }
            }
            if !rows_text.is_empty() {
                res.segments.push(TextSegment {
                    scope: SegmentScope::Table,
                    location_label: format!("Sheet[{sheet_name}]"),
                    text: rows_text,
                });
            }
        }
    }

    // Also extract embedded images in xl/media/* if it's a zip-based workbook
    if let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) {
        extract_zip_media(&mut zip, "xl/media/", &mut res.embedded_images);
        extract_zip_embeddings(&mut zip, "xl/embeddings/", &mut res.embedded_files);
    }

    res
}

pub fn parse_docx(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) else {
        res.warnings.push("invalid docx zip".into());
        return res;
    };

    let mut full_body = String::new();
    let mut ordered_xml = Vec::new();
    for i in 0..zip.len() {
        if let Some(name) = zip.name_for_index(i) {
            let nl = name.to_ascii_lowercase();
            if nl == "word/document.xml"
                || nl.starts_with("word/header")
                || nl.starts_with("word/footer")
                || nl == "word/comments.xml"
                || nl == "word/footnotes.xml"
                || nl == "word/endnotes.xml"
            {
                ordered_xml.push(name.to_string());
            }
        }
    }
    ordered_xml.sort();

    for name in ordered_xml {
        if let Ok(mut f) = zip.by_name(&name) {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() {
                let txt = extract_xml_text(&buf);
                let trimmed = txt.trim();
                if !trimmed.is_empty() {
                    let (scope, label) = if name.contains("comments") {
                        (SegmentScope::Comment, "批注 (word/comments.xml)".to_string())
                    } else if name.contains("header") || name.contains("footer") {
                        (SegmentScope::Body, format!("页眉页脚 ({name})"))
                    } else {
                        full_body.push_str(trimmed);
                        full_body.push('\n');
                        (SegmentScope::Body, format!("正文 ({name})"))
                    };
                    res.segments.push(TextSegment {
                        scope,
                        location_label: label,
                        text: trimmed.to_string(),
                    });
                }
            }
        }
    }

    if let Some(ht) = build_head_tail_segment(&full_body) {
        res.segments.insert(0, ht);
    }

    extract_zip_media(&mut zip, "word/media/", &mut res.embedded_images);
    extract_zip_embeddings(&mut zip, "word/embeddings/", &mut res.embedded_files);
    res
}

pub fn parse_pptx(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) else {
        res.warnings.push("invalid pptx zip".into());
        return res;
    };

    let mut slide_names = Vec::new();
    let mut note_names = Vec::new();
    for i in 0..zip.len() {
        if let Some(name) = zip.name_for_index(i) {
            if name.starts_with("ppt/slides/slide") && name.ends_with(".xml") {
                slide_names.push(name.to_string());
            } else if name.starts_with("ppt/notesSlides/notesSlide") && name.ends_with(".xml") {
                note_names.push(name.to_string());
            }
        }
    }
    slide_names.sort_by_key(|n| extract_trailing_num(n));
    note_names.sort_by_key(|n| extract_trailing_num(n));

    for name in slide_names {
        if let Ok(mut f) = zip.by_name(&name) {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() {
                let txt = extract_xml_text(&buf);
                let trimmed = txt.trim();
                if !trimmed.is_empty() {
                    let num = extract_trailing_num(&name);
                    res.segments.push(TextSegment {
                        scope: SegmentScope::Body,
                        location_label: format!("幻灯片 第{num}页"),
                        text: trimmed.to_string(),
                    });
                }
            }
        }
    }
    for name in note_names {
        if let Ok(mut f) = zip.by_name(&name) {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() {
                let txt = extract_xml_text(&buf);
                let trimmed = txt.trim();
                if !trimmed.is_empty() {
                    let num = extract_trailing_num(&name);
                    res.segments.push(TextSegment {
                        scope: SegmentScope::Comment,
                        location_label: format!("幻灯片备注 第{num}页"),
                        text: trimmed.to_string(),
                    });
                }
            }
        }
    }

    extract_zip_media(&mut zip, "ppt/media/", &mut res.embedded_images);
    extract_zip_embeddings(&mut zip, "ppt/embeddings/", &mut res.embedded_files);
    res
}

pub fn parse_odf_xml(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) else {
        res.warnings.push("invalid ODF zip".into());
        return res;
    };
    if let Ok(mut f) = zip.by_name("content.xml") {
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_ok() {
            let txt = extract_xml_text(&buf);
            if let Some(ht) = build_head_tail_segment(&txt) {
                res.segments.push(ht);
            }
            if !txt.trim().is_empty() {
                res.segments.push(TextSegment {
                    scope: SegmentScope::Body,
                    location_label: "ODF content.xml".into(),
                    text: txt.trim().to_string(),
                });
            }
        }
    }
    extract_zip_media(&mut zip, "Pictures/", &mut res.embedded_images);
    res
}

pub fn parse_xmind(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) else {
        res.warnings.push("invalid XMind zip".into());
        return res;
    };
    let json_bytes = if let Ok(mut f) = zip.by_name("content.json") {
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_ok() {
            Some(buf)
        } else {
            None
        }
    } else {
        None
    };

    if let Some(buf) = json_bytes {
        let (s, _) = decode_text_auto(&buf);
        if let Ok(val) = serde_json::from_str::<Value>(&s) {
            let mut titles = Vec::new();
            collect_xmind_titles(&val, &mut titles);
            if !titles.is_empty() {
                res.segments.push(TextSegment {
                    scope: SegmentScope::Body,
                    location_label: "XMind 思维导图节点".into(),
                    text: titles.join("\n"),
                });
            }
        }
    } else if let Ok(mut f) = zip.by_name("content.xml") {
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_ok() {
            let txt = extract_xml_text(&buf);
            if !txt.trim().is_empty() {
                res.segments.push(TextSegment {
                    scope: SegmentScope::Body,
                    location_label: "XMind content.xml".into(),
                    text: txt.trim().to_string(),
                });
            }
        }
    }
    extract_zip_media(&mut zip, "resources/", &mut res.embedded_images);
    res
}

pub fn parse_epub(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut zip) = ZipArchive::new(Cursor::new(bytes)) else {
        res.warnings.push("invalid EPUB zip".into());
        return res;
    };
    let mut html_names = Vec::new();
    let mut img_names = Vec::new();
    for i in 0..zip.len() {
        if let Some(name) = zip.name_for_index(i) {
            let nl = name.to_ascii_lowercase();
            if nl.ends_with(".html") || nl.ends_with(".xhtml") || nl.ends_with(".htm") {
                html_names.push(name.to_string());
            } else if nl.ends_with(".png") || nl.ends_with(".jpg") || nl.ends_with(".jpeg") || nl.ends_with(".webp") {
                img_names.push(name.to_string());
            }
        }
    }
    for name in img_names {
        if let Ok(mut f) = zip.by_name(&name) {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() {
                res.embedded_images.push((name, buf));
            }
        }
    }
    html_names.sort();
    for name in html_names {
        if let Ok(mut f) = zip.by_name(&name) {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() {
                let (txt, imgs) = extract_html_text_and_images(&buf);
                if !txt.trim().is_empty() {
                    res.segments.push(TextSegment {
                        scope: SegmentScope::Body,
                        location_label: format!("EPUB章节 ({name})"),
                        text: txt.trim().to_string(),
                    });
                }
                res.embedded_images.extend(imgs);
            }
        }
    }
    res
}

fn collect_xmind_titles(val: &Value, out: &mut Vec<String>) {
    match val {
        Value::Object(map) => {
            if let Some(Value::String(t)) = map.get("title") {
                if !t.trim().is_empty() {
                    out.push(t.trim().to_string());
                }
            }
            if let Some(Value::Object(notes)) = map.get("notes") {
                if let Some(Value::Object(plain)) = notes.get("plain") {
                    if let Some(Value::String(c)) = plain.get("content") {
                        if !c.trim().is_empty() {
                            out.push(c.trim().to_string());
                        }
                    }
                }
            }
            for (k, v) in map {
                if k != "title" && k != "notes" {
                    collect_xmind_titles(v, out);
                }
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_xmind_titles(v, out);
            }
        }
        _ => {}
    }
}

fn extract_zip_media(zip: &mut ZipArchive<Cursor<&[u8]>>, prefix: &str, out: &mut Vec<(String, Vec<u8>)>) {
    let mut names = Vec::new();
    for i in 0..zip.len() {
        if let Some(name) = zip.name_for_index(i) {
            if name.starts_with(prefix) && !name.ends_with('/') {
                names.push(name.to_string());
            }
        }
    }
    for name in names {
        if let Ok(mut f) = zip.by_name(&name) {
            if f.size() <= 32 * 1024 * 1024 {
                let mut buf = Vec::new();
                if f.read_to_end(&mut buf).is_ok() {
                    out.push((name, buf));
                }
            }
        }
    }
}

fn extract_zip_embeddings(zip: &mut ZipArchive<Cursor<&[u8]>>, prefix: &str, out: &mut Vec<(String, Vec<u8>)>) {
    extract_zip_media(zip, prefix, out);
}

fn extract_trailing_num(path: &str) -> u32 {
    let stem = path.rsplit('/').next().unwrap_or(path);
    let digits: String = stem.chars().filter(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or(0)
}
