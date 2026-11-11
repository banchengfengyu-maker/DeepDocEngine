use crate::office::OfficeParseResult;
use crate::text::{decode_text_auto, extract_html_text_and_images};
use deepdoc_protocol::{SegmentScope, TextSegment};
use dxf::entities::EntityType;
use dxf::Drawing;
use mail_parser::{MessageParser, MimeHeaders};
use std::io::{Cursor, Read};

pub fn parse_eml(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Some(msg) = MessageParser::default().parse(bytes) else {
        res.warnings.push("mail-parser failed to parse EML".into());
        return res;
    };

    let mut meta_lines = Vec::new();
    if let Some(sub) = msg.subject() {
        meta_lines.push(format!("Subject: {sub}"));
    }
    if let Some(from) = msg.from() {
        meta_lines.push(format!("From: {from:?}"));
    }
    if let Some(to) = msg.to() {
        meta_lines.push(format!("To: {to:?}"));
    }
    if !meta_lines.is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Metadata,
            location_label: "邮件头".into(),
            text: meta_lines.join("\n"),
        });
    }

    if let Some(body) = msg.body_text(0) {
        if !body.trim().is_empty() {
            res.segments.push(TextSegment {
                scope: SegmentScope::Body,
                location_label: "邮件纯文本正文".into(),
                text: body.into_owned(),
            });
        }
    } else if let Some(html) = msg.body_html(0) {
        let (txt, imgs) = extract_html_text_and_images(html.as_bytes());
        if !txt.trim().is_empty() {
            res.segments.push(TextSegment {
                scope: SegmentScope::Body,
                location_label: "邮件 HTML 正文".into(),
                text: txt.trim().to_string(),
            });
        }
        res.embedded_images.extend(imgs);
    }

    for (idx, att) in msg.attachments().enumerate() {
        let fname = att
            .attachment_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("attachment_{}", idx + 1));
        let data = att.contents().to_vec();
        let lower = fname.to_ascii_lowercase();
        if lower.ends_with(".png")
            || lower.ends_with(".jpg")
            || lower.ends_with(".jpeg")
            || lower.ends_with(".bmp")
            || lower.ends_with(".gif")
            || lower.ends_with(".webp")
        {
            res.embedded_images.push((fname, data));
        } else {
            res.embedded_files.push((fname, data));
        }
    }
    res
}

/// Parse Outlook `.msg` OLE2 Compound File (`__substg1.0_*` MAPI streams & attachments).
pub fn parse_msg(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(mut comp) = cfb::CompoundFile::open(Cursor::new(bytes)) else {
        res.warnings.push("invalid MSG OLE2 container".into());
        return res;
    };

    let mut paths = Vec::new();
    for entry in comp.walk() {
        if entry.is_stream() {
            paths.push(entry.path().to_string_lossy().into_owned());
        }
    }

    let mut meta_lines = Vec::new();
    let mut body_text = String::new();
    let mut html_body = Vec::new();
    let mut attach_names: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut attach_blobs: Vec<(String, Vec<u8>)> = Vec::new();

    for path in &paths {
        let norm = path.replace('\\', "/");
        if let Ok(mut s) = comp.open_stream(path) {
            let mut buf = Vec::new();
            if s.read_to_end(&mut buf).is_err() {
                continue;
            }
            let leaf = norm.rsplit('/').next().unwrap_or("");
            if norm.contains("__attach_version1.0_") {
                let prefix = norm.rsplit_once('/').map(|(p, _)| p).unwrap_or("").to_string();
                if leaf == "__substg1.0_3707001F" {
                    attach_names.insert(prefix, decode_utf16le_lossy(&buf));
                } else if leaf == "__substg1.0_3704001F" && !attach_names.contains_key(&prefix) {
                    attach_names.insert(prefix, decode_utf16le_lossy(&buf));
                } else if leaf == "__substg1.0_37010102" {
                    attach_blobs.push((prefix, buf));
                }
                continue;
            }
            match leaf {
                "__substg1.0_0037001F" => meta_lines.push(format!("Subject: {}", decode_utf16le_lossy(&buf))),
                "__substg1.0_0C1A001F" => meta_lines.push(format!("From: {}", decode_utf16le_lossy(&buf))),
                "__substg1.0_0E04001F" => meta_lines.push(format!("To: {}", decode_utf16le_lossy(&buf))),
                "__substg1.0_1000001F" => body_text = decode_utf16le_lossy(&buf),
                "__substg1.0_1000001E" if body_text.is_empty() => body_text = decode_text_auto(&buf).0,
                "__substg1.0_10130102" => html_body = buf,
                _ => {}
            }
        }
    }

    if !meta_lines.is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Metadata,
            location_label: "MSG 邮件头".into(),
            text: meta_lines.join("\n"),
        });
    }
    if !body_text.trim().is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "MSG 正文".into(),
            text: body_text.trim().to_string(),
        });
    } else if !html_body.is_empty() {
        let (txt, imgs) = extract_html_text_and_images(&html_body);
        if !txt.trim().is_empty() {
            res.segments.push(TextSegment {
                scope: SegmentScope::Body,
                location_label: "MSG HTML 正文".into(),
                text: txt.trim().to_string(),
            });
        }
        res.embedded_images.extend(imgs);
    }

    for (idx, (prefix, data)) in attach_blobs.into_iter().enumerate() {
        let fname = attach_names
            .remove(&prefix)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("msg_attachment_{}.bin", idx + 1));
        res.embedded_files.push((fname, data));
    }

    res
}

pub fn parse_dxf(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let Ok(drawing) = Drawing::load(&mut Cursor::new(bytes)) else {
        // Fallback: text lines if DXF has non-standard header/GBK codepage
        let (txt, _) = decode_text_auto(bytes);
        res.segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "DXF 文本回退".into(),
            text: txt,
        });
        res.warnings.push("dxf crate parse fell back to text extraction".into());
        return res;
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
                texts.push(format!("[{layer}] {}", t.value.trim()));
            }
            EntityType::MText(m) if !m.text.trim().is_empty() => {
                texts.push(format!("[{layer}] {}", m.text.trim()));
            }
            EntityType::Attribute(a) if !a.value.trim().is_empty() => {
                texts.push(format!("[{layer}] {}={}", a.attribute_tag, a.value.trim()));
            }
            EntityType::AttributeDefinition(a) if !a.value.trim().is_empty() => {
                texts.push(format!("[{layer}] {}", a.value.trim()));
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

fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_string()
}
