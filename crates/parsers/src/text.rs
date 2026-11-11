use chardetng::{EncodingDetector, Iso2022JpDetection, Utf8Detection};
use deepdoc_protocol::{SegmentScope, TextSegment};
use encoding_rs::{Encoding, UTF_16BE, UTF_16LE, UTF_8};
use quick_xml::events::Event;
use quick_xml::Reader;

/// Decode arbitrary text bytes (UTF-8, UTF-16LE/BE with BOM, GB18030/GBK/Big5) automatically.
pub fn decode_text_auto(bytes: &[u8]) -> (String, &'static str) {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        let (s, _, _) = UTF_8.decode(&bytes[3..]);
        return (s.into_owned(), "utf-8-bom");
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let (s, _, _) = UTF_16LE.decode(&bytes[2..]);
        return (s.into_owned(), "utf-16le");
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let (s, _, _) = UTF_16BE.decode(&bytes[2..]);
        return (s.into_owned(), "utf-16be");
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return (s.to_string(), "utf-8");
    }
    let mut det = EncodingDetector::new(Iso2022JpDetection::Deny);
    det.feed(&bytes[..bytes.len().min(64 * 1024)], true);
    let enc: &'static Encoding = det.guess(None, Utf8Detection::Allow);
    let (decoded, _, _) = enc.decode(bytes);
    (decoded.into_owned(), enc.name())
}

/// Extract first 10 non-empty lines and last 10 non-empty lines into a `HeadTail` segment
/// to directly support official document classification / red-header regex rules.
pub fn build_head_tail_segment(text: &str) -> Option<TextSegment> {
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return None;
    }
    let mut out = String::new();
    let head_end = lines.len().min(10);
    for l in &lines[..head_end] {
        out.push_str(l);
        out.push('\n');
    }
    if lines.len() > 10 {
        let tail_start = lines.len().saturating_sub(10).max(head_end);
        for l in &lines[tail_start..] {
            out.push_str(l);
            out.push('\n');
        }
    }
    Some(TextSegment {
        scope: SegmentScope::HeadTail,
        location_label: "文档首尾行 (前10/后10行)".to_string(),
        text: out,
    })
}

pub fn parse_csv_segments(bytes: &[u8]) -> Vec<TextSegment> {
    let (text, _) = decode_text_auto(bytes);
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(false)
        .from_reader(text.as_bytes());
    let mut out = String::new();
    for (idx, rec) in rdr.records().enumerate() {
        if let Ok(r) = rec {
            let row: Vec<&str> = r.iter().collect();
            out.push_str(&format!("行{}: {}\n", idx + 1, row.join(" | ")));
        }
    }
    if out.is_empty() {
        out = text;
    }
    vec![TextSegment {
        scope: SegmentScope::Table,
        location_label: "CSV 表格".to_string(),
        text: out,
    }]
}

pub fn extract_xml_text(xml_bytes: &[u8]) -> String {
    let (text, _) = decode_text_auto(xml_bytes);
    let mut reader = Reader::from_str(&text);
    reader.trim_text(true);
    let mut buf = Vec::new();
    let mut out = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Text(e)) => {
                if let Ok(t) = e.unescape() {
                    let s = t.trim();
                    if !s.is_empty() {
                        out.push_str(s);
                        out.push(' ');
                    }
                }
            }
            Ok(Event::CData(e)) => {
                let s = String::from_utf8_lossy(e.as_ref());
                let s = s.trim();
                if !s.is_empty() {
                    out.push_str(s);
                    out.push(' ');
                }
            }
            Ok(Event::End(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_ascii_lowercase();
                if matches!(tag.as_str(), "p" | "tr" | "row" | "div" | "li" | "br" | "h1" | "h2" | "h3" | "w:p" | "text:p") {
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
    out
}

/// Strip HTML scripts/styles and extract visible text + any embedded `data:image/...;base64,...` blobs.
pub fn extract_html_text_and_images(bytes: &[u8]) -> (String, Vec<(String, Vec<u8>)>) {
    let (html, _) = decode_text_auto(bytes);
    let lower = html.to_ascii_lowercase();
    let mut out = String::with_capacity(html.len() / 2);
    let mut skip_tag: Option<&str> = None;
    let mut i = 0;
    let hb = html.as_bytes();
    let lb = lower.as_bytes();

    while i < hb.len() {
        if let Some(tag) = skip_tag {
            let needle = format!("</{tag}");
            if let Some(pos) = lower[i..].find(&needle) {
                let close_start = i + pos;
                if let Some(gt) = html[close_start..].find('>') {
                    i = close_start + gt + 1;
                } else {
                    break;
                }
                skip_tag = None;
            } else {
                break;
            }
            continue;
        }
        if hb[i] == b'<' {
            if lb[i..].starts_with(b"<script") {
                skip_tag = Some("script");
                continue;
            }
            if lb[i..].starts_with(b"<style") {
                skip_tag = Some("style");
                continue;
            }
            if let Some(gt) = html[i..].find('>') {
                let tag_inner = &lower[i + 1..i + gt];
                if tag_inner.starts_with("br")
                    || tag_inner.starts_with("p")
                    || tag_inner.starts_with("/p")
                    || tag_inner.starts_with("/div")
                    || tag_inner.starts_with("/tr")
                    || tag_inner.starts_with("/li")
                {
                    if !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
                i += gt + 1;
                continue;
            }
        }
        if let Some(ch) = html[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    // Extract inline base64 data:image/...;base64,...
    let mut images = Vec::new();
    let mut search_from = 0;
    while let Some(pos) = lower[search_from..].find("data:image/") {
        let abs = search_from + pos;
        if let Some(b64_off) = lower[abs..].find(";base64,") {
            let ext = &lower[abs + "data:image/".len()..abs + b64_off];
            let data_start = abs + b64_off + ";base64,".len();
            let data_end = html[data_start..]
                .find(|c: char| matches!(c, '"' | '\'' | ')' | ' ' | '\n' | '\r' | '<'))
                .map(|o| data_start + o)
                .unwrap_or(html.len());
            if let Some(decoded) = decode_base64(&html[data_start..data_end]) {
                images.push((format!("inline_img_{}.{ext}", images.len() + 1), decoded));
            }
            search_from = data_end;
        } else {
            search_from = abs + 11;
        }
    }

    let decoded_entities = out
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"");

    (decoded_entities, images)
}

/// Lightweight RTF visible-text extractor supporting nested groups and `\'xx` ANSI/GBK hex escapes.
pub fn extract_rtf_text(bytes: &[u8]) -> String {
    let mut out = Vec::<u8>::new();
    let mut skip_depth: Option<usize> = None;
    let mut depth: usize = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                if skip_depth == Some(depth) {
                    skip_depth = None;
                }
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b'\\' => {
                i += 1;
                if i >= bytes.len() {
                    break;
                }
                match bytes[i] {
                    b'\\' | b'{' | b'}' => {
                        if skip_depth.is_none() {
                            out.push(bytes[i]);
                        }
                        i += 1;
                    }
                    b'\'' if i + 2 < bytes.len() => {
                        if skip_depth.is_none() {
                            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                                if let Ok(v) = u8::from_str_radix(hex_str, 16) {
                                    out.push(v);
                                }
                            }
                        }
                        i += 3;
                    }
                    b'~' => {
                        if skip_depth.is_none() {
                            out.push(b' ');
                        }
                        i += 1;
                    }
                    _ => {
                        let start = i;
                        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                            i += 1;
                        }
                        let word = &bytes[start..i];
                        if i < bytes.len() && (bytes[i] == b'-' || bytes[i].is_ascii_digit()) {
                            i += 1;
                            while i < bytes.len() && bytes[i].is_ascii_digit() {
                                i += 1;
                            }
                        }
                        if i < bytes.len() && bytes[i] == b' ' {
                            i += 1;
                        }
                        if matches!(
                            word,
                            b"fonttbl" | b"colortbl" | b"stylesheet" | b"info" | b"pict" | b"object" | b"themedata"
                        ) && skip_depth.is_none()
                        {
                            skip_depth = Some(depth);
                        } else if skip_depth.is_none() && matches!(word, b"par" | b"line" | b"row") {
                            out.push(b'\n');
                        } else if skip_depth.is_none() && matches!(word, b"tab" | b"cell") {
                            out.push(b'\t');
                        }
                    }
                }
            }
            b'\r' | b'\n' => {
                i += 1;
            }
            b => {
                if skip_depth.is_none() {
                    out.push(b);
                }
                i += 1;
            }
        }
    }
    decode_text_auto(&out).0
}

pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    const TABLE: [i8; 256] = {
        let mut t = [-1i8; 256];
        let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 {
            t[alpha[i] as usize] = i as i8;
            i += 1;
        }
        t
    };
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input.as_bytes() {
        if b == b'=' || b.is_ascii_whitespace() {
            continue;
        }
        let v = TABLE[b as usize];
        if v < 0 {
            return None;
        }
        acc = (acc << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}
