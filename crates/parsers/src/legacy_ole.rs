use crate::office::OfficeParseResult;
use crate::text::{build_head_tail_segment, decode_text_auto};
use deepdoc_protocol::{SegmentScope, TextSegment};
use std::io::{Cursor, Read};

/// Native MS-DOC / MS-PPT / WPS / DPS / ET OLE2 binary fallback parser + embedded image carver.
/// Used automatically when ONLYOFFICE Core (`x2t.exe`) is not deployed, or if `x2t` returns an error.
pub fn parse_legacy_doc_or_wps(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };

    let Ok(mut comp) = cfb::CompoundFile::open(Cursor::new(bytes)) else {
        res.warnings.push("invalid OLE2 compound file".into());
        return res;
    };

    let mut streams: Vec<String> = Vec::new();
    for entry in comp.walk() {
        if entry.is_stream() {
            streams.push(entry.path().to_string_lossy().into_owned());
        }
    }

    let read_stream = |c: &mut cfb::CompoundFile<Cursor<&[u8]>>, name: &str| -> Option<Vec<u8>> {
        let mut s = c.open_stream(name).ok()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).ok()?;
        Some(buf)
    };

    let mut extracted = String::new();
    if let Some(wd) = read_stream(&mut comp, "WordDocument") {
        if let Some(txt) = parse_word_piece_table(&wd, &mut comp) {
            extracted = txt;
        }
        if extracted.trim().is_empty() {
            extracted = extract_fib_or_runs(&wd);
        }
        carve_embedded_images(&wd, "WordDocument", &mut res.embedded_images);
    }

    // Kingsoft WPS sometimes uses `Contents` or `WpsContent` stream
    if extracted.trim().is_empty() {
        for sname in &streams {
            let low = sname.to_ascii_lowercase();
            if low.contains("content") || low.contains("text") {
                if let Some(data) = read_stream(&mut comp, sname) {
                    let candidate = extract_utf16_and_gbk_runs(&data);
                    if candidate.chars().count() > extracted.chars().count() {
                        extracted = candidate;
                    }
                }
            }
        }
    }

    // Carve embedded PNG/JPEG from `Data`, `Pictures`, `1Table`, `0Table`, or ObjectPool streams
    for sname in &streams {
        let low = sname.to_ascii_lowercase();
        if low.contains("picture") || low.contains("data") || low.contains("media") || low.contains("object") {
            if let Some(data) = read_stream(&mut comp, sname) {
                if data.len() <= 32 * 1024 * 1024 {
                    carve_embedded_images(&data, sname.trim_start_matches('/'), &mut res.embedded_images);
                }
            }
        }
    }

    let clean = clean_control_chars(&extracted);
    if !clean.is_empty() {
        if let Some(ht) = build_head_tail_segment(&clean) {
            res.segments.push(ht);
        }
        res.segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "OLE2 二进制文档正文 (原生回退)".into(),
            text: clean,
        });
    } else {
        res.warnings
            .push("OLE2 文档未抽取到有效文本（可能为纯扫描/复杂旧格式，建议部署 libs/x2t/x2t.exe）".into());
    }

    res
}

pub fn parse_legacy_ppt_or_dps(bytes: &[u8]) -> OfficeParseResult {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };

    let Ok(mut comp) = cfb::CompoundFile::open(Cursor::new(bytes)) else {
        res.warnings.push("invalid OLE2 PPT/DPS file".into());
        return res;
    };

    let mut ppt_stream = Vec::new();
    if let Ok(mut s) = comp.open_stream("PowerPoint Document") {
        let _ = s.read_to_end(&mut ppt_stream);
    }
    let mut pic_stream = Vec::new();
    if let Ok(mut s) = comp.open_stream("Pictures") {
        let _ = s.read_to_end(&mut pic_stream);
    }

    let mut slide_texts = Vec::new();
    if !ppt_stream.is_empty() {
        walk_ppt_records(&ppt_stream, 0, &mut slide_texts);
    }
    if !pic_stream.is_empty() {
        carve_embedded_images(&pic_stream, "Pictures", &mut res.embedded_images);
    }

    let joined = clean_control_chars(&slide_texts.join("\n"));
    if !joined.is_empty() {
        if let Some(ht) = build_head_tail_segment(&joined) {
            res.segments.push(ht);
        }
        res.segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "PPT/DPS 二进制幻灯片正文".into(),
            text: joined,
        });
    } else {
        res.warnings
            .push("PPT/DPS 未抽取到有效文本（建议部署 libs/x2t/x2t.exe）".into());
    }

    res
}

fn parse_word_piece_table(
    wd: &[u8],
    comp: &mut cfb::CompoundFile<Cursor<&[u8]>>,
) -> Option<String> {
    if wd.len() < 0x1B0 {
        return None;
    }
    let flags = u16::from_le_bytes([wd[0x0A], wd[0x0B]]);
    if (flags & 0x0100) != 0 {
        return None; // Encrypted
    }
    let table_name = if (flags & 0x0200) != 0 {
        "1Table"
    } else {
        "0Table"
    };

    // Navigate FIB sections dynamically: FibBase = 32 bytes
    let csw = u16::from_le_bytes([wd[32], wd[33]]) as usize;
    let pos_cslw = 34 + csw * 2;
    if pos_cslw + 2 > wd.len() {
        return None;
    }
    let cslw = u16::from_le_bytes([wd[pos_cslw], wd[pos_cslw + 1]]) as usize;
    let pos_cbrg = pos_cslw + 2 + cslw * 4;
    if pos_cbrg + 2 > wd.len() {
        return None;
    }
    let cb_rg = u16::from_le_bytes([wd[pos_cbrg], wd[pos_cbrg + 1]]) as usize;
    // FibRgFcLcb97 index 33 is (fcClx, lcbClx)
    let clx_entry_off = pos_cbrg + 2 + 33 * 8;
    if cb_rg <= 33 || clx_entry_off + 8 > wd.len() {
        return None;
    }
    let fc_clx = u32::from_le_bytes(wd[clx_entry_off..clx_entry_off + 4].try_into().ok()?) as usize;
    let lcb_clx = u32::from_le_bytes(wd[clx_entry_off + 4..clx_entry_off + 8].try_into().ok()?) as usize;
    if lcb_clx == 0 {
        return None;
    }

    let mut tbl_stream = comp.open_stream(table_name).ok()?;
    let mut tbl = Vec::new();
    tbl_stream.read_to_end(&mut tbl).ok()?;
    if fc_clx + lcb_clx > tbl.len() {
        return None;
    }
    let clx = &tbl[fc_clx..fc_clx + lcb_clx];

    let mut p = 0usize;
    while p < clx.len() {
        let clxt = clx[p];
        p += 1;
        if clxt == 1 {
            if p + 2 > clx.len() {
                break;
            }
            let cb = u16::from_le_bytes([clx[p], clx[p + 1]]) as usize;
            p = p.saturating_add(2 + cb);
        } else if clxt == 2 {
            if p + 4 > clx.len() {
                break;
            }
            let lcb = u32::from_le_bytes(clx[p..p + 4].try_into().ok()?) as usize;
            p += 4;
            if p + lcb > clx.len() || lcb < 4 {
                break;
            }
            let pcdt = &clx[p..p + lcb];
            let n_pieces = (lcb - 4) / 12;
            let cps_bytes = (n_pieces + 1) * 4;
            if cps_bytes + n_pieces * 8 > pcdt.len() {
                break;
            }
            let mut out = String::new();
            for i in 0..n_pieces {
                let cp_start = u32::from_le_bytes(pcdt[i * 4..i * 4 + 4].try_into().ok()?) as usize;
                let cp_end =
                    u32::from_le_bytes(pcdt[(i + 1) * 4..(i + 1) * 4 + 4].try_into().ok()?) as usize;
                if cp_end <= cp_start {
                    continue;
                }
                let char_cnt = cp_end - cp_start;
                let pcd_off = cps_bytes + i * 8;
                let fc = u32::from_le_bytes(pcdt[pcd_off + 2..pcd_off + 6].try_into().ok()?);
                if (fc & 0x4000_0000) != 0 {
                    // Compressed 8-bit ANSI
                    let byte_off = ((fc & !0x4000_0000) / 2) as usize;
                    let end = byte_off.saturating_add(char_cnt).min(wd.len());
                    if byte_off < end {
                        let (s, _, _) = encoding_rs::WINDOWS_1252.decode(&wd[byte_off..end]);
                        out.push_str(&s);
                    }
                } else {
                    // UTF-16LE
                    let byte_off = fc as usize;
                    let end = byte_off.saturating_add(char_cnt * 2).min(wd.len());
                    if byte_off + 1 < end {
                        let units: Vec<u16> = wd[byte_off..end]
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        out.push_str(&String::from_utf16_lossy(&units));
                    }
                }
            }
            return Some(out);
        } else {
            break;
        }
    }
    None
}

fn extract_fib_or_runs(wd: &[u8]) -> String {
    if wd.len() >= 0x20 {
        let fc_min = u32::from_le_bytes([wd[0x18], wd[0x19], wd[0x1A], wd[0x1B]]) as usize;
        let fc_mac = u32::from_le_bytes([wd[0x1C], wd[0x1D], wd[0x1E], wd[0x1F]]) as usize;
        if fc_min < fc_mac && fc_mac <= wd.len() && fc_mac - fc_min >= 4 {
            let slice = &wd[fc_min..fc_mac];
            let txt = extract_utf16_and_gbk_runs(slice);
            if !txt.trim().is_empty() {
                return txt;
            }
        }
    }
    extract_utf16_and_gbk_runs(wd)
}

fn walk_ppt_records(buf: &[u8], depth: u32, out: &mut Vec<String>) {
    if depth > 16 {
        return;
    }
    let mut pos = 0usize;
    while pos + 8 <= buf.len() {
        let ver_inst = u16::from_le_bytes([buf[pos], buf[pos + 1]]);
        let rec_type = u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]);
        let rec_len = u32::from_le_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]) as usize;
        pos += 8;
        if pos.saturating_add(rec_len) > buf.len() {
            break;
        }
        let payload = &buf[pos..pos + rec_len];
        if (ver_inst & 0x000F) == 0x000F {
            walk_ppt_records(payload, depth + 1, out);
        } else if rec_type == 0x0FA0 || rec_type == 0x0FBA {
            // TextCharsAtom / CString (UTF-16LE)
            let units: Vec<u16> = payload
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16_lossy(&units).replace('\r', "\n");
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
        } else if rec_type == 0x0FA8 {
            // TextBytesAtom (ANSI / CP936)
            let (s, _) = decode_text_auto(payload);
            let s = s.replace('\r', "\n");
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
        }
        pos += rec_len;
    }
}

/// Carve embedded PNG and JPEG blobs from OLE2 binary streams (`Pictures`, `Data`, `WordDocument`).
pub fn carve_embedded_images(data: &[u8], prefix: &str, out: &mut Vec<(String, Vec<u8>)>) {
    // PNG signature: 89 50 4E 47 0D 0A 1A 0A ... IEND AE 42 60 82
    const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
    const PNG_END: &[u8] = b"IEND\xAE\x42\x60\x82";
    let mut pos = 0usize;
    let mut idx = 0usize;
    while let Some(off) = find_bytes(&data[pos..], PNG_SIG) {
        let start = pos + off;
        if let Some(end_off) = find_bytes(&data[start..], PNG_END) {
            let end = start + end_off + PNG_END.len();
            if end - start <= 16 * 1024 * 1024 {
                idx += 1;
                out.push((format!("{prefix}_img_{idx}.png"), data[start..end].to_vec()));
            }
            pos = end;
        } else {
            break;
        }
    }

    // JPEG signature: FF D8 FF ... FF D9
    pos = 0;
    while let Some(off) = find_bytes(&data[pos..], b"\xFF\xD8\xFF") {
        let start = pos + off;
        if let Some(end_off) = find_bytes(&data[start + 3..data.len().min(start + 16 * 1024 * 1024)], b"\xFF\xD9") {
            let end = start + 3 + end_off + 2;
            if end - start >= 128 {
                idx += 1;
                out.push((format!("{prefix}_img_{idx}.jpg"), data[start..end].to_vec()));
            }
            pos = end;
        } else {
            break;
        }
    }
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn extract_utf16_and_gbk_runs(bytes: &[u8]) -> String {
    let mut runs = Vec::new();
    // Try UTF-16LE CJK/ASCII runs (at least 4 chars)
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        let mut units = Vec::new();
        let mut j = i;
        while j + 1 < bytes.len() {
            let u = u16::from_le_bytes([bytes[j], bytes[j + 1]]);
            if (0x0020..=0x007E).contains(&u)
                || (0x4E00..=0x9FFF).contains(&u)
                || (0x3000..=0x303F).contains(&u)
                || (0xFF00..=0xFFEF).contains(&u)
                || matches!(u, 0x0009 | 0x000A | 0x000D)
            {
                units.push(u);
                j += 2;
            } else {
                break;
            }
        }
        if units.len() >= 4 {
            let s = String::from_utf16_lossy(&units);
            if s.trim().chars().count() >= 3 {
                runs.push(s.trim().to_string());
            }
            i = j;
        } else {
            i += 2;
        }
    }
    if !runs.is_empty() {
        return runs.join("\n");
    }

    // Fallback: printable UTF-8/GB18030 runs
    let (decoded, _, _) = encoding_rs::GB18030.decode(bytes);
    decoded
        .lines()
        .map(|l| l.trim())
        .filter(|l| l.chars().count() >= 4)
        .collect::<Vec<_>>()
        .join("\n")
}

fn clean_control_chars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\r' | '\x07' | '\x0b' => out.push('\n'),
            '\t' | '\n' => out.push(ch),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}
