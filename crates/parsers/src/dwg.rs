use crate::office::OfficeParseResult;
use crate::text::build_head_tail_segment;
use acadrust::entities::{EntityType, Ole2Frame};
use acadrust::io::dwg::{DwgReadOptions, DwgReader};
use acadrust::io::dxf::code_page::encoding_from_code_page;
use acadrust::objects::ObjectType;
use acadrust::types::DxfVersion;
use acadrust::CadDocument;
use deepdoc_protocol::{SegmentScope, TextSegment};
use std::collections::HashSet;
use std::io::Cursor;

/// Parse a DWG binary buffer directly into structured segments and embedded assets
/// using pure-Rust `acadrust`, without spawning external processes or temp DXF files.
pub fn parse_dwg_document(bytes: &[u8]) -> (OfficeParseResult, Vec<(String, String)>) {
    let mut res = OfficeParseResult {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        embedded_files: Vec::new(),
        warnings: Vec::new(),
    };
    let mut metadata = Vec::new();

    let header_ver = if bytes.len() >= 6 && bytes.starts_with(b"AC10") {
        String::from_utf8_lossy(&bytes[..6]).to_string()
    } else {
        "UNKNOWN".to_string()
    };
    let release = dwg_release_label(&header_ver);
    metadata.push(("dwg_version".into(), header_ver.clone()));
    metadata.push(("dwg_release".into(), release.into()));

    let read_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        read_dwg_with_failsafe(bytes)
    }));

    let (doc, dwg_warnings) = match read_result {
        Ok(Ok((doc, warnings))) => (doc, warnings),
        Ok(Err(err)) => {
            metadata.push(("dwg_engine".into(), "acadrust-carve".into()));
            res.warnings.push(format!(
                "DWG 原生解析未能识别完整实体 ({err})，已执行底层可见文本雕刻"
            ));
            res.segments.push(TextSegment {
                scope: SegmentScope::Metadata,
                location_label: "DWG 文件头".into(),
                text: format!("{release} ({header_ver})"),
            });
            let carved = carve_dwg_strings(bytes);
            if !carved.is_empty() {
                if let Some(ht) = build_head_tail_segment(&carved) {
                    res.segments.push(ht);
                }
                res.segments.push(TextSegment {
                    scope: SegmentScope::Body,
                    location_label: "DWG 可见文本雕刻".into(),
                    text: carved,
                });
            }
            return (res, metadata);
        }
        Err(_) => {
            metadata.push(("dwg_engine".into(), "acadrust-carve".into()));
            res.warnings
                .push("DWG 二进制结构异常（已安全隔离），已回退底层可见文本雕刻".into());
            res.segments.push(TextSegment {
                scope: SegmentScope::Metadata,
                location_label: "DWG 文件头".into(),
                text: format!("{release} ({header_ver})"),
            });
            let carved = carve_dwg_strings(bytes);
            if !carved.is_empty() {
                if let Some(ht) = build_head_tail_segment(&carved) {
                    res.segments.push(ht);
                }
                res.segments.push(TextSegment {
                    scope: SegmentScope::Body,
                    location_label: "DWG 可见文本雕刻".into(),
                    text: carved,
                });
            }
            return (res, metadata);
        }
    };

    metadata.push(("dwg_engine".into(), "acadrust".into()));
    metadata.push(("dwg_entity_count".into(), doc.entity_count().to_string()));
    metadata.push(("dwg_code_page".into(), doc.header.code_page.clone()));
    if !dwg_warnings.is_empty() {
        res.warnings.extend(
            dwg_warnings
                .into_iter()
                .filter(|w| should_surface_dwg_notification(w))
                .take(8),
        );
    }

    let mut meta_lines = vec![format!(
        "版本: {release} ({header_ver}), 代码页: {}, 实体数: {}",
        doc.header.code_page,
        doc.entity_count()
    )];
    let layers: Vec<String> = doc
        .layers
        .iter()
        .map(|l| l.name.trim().to_string())
        .filter(|name| !name.is_empty() && name != "0")
        .collect();
    if !layers.is_empty() {
        meta_lines.push(format!("图层: {}", layers.join(", ")));
    }

    let mut block_notes = Vec::new();
    for br in doc.block_records.iter() {
        let name = br.name.trim();
        let desc = br.description.trim();
        let xref = br.xref_path.trim();
        if !name.is_empty() && !name.starts_with('*') {
            if !desc.is_empty() {
                block_notes.push(format!("{name} ({desc})"));
            } else {
                block_notes.push(name.to_string());
            }
        }
        if !xref.is_empty() {
            block_notes.push(format!("XREF:{xref}"));
        }
    }
    if !block_notes.is_empty() {
        block_notes.truncate(200);
        meta_lines.push(format!("图块与外参: {}", block_notes.join(", ")));
    }

    let mut image_refs = Vec::new();
    let mut table_lines = Vec::new();
    let mut seen_table = HashSet::new();

    for object in doc.objects.values() {
        match object {
            ObjectType::ImageDefinition(img) if !img.file_name.trim().is_empty() => {
                image_refs.push(img.file_name.trim().to_string());
            }
            ObjectType::Unknown {
                type_name,
                raw_dwg_data: Some(raw),
                ..
            } if type_name.contains("105")
                || type_name.to_ascii_uppercase().contains("TABLECONTENT") =>
            {
                let cells: Vec<String> = extract_dwg_variable_text_spans(raw)
                    .into_iter()
                    .map(|span| decode_acad_text(&span.text, true))
                    .filter(|t| is_probable_table_cell_text(t) && seen_table.insert(t.clone()))
                    .collect();
                if cells.len() >= 2 {
                    table_lines.push(cells.join(" | "));
                }
            }
            _ => {}
        }
    }
    if !image_refs.is_empty() {
        meta_lines.push(format!("关联光栅图像: {}", image_refs.join(", ")));
    }

    let mut body_lines = Vec::new();
    let mut seen_body = HashSet::new();
    let mut ole_idx = 0usize;

    let mut push_body = |raw: &str, strip_mtext: bool, prefix: Option<&str>| {
        let decoded = decode_acad_text(raw, strip_mtext);
        let trimmed = decoded.trim();
        if trimmed.is_empty() || trimmed == "<>" {
            return;
        }
        let formatted = match prefix {
            Some(p) if !p.is_empty() && p != trimmed => format!("{p}: {trimmed}"),
            _ => trimmed.to_string(),
        };
        if seen_body.insert(formatted.clone()) {
            body_lines.push(formatted);
        }
    };

    for entity in doc.entities() {
        match entity {
            EntityType::Text(t) => push_body(&t.value, false, None),
            EntityType::MText(m) => push_body(&m.value, true, None),
            EntityType::AttributeEntity(attr) => {
                let tag = attr.tag.trim();
                let prefix = (!tag.is_empty()).then_some(tag);
                push_body(&attr.value, false, prefix);
            }
            EntityType::AttributeDefinition(attr) => {
                let tag = attr.tag.trim();
                let prefix = (!tag.is_empty()).then_some(tag);
                push_body(&attr.default_value, false, prefix);
                if !attr.prompt.trim().is_empty() && attr.prompt.trim() != attr.default_value.trim() {
                    push_body(&attr.prompt, false, None);
                }
            }
            EntityType::Insert(ins) => {
                for attr in &ins.attributes {
                    let tag = attr.tag.trim();
                    let prefix = (!tag.is_empty()).then_some(tag);
                    push_body(&attr.value, false, prefix);
                }
            }
            EntityType::Dimension(dim) => {
                let base = dim.base();
                if let Some(user_text) = &base.user_text {
                    push_body(user_text, true, None);
                } else {
                    push_body(&base.text, true, None);
                }
            }
            EntityType::MultiLeader(ml) => {
                if let Some(text) = ml.text() {
                    push_body(text, true, None);
                }
            }
            EntityType::Tolerance(tol) => push_body(&tol.text, true, None),
            EntityType::Table(table) => {
                let mut structured_rows = 0usize;
                for row in 0..table.row_count() {
                    let mut row_cells = Vec::new();
                    for col in 0..table.column_count() {
                        if let Some(raw_cell) = table.cell_text(row, col) {
                            let cleaned = decode_acad_text(raw_cell, true);
                            let t = cleaned.trim();
                            if !t.is_empty() {
                                seen_table.insert(t.to_string());
                                row_cells.push(t.to_string());
                            }
                        }
                    }
                    if !row_cells.is_empty() {
                        structured_rows += 1;
                        table_lines.push(row_cells.join(" | "));
                    }
                }
                if structured_rows == 0 {
                    if let Some(raw) = &table.raw_dwg_data {
                        let raw_cells: Vec<String> = extract_table_cell_prefix_spans(
                            raw,
                            table.dwg_handle_bits,
                            doc.version,
                            &doc.header.code_page,
                        )
                        .into_iter()
                        .map(|s| decode_acad_text(&s.text, true))
                        .filter(|t| !t.is_empty() && seen_table.insert(t.clone()))
                        .collect();
                        if !raw_cells.is_empty() {
                            table_lines.push(raw_cells.join(" | "));
                        }
                    }
                }
            }
            EntityType::Ole2Frame(ole) => {
                if !ole.source_application.trim().is_empty() {
                    meta_lines.push(format!("内嵌OLE对象: {}", ole.source_application.trim()));
                }
                ole_idx += 1;
                extract_ole2_frame_payload(
                    ole,
                    ole_idx,
                    &mut res.embedded_images,
                    &mut res.embedded_files,
                );
            }
            _ => {}
        }
    }

    res.segments.push(TextSegment {
        scope: SegmentScope::Metadata,
        location_label: "DWG 图纸信息与图层".into(),
        text: meta_lines.join("\n"),
    });

    if !table_lines.is_empty() {
        res.segments.push(TextSegment {
            scope: SegmentScope::Table,
            location_label: "DWG 表格数据".into(),
            text: table_lines.join("\n"),
        });
    }

    if body_lines.is_empty() && table_lines.is_empty() {
        // Rare DWG with custom proxy text or unparsed blocks: run binary carving as a supplement.
        let carved = carve_dwg_strings(bytes);
        if !carved.is_empty() {
            if let Some(ht) = build_head_tail_segment(&carved) {
                res.segments.push(ht);
            }
            res.segments.push(TextSegment {
                scope: SegmentScope::Body,
                location_label: "DWG 补充文本雕刻".into(),
                text: carved,
            });
        }
    } else if !body_lines.is_empty() {
        let body_text = body_lines.join("\n");
        if let Some(ht) = build_head_tail_segment(&body_text) {
            res.segments.push(ht);
        }
        res.segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "DWG 图纸文字与标注".into(),
            text: body_text,
        });
    }

    (res, metadata)
}

fn read_dwg_with_failsafe(bytes: &[u8]) -> Result<(CadDocument, Vec<String>), String> {
    let mut reader = DwgReader::from_stream(Cursor::new(bytes));
    match reader.read() {
        Ok(doc) => {
            let mut warnings: Vec<String> =
                doc.notifications.iter().map(|n| n.message.clone()).collect();
            if doc.entity_count() == 0 && bytes.len() > 1_000_000 {
                let mut fs_reader =
                    DwgReader::from_stream_with_options(Cursor::new(bytes), DwgReadOptions::failsafe());
                if let Ok(fs_doc) = fs_reader.read() {
                    if fs_doc.entity_count() > 0 {
                        warnings.extend(fs_doc.notifications.iter().map(|n| n.message.clone()));
                        return Ok((fs_doc, warnings));
                    }
                }
            }
            Ok((doc, warnings))
        }
        Err(first_err) => {
            let mut fs_reader =
                DwgReader::from_stream_with_options(Cursor::new(bytes), DwgReadOptions::failsafe());
            match fs_reader.read() {
                Ok(fs_doc) => {
                    let mut warnings = vec![format!("DWG 标准读取回退 failsafe ({first_err})")];
                    warnings.extend(fs_doc.notifications.iter().map(|n| n.message.clone()));
                    Ok((fs_doc, warnings))
                }
                Err(second_err) => Err(format!("{first_err}; failsafe: {second_err}")),
            }
        }
    }
}

fn should_surface_dwg_notification(msg: &str) -> bool {
    !(msg.starts_with("Reading DWG file version:")
        || msg.starts_with("AC18 ")
        || msg.starts_with("AC21 ")
        || msg.starts_with("PM_")
        || msg.starts_with("Recovery:"))
}

fn dwg_release_label(ver: &str) -> &'static str {
    match ver {
        "AC1032" => "AutoCAD 2018-2024",
        "AC1027" => "AutoCAD 2013-2017",
        "AC1024" => "AutoCAD 2010-2012",
        "AC1021" => "AutoCAD 2007-2009",
        "AC1018" => "AutoCAD 2004-2006",
        "AC1015" => "AutoCAD 2000-2002",
        "AC1014" => "AutoCAD R14",
        "AC1012" => "AutoCAD R13",
        _ => "AutoCAD DWG",
    }
}

/// Decode AutoCAD Unicode escapes (`\U+XXXX`), SHX Cyrillic (`§...`), `%%` symbols,
/// and optionally strip MText formatting directives such as `{\fSimSun;文本}` and `\P`.
pub(crate) fn decode_acad_text(input: &str, strip_mtext: bool) -> String {
    let unicode_decoded = decode_acad_unicode_and_shx(input);
    let symbols_decoded = decode_acad_percent_codes(&unicode_decoded);
    if strip_mtext {
        strip_mtext_codes(&symbols_decoded)
    } else {
        symbols_decoded.replace("\r\n", "\n").trim().to_string()
    }
}

fn decode_acad_unicode_and_shx(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut output = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        if i + 7 <= chars.len()
            && chars[i] == '\\'
            && (chars[i + 1] == 'U' || chars[i + 1] == 'u')
            && chars[i + 2] == '+'
            && chars[i + 3..i + 7].iter().all(|c| c.is_ascii_hexdigit())
        {
            let hex: String = chars[i + 3..i + 7].iter().collect();
            if let Ok(value) = u32::from_str_radix(&hex, 16) {
                if let Some(decoded) = char::from_u32(value) {
                    output.push(decoded);
                    i += 7;
                    continue;
                }
            }
        }
        if chars[i] == '§' && i + 1 < chars.len() {
            if let Some(decoded) = shx_cyrillic_char(chars[i + 1]) {
                output.push(decoded);
                i += 2;
                continue;
            }
        }
        output.push(chars[i]);
        i += 1;
    }
    output
}

fn shx_cyrillic_char(ch: char) -> Option<char> {
    let code = ch as u32;
    if code == 0x00A1 {
        return Some('Ё');
    }
    if (0x00A2..=0x00C1).contains(&code) {
        return char::from_u32('А' as u32 + (code - 0x00A2));
    }
    if (0x00D1..=0x00D6).contains(&code) {
        return char::from_u32('а' as u32 + (code - 0x00D1));
    }
    if code == 0x00D7 {
        return Some('ё');
    }
    if (0x00D8..=0x00F1).contains(&code) {
        return char::from_u32('ж' as u32 + (code - 0x00D8));
    }
    None
}

fn decode_acad_percent_codes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if i + 2 < chars.len() && chars[i] == '%' && chars[i + 1] == '%' {
            let code = chars[i + 2];
            match code {
                'd' | 'D' => {
                    out.push('°');
                    i += 3;
                    continue;
                }
                'p' | 'P' => {
                    out.push('±');
                    i += 3;
                    continue;
                }
                'c' | 'C' => {
                    out.push('⌀');
                    i += 3;
                    continue;
                }
                'u' | 'U' | 'o' | 'O' => {
                    i += 3;
                    continue;
                }
                '%' => {
                    out.push('%');
                    i += 3;
                    continue;
                }
                _ => {}
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn strip_mtext_codes(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        match chars[i] {
            '{' | '}' => {
                i += 1;
            }
            '\\' if i + 1 < chars.len() => {
                let next = chars[i + 1];
                match next {
                    '\\' | '{' | '}' => {
                        out.push(next);
                        i += 2;
                    }
                    '~' => {
                        out.push(' ');
                        i += 2;
                    }
                    'P' => {
                        out.push('\n');
                        i += 2;
                    }
                    'L' | 'l' | 'O' | 'o' | 'K' | 'k' => {
                        i += 2;
                    }
                    'S' | 's' => {
                        // Stacked text `\Snum^den;` -> `num/den`
                        i += 2;
                        while i < chars.len() && chars[i] != ';' {
                            let c = chars[i];
                            out.push(if c == '^' || c == '#' { '/' } else { c });
                            i += 1;
                        }
                        if i < chars.len() && chars[i] == ';' {
                            i += 1;
                        }
                    }
                    'f' | 'F' | 'C' | 'c' | 'H' | 'h' | 'W' | 'w' | 'T' | 'Q' | 'A' | 'p' => {
                        // Parameterized inline formatting directive ending at `;`
                        let mut j = i + 2;
                        while j < chars.len() && chars[j] != ';' && chars[j] != '\n' {
                            j += 1;
                        }
                        if j < chars.len() && chars[j] == ';' {
                            i = j + 1;
                        } else {
                            i += 2;
                        }
                    }
                    _ => {
                        out.push(chars[i]);
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn extract_ole2_frame_payload(
    ole: &Ole2Frame,
    idx: usize,
    embedded_images: &mut Vec<(String, Vec<u8>)>,
    embedded_files: &mut Vec<(String, Vec<u8>)>,
) {
    let data = &ole.binary_data;
    if data.len() < 16 || data.len() > 16 * 1024 * 1024 {
        return;
    }
    let scan_limit = data.len().min(512);
    if let Some(pos) = find_magic(&data[..scan_limit], b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        let app = ole.source_application.to_ascii_lowercase();
        let ext = if app.contains("excel") || app.contains("sheet") {
            "xls"
        } else if app.contains("word") {
            "doc"
        } else if app.contains("powerpoint") {
            "ppt"
        } else {
            "bin"
        };
        embedded_files.push((format!("dwg_ole_{idx}.{ext}"), data[pos..].to_vec()));
        return;
    }
    if let Some(pos) = find_magic(&data[..scan_limit], b"PK\x03\x04") {
        let app = ole.source_application.to_ascii_lowercase();
        let ext = if app.contains("excel") || app.contains("sheet") {
            "xlsx"
        } else if app.contains("word") {
            "docx"
        } else {
            "zip"
        };
        embedded_files.push((format!("dwg_ole_{idx}.{ext}"), data[pos..].to_vec()));
        return;
    }
    if let Some(pos) = find_magic(&data[..scan_limit], b"\x89PNG\r\n\x1A\n") {
        embedded_images.push((format!("dwg_ole_{idx}.png"), data[pos..].to_vec()));
        return;
    }
    if let Some(pos) = find_magic(&data[..scan_limit], b"\xFF\xD8\xFF") {
        embedded_images.push((format!("dwg_ole_{idx}.jpg"), data[pos..].to_vec()));
    }
}

fn find_magic(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[derive(Debug, Clone)]
struct RawTextSpan {
    text: String,
    tv_bit_start: usize,
    tv_bit_end: usize,
}

#[derive(Debug, Clone, Copy)]
struct ThreeStreamBounds {
    text_start: usize,
    text_size: usize,
}

impl ThreeStreamBounds {
    fn parse(raw: &[u8], handle_bits: i64) -> Result<Self, String> {
        let total_bits = raw.len().saturating_mul(8);
        if handle_bits <= 0 {
            return Self::parse_r2007(raw, total_bits);
        }

        let handle_bits = handle_bits as usize;
        if handle_bits >= total_bits {
            return Err("handle_bits out of bounds".into());
        }

        let handle_start = total_bits - handle_bits;
        if handle_start == 0 {
            return Err("handle_start out of bounds".into());
        }

        Self::parse_from_handle_start(raw, handle_start)
    }

    fn parse_r2007(raw: &[u8], total_bits: usize) -> Result<Self, String> {
        let mut cursor = BitCursor::new(raw, 0);
        let _type_code = cursor
            .read_bit_short()
            .ok_or_else(|| "missing R2007 object type".to_string())?;
        let handle_start = cursor
            .read_raw_long()
            .ok_or_else(|| "missing R2007 handle stream start".to_string())?;
        if handle_start <= 0 {
            return Err("invalid R2007 handle stream start".into());
        }

        let handle_start = handle_start as usize;
        if handle_start >= total_bits {
            return Err("R2007 handle stream start out of bounds".into());
        }

        Self::parse_from_handle_start(raw, handle_start)
    }

    fn parse_from_handle_start(raw: &[u8], handle_start: usize) -> Result<Self, String> {
        let flag_pos = handle_start - 1;
        if !read_bit_at(raw, flag_pos).unwrap_or(false) {
            return Err("no text stream".into());
        }

        let mut length = flag_pos
            .checked_sub(16)
            .ok_or_else(|| "text-size flag out of bounds".to_string())?;
        let mut str_size = read_raw_ushort_at(raw, length)
            .ok_or_else(|| "invalid text-size flag".to_string())? as usize;

        if (str_size & 0x8000) != 0 {
            length = length
                .checked_sub(16)
                .ok_or_else(|| "extended text-size flag out of bounds".to_string())?;
            str_size &= 0x7FFF;
            let hi_size = read_raw_ushort_at(raw, length)
                .ok_or_else(|| "invalid extended text-size flag".to_string())?
                as usize;
            str_size += hi_size << 15;
        }

        let text_start = length
            .checked_sub(str_size)
            .ok_or_else(|| "text stream start out of bounds".to_string())?;
        if text_start > length || length > flag_pos {
            return Err("invalid text stream bounds".into());
        }

        Ok(Self {
            text_start,
            text_size: str_size,
        })
    }
}

fn extract_table_cell_prefix_spans(
    raw: &[u8],
    handle_bits: i64,
    version: DxfVersion,
    code_page: &str,
) -> Vec<RawTextSpan> {
    if version < DxfVersion::AC1021 {
        return extract_legacy_table_cell_spans(raw, code_page);
    }

    let mut cells = Vec::new();
    let mut seen = HashSet::new();
    let mut started = false;
    let mut misses_after_started = 0usize;

    let spans = extract_table_text_stream_spans(raw, handle_bits)
        .unwrap_or_else(|_| extract_dwg_variable_text_spans(raw));

    for span in spans {
        let text = span.text.trim_matches(char::from(0)).trim().to_string();
        if !is_probable_table_cell_text(&text) {
            if started {
                misses_after_started += 1;
                if misses_after_started >= 2 {
                    break;
                }
            }
            continue;
        }
        started = true;
        misses_after_started = 0;
        if seen.insert(text.clone()) {
            cells.push(RawTextSpan {
                text,
                tv_bit_start: span.tv_bit_start,
                tv_bit_end: span.tv_bit_end,
            });
        }
    }

    cells
}

fn extract_table_text_stream_spans(raw: &[u8], handle_bits: i64) -> Result<Vec<RawTextSpan>, String> {
    let bounds = ThreeStreamBounds::parse(raw, handle_bits)?;
    let text_end = bounds.text_start.saturating_add(bounds.text_size);
    let mut spans = Vec::new();
    let mut cursor = BitCursor::new(raw, bounds.text_start);

    while cursor.bit_pos < text_end {
        let tv_bit_start = cursor.bit_pos;
        let Some(char_count) = cursor.read_bit_short() else {
            break;
        };
        let char_count = char_count.max(0) as usize;
        if char_count == 0 {
            continue;
        }
        if char_count > 2048 || cursor.bit_pos + char_count.saturating_mul(16) > text_end {
            break;
        }

        let mut units = Vec::with_capacity(char_count);
        for _ in 0..char_count {
            let Some(lo) = cursor.read_byte() else {
                break;
            };
            let Some(hi) = cursor.read_byte() else {
                break;
            };
            units.push(u16::from_le_bytes([lo, hi]));
        }
        if units.len() != char_count {
            break;
        }
        if let Ok(text) = String::from_utf16(&units) {
            let text = text.trim_matches(char::from(0)).trim().to_string();
            spans.push(RawTextSpan {
                text,
                tv_bit_start,
                tv_bit_end: cursor.bit_pos,
            });
        }
    }

    Ok(spans)
}

fn extract_dwg_variable_text_spans(raw: &[u8]) -> Vec<RawTextSpan> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    // Bound raw bit-scanning on unexpectedly huge table blobs to avoid O(N) bit-shift stalls.
    let raw = &raw[..raw.len().min(64 * 1024)];
    let bit_len = raw.len().saturating_mul(8);

    for bit_offset in 0..bit_len.saturating_sub(18) {
        let tv_bit_start = bit_offset;
        let mut cursor = BitCursor::new(raw, bit_offset);
        let Some(char_count) = cursor.read_bit_short() else {
            continue;
        };
        let char_count = char_count.max(0) as usize;
        if !(2..=120).contains(&char_count) {
            continue;
        }
        if cursor.remaining_bits() < char_count.saturating_mul(16) {
            continue;
        }

        let mut units = Vec::with_capacity(char_count);
        for i in 0..char_count {
            let Some(lo) = cursor.read_byte() else {
                break;
            };
            let Some(hi) = cursor.read_byte() else {
                break;
            };
            let unit = u16::from_le_bytes([lo, hi]);
            if !is_raw_text_unit(unit) {
                break;
            }
            units.push(unit);
            if i == 0 && unit == 0 {
                break;
            }
        }
        if units.len() != char_count {
            continue;
        }
        if let Ok(text) = String::from_utf16(&units) {
            let text = text.trim_matches(char::from(0)).trim().to_string();
            if is_probable_table_cell_text(&text) && seen.insert(text.clone()) {
                out.push(RawTextSpan {
                    text,
                    tv_bit_start,
                    tv_bit_end: cursor.bit_pos,
                });
            }
        }
    }

    out
}

fn extract_legacy_table_cell_spans(raw: &[u8], code_page: &str) -> Vec<RawTextSpan> {
    let raw = &raw[..raw.len().min(64 * 1024)];
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let bit_len = raw.len().saturating_mul(8);
    let encoding = encoding_from_code_page(code_page).unwrap_or(encoding_rs::GB18030);

    for bit_offset in 0..bit_len.saturating_sub(10) {
        let tv_bit_start = bit_offset;
        let mut cursor = BitCursor::new(raw, bit_offset);
        let Some(byte_count) = cursor.read_bit_short() else {
            continue;
        };
        let byte_count = byte_count.max(0) as usize;
        if !(2..=120).contains(&byte_count) || cursor.remaining_bits() < byte_count * 8 {
            continue;
        }

        let mut buf = Vec::with_capacity(byte_count);
        for _ in 0..byte_count {
            let Some(b) = cursor.read_byte() else {
                break;
            };
            if b < 0x20 {
                break;
            }
            buf.push(b);
        }
        if buf.len() != byte_count {
            continue;
        }
        let (decoded, _, _) = encoding.decode(&buf);
        let text = decoded.trim_matches(char::from(0)).trim().to_string();
        if is_probable_table_cell_text(&text) && seen.insert(text.clone()) {
            out.push(RawTextSpan {
                text,
                tv_bit_start,
                tv_bit_end: cursor.bit_pos,
            });
        }
        if out.len() >= 12 {
            break;
        }
    }

    out
}

struct BitCursor<'a> {
    raw: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitCursor<'a> {
    fn new(raw: &'a [u8], bit_pos: usize) -> Self {
        Self { raw, bit_pos }
    }

    fn remaining_bits(&self) -> usize {
        self.raw.len().saturating_mul(8).saturating_sub(self.bit_pos)
    }

    fn read_bit(&mut self) -> Option<bool> {
        let byte = *self.raw.get(self.bit_pos / 8)?;
        let bit = (byte >> (7 - (self.bit_pos % 8))) & 1;
        self.bit_pos += 1;
        Some(bit != 0)
    }

    fn read_2bits(&mut self) -> Option<u8> {
        let high = self.read_bit()? as u8;
        let low = self.read_bit()? as u8;
        Some((high << 1) | low)
    }

    fn read_byte(&mut self) -> Option<u8> {
        let mut value = 0u8;
        for _ in 0..8 {
            value = (value << 1) | self.read_bit()? as u8;
        }
        Some(value)
    }

    fn read_raw_short(&mut self) -> Option<i16> {
        let b0 = self.read_byte()? as u16;
        let b1 = self.read_byte()? as u16;
        Some((b0 | (b1 << 8)) as i16)
    }

    fn read_raw_long(&mut self) -> Option<i32> {
        let b0 = self.read_byte()? as u32;
        let b1 = self.read_byte()? as u32;
        let b2 = self.read_byte()? as u32;
        let b3 = self.read_byte()? as u32;
        Some((b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) as i32)
    }

    fn read_bit_short(&mut self) -> Option<i16> {
        match self.read_2bits()? {
            0 => self.read_raw_short(),
            1 => Some(self.read_byte()? as i16),
            2 => Some(0),
            3 => Some(256),
            _ => None,
        }
    }
}

fn read_bit_at(raw: &[u8], bit_pos: usize) -> Option<bool> {
    let byte = *raw.get(bit_pos / 8)?;
    Some(((byte >> (7 - (bit_pos % 8))) & 1) != 0)
}

fn read_raw_ushort_at(raw: &[u8], bit_pos: usize) -> Option<u16> {
    let mut bytes = [0u8; 2];
    for (idx, dst) in bytes.iter_mut().enumerate() {
        let base = bit_pos + idx * 8;
        if base + 8 > raw.len().saturating_mul(8) {
            return None;
        }
        let mut val = 0u8;
        for i in 0..8 {
            val = (val << 1) | read_bit_at(raw, base + i)? as u8;
        }
        *dst = val;
    }
    Some(u16::from_le_bytes(bytes))
}

fn is_raw_text_unit(unit: u16) -> bool {
    matches!(
        unit,
        0x0020..=0x007E | 0x3000..=0x303F | 0x4E00..=0x9FFF | 0xFF00..=0xFFEF
    )
}

fn is_probable_table_cell_text(text: &str) -> bool {
    if text.len() < 2 || text.len() > 120 {
        return false;
    }
    if !text.chars().all(is_probable_raw_text_char) {
        return false;
    }
    if text.eq_ignore_ascii_case("txt")
        || text.eq_ignore_ascii_case("txt.shx")
        || text.eq_ignore_ascii_case("standard")
        || text.eq_ignore_ascii_case("cell_value")
        || text.contains("ACAD_")
        || text.contains("Open Design")
        || text.contains("Teigha")
    {
        return false;
    }
    if text.chars().count() == 1 && text.chars().any(|c| ('\u{4E00}'..='\u{9FFF}').contains(&c)) {
        return false;
    }
    text.chars().any(|c| c.is_alphanumeric())
}

fn is_probable_raw_text_char(c: char) -> bool {
    c.is_alphanumeric()
        || c.is_ascii_whitespace()
        || matches!(
            c,
            '_' | '-'
                | '+'
                | '/'
                | '\\'
                | '.'
                | ','
                | ':'
                | ';'
                | '('
                | ')'
                | '['
                | ']'
                | '#'
                | '%'
                | '&'
                | '='
                | '<'
                | '>'
                | '°'
        )
        || ('\u{4E00}'..='\u{9FFF}').contains(&c)
        || ('\u{3000}'..='\u{303F}').contains(&c)
        || ('\u{FF00}'..='\u{FFEF}').contains(&c)
}

/// Binary string carving fallback for malformed or pre-R13 DWG files.
pub fn carve_dwg_strings(bytes: &[u8]) -> String {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut cur = Vec::new();
    for &b in bytes.iter().take(4 * 1024 * 1024) {
        if b >= 0x20 && b != 0x7F {
            cur.push(b);
        } else {
            if cur.len() >= 6 {
                if let Ok(s) = std::str::from_utf8(&cur) {
                    let s = s.trim();
                    if s.chars().any(|c| c.is_alphanumeric()) && seen.insert(s.to_string()) {
                        out.push(s.to_string());
                    }
                }
            }
            cur.clear();
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_acad_mtext_and_unicode_escapes() {
        let raw = r#"{\fSimSun|b0|i0|c134|p2;\C7;一层给排水平面图\P\H2.5x;\U+7BA1\U+9053\S1^2; %%c100 %%d}"#;
        let clean = decode_acad_text(raw, true);
        assert!(clean.contains("一层给排水平面图"));
        assert!(clean.contains("管道1/2"));
        assert!(clean.contains("⌀100 °"));
    }
}
