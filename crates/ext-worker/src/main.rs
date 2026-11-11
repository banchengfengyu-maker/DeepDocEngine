use deepdoc_parsers::adapters::find_native_asset;
use deepdoc_parsers::extra_formats::{parse_dbf, parse_dxf_smart};
use deepdoc_parsers::text::{decode_text_auto, extract_html_text_and_images, extract_rtf_text};
use deepdoc_parsers::{parse_bytes, ParserContext};
use deepdoc_protocol::{
    read_frame_sync, write_frame_sync, ExtractedDocument, FailureKind, FrameError, ParseOptions,
    SegmentScope, TextSegment, WorkerCapabilities, WorkerRequest, WorkerResponse,
};
use deepdoc_source_fs::blake3_bytes;
use outlook_pst::ltp::prop_context::PropertyValue;
use outlook_pst::messaging::attachment::{AnsiAttachment, Attachment, AttachmentData, UnicodeAttachment};
use outlook_pst::messaging::folder::{AnsiFolder, Folder, UnicodeFolder};
use outlook_pst::messaging::message::{AnsiMessage, Message, UnicodeMessage};
use outlook_pst::messaging::store::{AnsiStore, Store, UnicodeStore};
use outlook_pst::ndb::node_id::{NodeId, NID_ROOT_FOLDER};
use outlook_pst::{AnsiPstFile, UnicodePstFile};
use std::collections::BTreeSet;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;

/// Isolated external/GPL/heavy-native sandbox worker (`ext-worker`).
/// Shares the identical binary frame protocol with `parser-worker`, keeping
/// GPL/CPL tools (`LibreDWG`, `libpst`, `libtsk` + `libyal`, `GDAL`, `chmlib`)
/// strictly out-of-process from `engine-daemon` and `App.UI.exe`.
fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = std::io::BufWriter::new(stdout.lock());

    let tools = ExternalTools::discover();
    let parser_ctx = ParserContext::new();

    loop {
        let req: WorkerRequest = match read_frame_sync(&mut reader) {
            Ok(r) => r,
            Err(FrameError::Eof) => break,
            Err(e) => {
                eprintln!("[ext-worker] frame read error: {e}");
                break;
            }
        };

        let resp = match req {
            WorkerRequest::HealthCheck => WorkerResponse::Health {
                capabilities: WorkerCapabilities {
                    worker_kind: "ext-worker".into(),
                    license_tier: "isolated-sidecar (GPL/C++ + Forensics boundary)".into(),
                    engines: tools.capability_list(),
                },
            },
            WorkerRequest::WarmOcrCache { entries } => {
                let loaded = entries.len().min(16384);
                parser_ctx.ocr.warm_cache(&entries);
                WorkerResponse::OcrCacheWarmed { loaded }
            }
            WorkerRequest::ParseFile {
                task_id,
                disk_path,
                virtual_path,
                options,
            } => handle_ext_file(
                &tools,
                &parser_ctx,
                task_id,
                Path::new(&disk_path),
                &virtual_path,
                &options,
            ),
            WorkerRequest::ParseBytes {
                task_id,
                data,
                virtual_path,
                options,
                ..
            } => handle_ext_bytes(&tools, &parser_ctx, task_id, None, &data, &virtual_path, &options),
        };

        if let Err(e) = write_frame_sync(&mut writer, &resp) {
            eprintln!("[ext-worker] frame write error: {e}");
            break;
        }
    }
}

struct ExternalTools {
    dwg2dxf: Option<PathBuf>,
    readpst: Option<PathBuf>,
    sevenz: Option<PathBuf>,
    libtsk_present: bool,
    gdal_present: bool,
}

impl ExternalTools {
    fn discover() -> Self {
        Self {
            dwg2dxf: find_native_asset(
                "DEEPDOC_DWG2DXF_PATH",
                &["libs\\dwg2dxf.exe", "dwg2dxf.exe", "libs\\dwgread.exe"],
            ),
            readpst: find_native_asset("DEEPDOC_READPST_PATH", &["libs\\readpst.exe", "readpst.exe"]),
            sevenz: find_native_asset("DEEPDOC_7Z_PATH", &["libs\\7z.exe", "7z.exe"]),
            libtsk_present: find_native_asset("DEEPDOC_LIBTSK_PATH", &["libs\\libtsk.dll", "libs\\tsk_recover.exe"])
                .is_some(),
            gdal_present: find_native_asset("DEEPDOC_GDAL_PATH", &["libs\\gdal.dll", "libs\\ogrinfo.exe"]).is_some(),
        }
    }

    fn capability_list(&self) -> Vec<String> {
        let mut v = vec![
            "cad:dwg(acadrust)+dxf(gbk)".to_string(),
            "mail:outlook-pst-ost(native)".to_string(),
            "gis:shp+sibling-dbf".to_string(),
        ];
        if self.dwg2dxf.is_some() {
            v.push("cad:libredwg-dwg2dxf-fallback".into());
        }
        if self.readpst.is_some() {
            v.push("mail:libpst-cli".into());
        }
        if self.sevenz.is_some() {
            v.push("chm:7z-extract".into());
        }
        if self.libtsk_present {
            v.push("forensics:libtsk+libyal".into());
        } else {
            v.push("forensics:libtsk-slot-ready".into());
        }
        if self.gdal_present {
            v.push("gis:gdal-ogr".into());
        } else {
            v.push("gis:gdal-slot-ready".into());
        }
        v
    }
}

fn handle_ext_file(
    tools: &ExternalTools,
    parser_ctx: &ParserContext,
    task_id: u64,
    disk_path: &Path,
    virtual_path: &str,
    options: &ParseOptions,
) -> WorkerResponse {
    match std::fs::read(disk_path) {
        Ok(bytes) => handle_ext_bytes(
            tools,
            parser_ctx,
            task_id,
            Some(disk_path),
            &bytes,
            virtual_path,
            options,
        ),
        Err(e) => WorkerResponse::Failed {
            task_id,
            virtual_path: virtual_path.to_string(),
            kind: FailureKind::IoError,
            detail: e.to_string(),
        },
    }
}

fn make_parsed(
    parser_ctx: &ParserContext,
    task_id: u64,
    doc: ExtractedDocument,
    child_docs: Vec<ExtractedDocument>,
) -> WorkerResponse {
    WorkerResponse::Parsed {
        task_id,
        doc,
        child_docs,
        new_ocr_entries: parser_ctx.ocr.take_new_cache_entries(),
    }
}

fn handle_ext_bytes(
    tools: &ExternalTools,
    parser_ctx: &ParserContext,
    task_id: u64,
    disk_path: Option<&Path>,
    bytes: &[u8],
    virtual_path: &str,
    options: &ParseOptions,
) -> WorkerResponse {
    let file_name = virtual_path
        .rsplit(['/', '\\', '!'])
        .find(|s| !s.is_empty())
        .unwrap_or(virtual_path)
        .to_string();
    let ext = Path::new(&file_name)
        .extension()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let blake3_hex = blake3_bytes(bytes);

    let mut doc = ExtractedDocument {
        virtual_path: virtual_path.to_string(),
        file_name: file_name.clone(),
        detected_format: ext.clone(),
        blake3_hex,
        byte_size: bytes.len() as u64,
        encrypted: false,
        segments: Vec::new(),
        metadata: Vec::new(),
        warnings: Vec::new(),
    };
    let mut children = Vec::new();

    if bytes.starts_with(b"AC10") || ext == "dwg" {
        if let Ok((mut parsed_doc, child_docs)) = parse_bytes(parser_ctx, bytes, virtual_path, options) {
            let needs_fallback = parsed_doc
                .metadata
                .iter()
                .any(|(k, v)| k == "dwg_engine" && v == "acadrust-carve");
            if !needs_fallback || tools.dwg2dxf.is_none() {
                return make_parsed(parser_ctx, task_id, parsed_doc, child_docs);
            }
            if let Some(ref dwg_tool) = tools.dwg2dxf {
                if let Ok(dxf_bytes) = run_dwg2dxf(dwg_tool, bytes) {
                    let dxf_res = parse_dxf_smart(&dxf_bytes);
                    if !dxf_res.segments.is_empty() {
                        parsed_doc.metadata.push(("dwg_fallback".into(), "libredwg-dwg2dxf".into()));
                        parsed_doc.segments.extend(dxf_res.segments);
                        parsed_doc.warnings.extend(dxf_res.warnings);
                    }
                }
            }
            return make_parsed(parser_ctx, task_id, parsed_doc, child_docs);
        }
    }

    if (bytes.len() >= 100 && bytes[0..4] == [0x00, 0x00, 0x27, 0x0A]) || ext == "shp" {
        doc.detected_format = "shp".into();
        if bytes.len() >= 36 {
            let shape_type = i32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
            doc.segments.push(TextSegment {
                scope: SegmentScope::Metadata,
                location_label: "ESRI Shapefile 头".into(),
                text: format!("ShapeType={shape_type}, FileBytes={}", bytes.len()),
            });
        }
        if let Some(dp) = disk_path {
            let dbf_path = dp.with_extension("dbf");
            if dbf_path.exists() {
                if let Ok(dbf_bytes) = std::fs::read(&dbf_path) {
                    let dbf_res = parse_dbf(&dbf_bytes);
                    doc.segments.extend(dbf_res.segments);
                    doc.warnings.extend(dbf_res.warnings);
                }
            } else {
                doc.warnings.push("未发现同目录同名 .dbf 属性表文件".into());
            }
        }
        return make_parsed(parser_ctx, task_id, doc, children);
    }

    if bytes.starts_with(b"ITSF") || ext == "chm" {
        doc.detected_format = "chm".into();
        if let Some(ref sz) = tools.sevenz {
            if let Ok(entries) = extract_with_7z(sz, bytes, "in.chm") {
                for (name, data) in entries {
                    let child_vp = format!("{virtual_path}!/{name}");
                    if let Ok((cd, gc)) = parse_bytes(parser_ctx, &data, &child_vp, options) {
                        children.push(cd);
                        children.extend(gc);
                    }
                }
                return make_parsed(parser_ctx, task_id, doc, children);
            }
        }
        doc.warnings
            .push("CHM 帮助文件已识别（ITSF）；部署 `libs/7z.exe` 或 `chmlib` 后自动解包内部 HTML".into());
        return make_parsed(parser_ctx, task_id, doc, children);
    }

    if bytes.starts_with(b"!BDN") || ext == "pst" || ext == "ost" {
        doc.detected_format = if ext == "ost" { "ost".into() } else { "pst".into() };
        parse_pst_or_ost(
            tools,
            parser_ctx,
            disk_path,
            bytes,
            virtual_path,
            options,
            &mut doc,
            &mut children,
        );
        return make_parsed(parser_ctx, task_id, doc, children);
    }

    doc.warnings.push(format!(
        "ext-worker 收到扩展格式 `{ext}`，对应 C/C++ 插件槽位就绪"
    ));
    make_parsed(parser_ctx, task_id, doc, children)
}

#[allow(clippy::too_many_arguments)]
fn parse_pst_or_ost(
    tools: &ExternalTools,
    parser_ctx: &ParserContext,
    disk_path: Option<&Path>,
    bytes: &[u8],
    virtual_path: &str,
    options: &ParseOptions,
    doc: &mut ExtractedDocument,
    children: &mut Vec<ExtractedDocument>,
) {
    let mut temp_file: Option<PathBuf> = None;
    let open_path = if let Some(dp) = disk_path {
        dp.to_path_buf()
    } else {
        let p = std::env::temp_dir().join(format!(
            "deepdoc_pst_{}_{}.pst",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        if let Err(e) = std::fs::write(&p, bytes) {
            doc.warnings.push(format!("PST/OST 临时落盘失败: {e}"));
            return;
        }
        temp_file = Some(p.clone());
        p
    };

    let native_res = parse_pst_native_path(
        parser_ctx,
        &open_path,
        virtual_path,
        options,
        doc,
        children,
    );

    if let Err(err) = native_res {
        // Fallback to external `libs/readpst.exe` CLI if native pure-Rust parser fails
        if let Some(ref tool) = tools.readpst {
            if let Ok(entries) = run_readpst(tool, &open_path) {
                if !entries.is_empty() {
                    doc.metadata.push(("pst_engine".into(), "libpst-readpst".into()));
                    for (rel, data) in entries {
                        let child_vp = format!("{virtual_path}!/{rel}");
                        if let Ok((cd, gc)) = parse_bytes(parser_ctx, &data, &child_vp, options) {
                            children.push(cd);
                            children.extend(gc);
                        }
                    }
                    if let Some(tp) = temp_file {
                        let _ = std::fs::remove_file(tp);
                    }
                    return;
                }
            }
        }
        doc.warnings.push(format!("PST/OST 解析失败: {err}"));
    }

    if let Some(tp) = temp_file {
        let _ = std::fs::remove_file(tp);
    }
}

fn parse_pst_native_path(
    parser_ctx: &ParserContext,
    path: &Path,
    virtual_path: &str,
    options: &ParseOptions,
    doc: &mut ExtractedDocument,
    children: &mut Vec<ExtractedDocument>,
) -> Result<(), String> {
    let mut visited = BTreeSet::new();
    let mut msg_count = 0usize;

    if let Ok(pst_file) = UnicodePstFile::open(path) {
        let store = UnicodeStore::read(Rc::new(pst_file)).map_err(|e| format!("UnicodeStore::read: {e}"))?;
        doc.metadata.push(("pst_engine".into(), "outlook-pst(unicode)".into()));
        let root_eid = store
            .properties()
            .ipm_sub_tree_entry_id()
            .or_else(|_| store.properties().make_entry_id(NodeId::from(u32::from(NID_ROOT_FOLDER))))
            .map_err(|e| format!("PST root entry id: {e}"))?;
        walk_unicode_folder(
            &store,
            &root_eid,
            "",
            0,
            &mut visited,
            &mut msg_count,
            parser_ctx,
            virtual_path,
            options,
            doc,
            children,
        );
        doc.metadata.push(("pst_messages".into(), msg_count.to_string()));
        return Ok(());
    }

    if let Ok(pst_file) = AnsiPstFile::open(path) {
        let store = AnsiStore::read(Rc::new(pst_file)).map_err(|e| format!("AnsiStore::read: {e}"))?;
        doc.metadata.push(("pst_engine".into(), "outlook-pst(ansi)".into()));
        let root_eid = store
            .properties()
            .ipm_sub_tree_entry_id()
            .or_else(|_| store.properties().make_entry_id(NodeId::from(u32::from(NID_ROOT_FOLDER))))
            .map_err(|e| format!("PST root entry id: {e}"))?;
        walk_ansi_folder(
            &store,
            &root_eid,
            "",
            0,
            &mut visited,
            &mut msg_count,
            parser_ctx,
            virtual_path,
            options,
            doc,
            children,
        );
        doc.metadata.push(("pst_messages".into(), msg_count.to_string()));
        return Ok(());
    }

    Err("无法作为 Unicode 或 ANSI PST/OST 打开".into())
}

#[allow(clippy::too_many_arguments)]
fn walk_unicode_folder(
    store: &Rc<UnicodeStore>,
    entry_id: &outlook_pst::messaging::store::EntryId,
    parent_path: &str,
    depth: u32,
    visited: &mut BTreeSet<u32>,
    msg_count: &mut usize,
    parser_ctx: &ParserContext,
    virtual_path: &str,
    options: &ParseOptions,
    doc: &mut ExtractedDocument,
    children: &mut Vec<ExtractedDocument>,
) {
    if depth > 32 || *msg_count >= 20_000 {
        return;
    }
    if !visited.insert(u32::from(entry_id.node_id())) {
        return;
    }
    let Ok(folder) = UnicodeFolder::read(store.clone(), entry_id) else {
        return;
    };
    let fname = folder.properties().display_name().unwrap_or_default();
    let folder_path = if parent_path.is_empty() {
        fname
    } else if fname.is_empty() {
        parent_path.to_string()
    } else {
        format!("{parent_path}/{fname}")
    };

    if let Some(tbl) = folder.contents_table() {
        for row in tbl.rows_matrix() {
            if *msg_count >= 20_000 {
                break;
            }
            let nid = NodeId::from(u32::from(row.id()));
            let Ok(eid) = store.properties().make_entry_id(nid) else {
                continue;
            };
            if let Ok(msg) = UnicodeMessage::read(store.clone(), &eid, None) {
                *msg_count += 1;
                let subj = absorb_pst_message(&*msg, &folder_path, doc);
                if let Some(att_tbl) = msg.attachment_table() {
                    for (idx, att_row) in att_tbl.rows_matrix().enumerate() {
                        let att_nid = NodeId::from(u32::from(att_row.id()));
                        if let Ok(att) = UnicodeAttachment::read(msg.clone(), att_nid, None) {
                            absorb_pst_attachment(
                                &*att,
                                idx + 1,
                                &folder_path,
                                &subj,
                                parser_ctx,
                                virtual_path,
                                options,
                                doc,
                                children,
                            );
                        }
                    }
                }
            }
        }
    }

    if let Some(hier) = folder.hierarchy_table() {
        for sub_row in hier.rows_matrix() {
            let sub_nid = NodeId::from(u32::from(sub_row.id()));
            if let Ok(sub_eid) = store.properties().make_entry_id(sub_nid) {
                walk_unicode_folder(
                    store,
                    &sub_eid,
                    &folder_path,
                    depth + 1,
                    visited,
                    msg_count,
                    parser_ctx,
                    virtual_path,
                    options,
                    doc,
                    children,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_ansi_folder(
    store: &Rc<AnsiStore>,
    entry_id: &outlook_pst::messaging::store::EntryId,
    parent_path: &str,
    depth: u32,
    visited: &mut BTreeSet<u32>,
    msg_count: &mut usize,
    parser_ctx: &ParserContext,
    virtual_path: &str,
    options: &ParseOptions,
    doc: &mut ExtractedDocument,
    children: &mut Vec<ExtractedDocument>,
) {
    if depth > 32 || *msg_count >= 20_000 {
        return;
    }
    if !visited.insert(u32::from(entry_id.node_id())) {
        return;
    }
    let Ok(folder) = AnsiFolder::read(store.clone(), entry_id) else {
        return;
    };
    let fname = folder.properties().display_name().unwrap_or_default();
    let folder_path = if parent_path.is_empty() {
        fname
    } else if fname.is_empty() {
        parent_path.to_string()
    } else {
        format!("{parent_path}/{fname}")
    };

    if let Some(tbl) = folder.contents_table() {
        for row in tbl.rows_matrix() {
            if *msg_count >= 20_000 {
                break;
            }
            let nid = NodeId::from(u32::from(row.id()));
            let Ok(eid) = store.properties().make_entry_id(nid) else {
                continue;
            };
            if let Ok(msg) = AnsiMessage::read(store.clone(), &eid, None) {
                *msg_count += 1;
                let subj = absorb_pst_message(&*msg, &folder_path, doc);
                if let Some(att_tbl) = msg.attachment_table() {
                    for (idx, att_row) in att_tbl.rows_matrix().enumerate() {
                        let att_nid = NodeId::from(u32::from(att_row.id()));
                        if let Ok(att) = AnsiAttachment::read(msg.clone(), att_nid, None) {
                            absorb_pst_attachment(
                                &*att,
                                idx + 1,
                                &folder_path,
                                &subj,
                                parser_ctx,
                                virtual_path,
                                options,
                                doc,
                                children,
                            );
                        }
                    }
                }
            }
        }
    }

    if let Some(hier) = folder.hierarchy_table() {
        for sub_row in hier.rows_matrix() {
            let sub_nid = NodeId::from(u32::from(sub_row.id()));
            if let Ok(sub_eid) = store.properties().make_entry_id(sub_nid) {
                walk_ansi_folder(
                    store,
                    &sub_eid,
                    &folder_path,
                    depth + 1,
                    visited,
                    msg_count,
                    parser_ctx,
                    virtual_path,
                    options,
                    doc,
                    children,
                );
            }
        }
    }
}

fn prop_str(props: &outlook_pst::messaging::message::MessageProperties, id: u16) -> Option<String> {
    match props.get(id)? {
        PropertyValue::Unicode(u) => Some(u.to_string()),
        PropertyValue::String8(s) => Some(decode_text_auto(s.buffer()).0),
        PropertyValue::Binary(b) => Some(decode_text_auto(b.buffer()).0),
        _ => None,
    }
}

fn absorb_pst_message(
    msg: &dyn Message,
    folder_path: &str,
    doc: &mut ExtractedDocument,
) -> String {
    let props = msg.properties();
    let raw_subj = prop_str(props, 0x0037).unwrap_or_else(|| "(无主题)".into());
    // `[MS-OXCMSG]` PidTagSubject often carries a 2-char `\x01<prefix_len>` prefix indicator
    let subject = if let Some(rest) = raw_subj.strip_prefix('\x01') {
        rest.chars().skip(1).collect::<String>()
    } else {
        raw_subj
    };
    let sender = prop_str(props, 0x0C1A)
        .or_else(|| prop_str(props, 0x0042))
        .unwrap_or_default();
    let sender_email = prop_str(props, 0x0C1F).unwrap_or_default();
    let display_to = prop_str(props, 0x0E04).unwrap_or_default();

    let mut body = prop_str(props, 0x1000).unwrap_or_default();
    if body.trim().is_empty() {
        if let Some(html_raw) = prop_str(props, 0x1013) {
            let (txt, _) = extract_html_text_and_images(html_raw.as_bytes());
            body = txt;
        }
    }
    if body.trim().is_empty() {
        if let Some(PropertyValue::Binary(comp)) = props.get(0x1009) {
            if let Some(rtf) = decompress_ms_rtf(comp.buffer()) {
                body = extract_rtf_text(&rtf);
            }
        }
    }

    let mut block = String::new();
    block.push_str(&format!("Subject: {}\n", subject.trim()));
    if !sender.is_empty() || !sender_email.is_empty() {
        block.push_str(&format!("From: {} <{}>\n", sender.trim(), sender_email.trim()));
    }
    if !display_to.is_empty() {
        block.push_str(&format!("To: {}\n", display_to.trim()));
    }
    if !body.trim().is_empty() {
        block.push('\n');
        block.push_str(body.trim());
    }

    let loc = if folder_path.is_empty() {
        format!("PST/OST 邮件: {}", subject.trim())
    } else {
        format!("PST/OST [{folder_path}] {}", subject.trim())
    };
    doc.segments.push(TextSegment {
        scope: SegmentScope::Body,
        location_label: loc,
        text: block,
    });
    subject
}

#[allow(clippy::too_many_arguments)]
fn absorb_pst_attachment(
    att: &dyn Attachment,
    idx: usize,
    folder_path: &str,
    subject: &str,
    parser_ctx: &ParserContext,
    virtual_path: &str,
    options: &ParseOptions,
    doc: &mut ExtractedDocument,
    children: &mut Vec<ExtractedDocument>,
) {
    let ap = att.properties();
    let fname = match ap.get(0x3707).or_else(|| ap.get(0x3704)) {
        Some(PropertyValue::Unicode(u)) => u.to_string(),
        Some(PropertyValue::String8(s)) => decode_text_auto(s.buffer()).0,
        _ => format!("attachment_{idx}.bin"),
    };

    match att.data() {
        Some(AttachmentData::Binary(bin)) => {
            if children.len() >= 10_000 {
                return;
            }
            let safe_folder = if folder_path.is_empty() { "Root" } else { folder_path };
            let child_vp = format!("{virtual_path}!/{safe_folder}/{fname}");
            if let Ok((cd, gc)) = parse_bytes(parser_ctx, bin.buffer(), &child_vp, options) {
                children.push(cd);
                children.extend(gc);
            }
        }
        Some(AttachmentData::Message(nested)) => {
            absorb_pst_message(&**nested, &format!("{folder_path}/{subject}"), doc);
        }
        None => {}
    }
}

/// `[MS-OXRTF]` Compressed RTF (`LZFu` / `MELA`) decompressor used in Outlook PST/MSG bodies.
fn decompress_ms_rtf(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 16 {
        return None;
    }
    let comp_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let raw_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let comp_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if raw_size == 0 || raw_size > 16 * 1024 * 1024 {
        return None;
    }
    let payload_end = (4 + comp_size).min(data.len());
    if payload_end < 16 {
        return None;
    }
    let src = &data[16..payload_end];

    if comp_type == 0x414C_454D {
        // "MELA" (uncompressed)
        return Some(src[..src.len().min(raw_size)].to_vec());
    }
    if comp_type != 0x7546_5A4C {
        // Not "LZFu"
        return None;
    }

    const PREBUF: &[u8] = b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx";
    let mut dict = [0u8; 4096];
    let init_len = PREBUF.len().min(4096);
    dict[..init_len].copy_from_slice(&PREBUF[..init_len]);
    let mut write_pos = init_len;

    let mut out = Vec::with_capacity(raw_size);
    let mut pos = 0usize;
    'outer: while pos < src.len() && out.len() < raw_size {
        let flags = src[pos];
        pos += 1;
        for bit in 0..8 {
            if out.len() >= raw_size || pos >= src.len() {
                break 'outer;
            }
            if (flags & (1 << bit)) == 0 {
                let b = src[pos];
                pos += 1;
                out.push(b);
                dict[write_pos & 4095] = b;
                write_pos += 1;
            } else {
                if pos + 2 > src.len() {
                    break 'outer;
                }
                let dict_ref = u16::from_be_bytes([src[pos], src[pos + 1]]);
                pos += 2;
                let offset = ((dict_ref >> 4) & 0x0FFF) as usize;
                let len = ((dict_ref & 0x000F) + 2) as usize;
                if offset == (write_pos & 4095) {
                    break 'outer;
                }
                for k in 0..len {
                    if out.len() >= raw_size {
                        break 'outer;
                    }
                    let b = dict[(offset + k) & 4095];
                    out.push(b);
                    dict[write_pos & 4095] = b;
                    write_pos += 1;
                }
            }
        }
    }
    Some(out)
}

fn run_readpst(tool: &Path, pst_path: &Path) -> Result<Vec<(String, Vec<u8>)>, std::io::Error> {
    let tmp = std::env::temp_dir().join(format!(
        "deepdoc_readpst_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp)?;
    let out = Command::new(tool)
        .arg("-M")
        .arg("-e")
        .arg("-o")
        .arg(&tmp)
        .arg(pst_path)
        .current_dir(tool.parent().unwrap_or_else(|| Path::new(".")))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let mut entries = Vec::new();
    if out.status.success() {
        collect_dir(&tmp, &tmp, &mut entries)?;
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(entries)
}

fn run_dwg2dxf(tool: &Path, dwg_bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let tmp = std::env::temp_dir().join(format!(
        "deepdoc_dwg_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp)?;
    let in_p = tmp.join("in.dwg");
    let out_p = tmp.join("out.dxf");
    std::fs::write(&in_p, dwg_bytes)?;
    let out = Command::new(tool)
        .arg("-y")
        .arg("-o")
        .arg(&out_p)
        .arg(&in_p)
        .current_dir(tool.parent().unwrap_or_else(|| Path::new(".")))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let res = if out.status.success() && out_p.exists() {
        std::fs::read(&out_p)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(std::io::Error::other(format!("dwg2dxf exited {}: {}", out.status, stderr.trim())))
    };
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

fn extract_with_7z(tool: &Path, bytes: &[u8], fname: &str) -> Result<Vec<(String, Vec<u8>)>, std::io::Error> {
    let tmp = std::env::temp_dir().join(format!(
        "deepdoc_chm_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp)?;
    let in_p = tmp.join(fname);
    let out_dir = tmp.join("out");
    std::fs::create_dir_all(&out_dir)?;
    std::fs::write(&in_p, bytes)?;
    let out = Command::new(tool)
        .arg("x")
        .arg("-y")
        .arg(format!("-o{}", out_dir.display()))
        .arg(&in_p)
        .current_dir(tool.parent().unwrap_or_else(|| Path::new(".")))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let mut entries = Vec::new();
    if out.status.success() {
        collect_dir(&out_dir, &out_dir, &mut entries)?;
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(entries)
}

fn collect_dir(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) -> std::io::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let p = e.path();
        if p.is_dir() {
            collect_dir(base, &p, out)?;
        } else if p.is_file() {
            let rel = p.strip_prefix(base).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            if let Ok(b) = std::fs::read(&p) {
                out.push((rel, b));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_tools() -> ExternalTools {
        ExternalTools {
            dwg2dxf: None,
            readpst: None,
            sevenz: None,
            libtsk_present: false,
            gdal_present: false,
        }
    }

    #[test]
    fn ext_worker_handles_dwg_shp_dbf_and_disk_carving() {
        let tools = empty_tools();
        let ctx = ParserContext::new();
        let opts = ParseOptions::default();

        // 1. DWG release header detection
        let mut dwg = vec![0u8; 64];
        dwg[..6].copy_from_slice(b"AC1032");
        match handle_ext_bytes(&tools, &ctx, 1, None, &dwg, r"C:\cad\plan.dwg", &opts) {
            WorkerResponse::Parsed { doc, .. } => {
                assert_eq!(doc.detected_format, "dwg");
                assert!(doc.segments.iter().any(|s| s.text.contains("AutoCAD 2018-2024")));
            }
            other => panic!("unexpected dwg response: {other:?}"),
        }

        // 2. ESRI .shp + sibling .dbf attribute table loading
        let tmp = std::env::temp_dir().join(format!("deepdoc_ext_shp_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let shp_path = tmp.join("parcel.shp");
        let dbf_path = tmp.join("parcel.dbf");

        let mut shp = vec![0u8; 100];
        shp[0..4].copy_from_slice(&[0x00, 0x00, 0x27, 0x0A]);
        shp[32..36].copy_from_slice(&5i32.to_le_bytes()); // Polygon
        std::fs::write(&shp_path, &shp).unwrap();

        let mut dbf = vec![0u8; 65 + 21 + 1];
        dbf[0] = 0x03;
        dbf[1] = 26;
        dbf[2] = 11;
        dbf[3] = 11;
        dbf[4..8].copy_from_slice(&1u32.to_le_bytes());
        dbf[8..10].copy_from_slice(&65u16.to_le_bytes());
        dbf[10..12].copy_from_slice(&21u16.to_le_bytes());
        dbf[32..36].copy_from_slice(b"ZONE");
        dbf[43] = b'C';
        dbf[48] = 20;
        dbf[64] = 0x0D;
        dbf[65] = b' ';
        dbf[66..81].copy_from_slice(b"RESTRICTED_AREA");
        dbf[81..86].fill(b' ');
        dbf[86] = 0x1A;
        std::fs::write(&dbf_path, &dbf).unwrap();

        match handle_ext_file(&tools, &ctx, 2, &shp_path, &shp_path.to_string_lossy(), &opts) {
            WorkerResponse::Parsed { doc, .. } => {
                assert_eq!(doc.detected_format, "shp");
                assert!(doc.segments.iter().any(|s| s.text.contains("ShapeType=5")));
                assert!(doc.segments.iter().any(|s| s.text.contains("RESTRICTED_AREA")));
            }
            other => panic!("unexpected shp response: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn ext_worker_parses_real_dwg_and_pst_with_lzfu_rtf() {
        let tools = ExternalTools::discover();
        let ctx = ParserContext::new();
        let opts = ParseOptions::default();

        // 1. Real DWG -> Pure-Rust acadrust direct parser (no temp DXF / LibreDWG required)
        let dwg = include_bytes!("../tests/fixtures/testDWG2004.dwg");
        match handle_ext_bytes(&tools, &ctx, 10, None, dwg, r"C:\cad\testDWG2004.dwg", &opts) {
            WorkerResponse::Parsed { doc, .. } => {
                assert_eq!(doc.detected_format, "dwg");
                assert!(
                    doc.metadata.iter().any(|(k, v)| k == "dwg_engine" && v == "acadrust"),
                    "Expected native acadrust DWG extraction, warnings={:?} metadata={:?}",
                    doc.warnings,
                    doc.metadata
                );
                assert!(
                    doc.segments
                        .iter()
                        .any(|s| s.scope == SegmentScope::Metadata && s.text.contains("AC1018")),
                    "Expected DWG metadata segment, got {:?}",
                    doc.segments
                );
            }
            other => panic!("unexpected real dwg response: {other:?}"),
        }

        // 2. Real Outlook PST (`testPST_variousBodyTypes.pst`) -> folders, emails & RTF bodies
        let pst = include_bytes!("../tests/fixtures/testPST_variousBodyTypes.pst");
        match handle_ext_bytes(&tools, &ctx, 11, None, pst, r"C:\mail\testPST_variousBodyTypes.pst", &opts) {
            WorkerResponse::Parsed { doc, child_docs, .. } => {
                assert_eq!(doc.detected_format, "pst");
                let msg_count: usize = doc
                    .metadata
                    .iter()
                    .find(|(k, _)| k == "pst_messages")
                    .and_then(|(_, v)| v.parse().ok())
                    .unwrap_or(0);
                eprintln!("[PST] msgs={msg_count}, segs={}, children={}", doc.segments.len(), child_docs.len());
                for s in doc.segments.iter().take(5) {
                    eprintln!("[PST seg] {} => {:?}", s.location_label, &s.text[..s.text.len().min(120)]);
                }
                assert!(msg_count > 0, "Expected messages from testPST_variousBodyTypes.pst; warnings={:?}", doc.warnings);
                assert!(!doc.segments.is_empty());
            }
            other => panic!("unexpected real pst response: {other:?}"),
        }

        // 3. Direct MS-OXRTF MELA & LZFu unit check
        let rtf_plain = b"{\\rtf1 Hello MELA}";
        let mut mela = Vec::new();
        mela.extend_from_slice(&((12 + rtf_plain.len()) as u32).to_le_bytes());
        mela.extend_from_slice(&(rtf_plain.len() as u32).to_le_bytes());
        mela.extend_from_slice(&0x414C_454Du32.to_le_bytes()); // MELA
        mela.extend_from_slice(&0u32.to_le_bytes());
        mela.extend_from_slice(rtf_plain);
        assert_eq!(decompress_ms_rtf(&mela).as_deref(), Some(&rtf_plain[..]));
    }

    #[test]
    fn verifies_staged_7z_and_dwg_fallback() {
        let tools = ExternalTools::discover();
        assert!(
            tools.sevenz.is_some(),
            "7z.exe must be staged in native_deps/libs/7z.exe for CHM unpacking"
        );
        let ctx = ParserContext::default();
        let opts = ParseOptions::default();

        let dwg_fake = b"AC1032\x00\x00CAD_PROJECT_DRAWING_NO_0099\x00";
        match handle_ext_bytes(&tools, &ctx, 20, None, dwg_fake, r"C:\cad\sample.dwg", &opts) {
            WorkerResponse::Parsed { doc, .. } => {
                assert_eq!(doc.detected_format, "dwg");
                assert!(doc.segments.iter().any(|s| s.text.contains("CAD_PROJECT_DRAWING_NO_0099")));
            }
            other => panic!("unexpected DWG fallback response: {other:?}"),
        }
    }
}
