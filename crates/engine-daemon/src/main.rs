mod supervisor;

use deepdoc_indexer::{build_document_preview, IndexStore, PendingOcrTaskInput, PendingOcrTaskRow};
use deepdoc_protocol::framing::async_codec::{read_frame_async, write_frame_async};
use deepdoc_protocol::{
    build_metadata_only_doc, is_metadata_only_binary_ext, is_ocr_image_ext, ClientEnvelope,
    ClientRequest, DaemonMessage, DeferredOcrImage, ExtractedDocument, FailureKind, RuleDefinition,
    RuleMatchMode, RuleSet, ScanOptions, ScanSummary, SegmentScope, TextSegment, WorkerRequest,
    WorkerResponse, DEFAULT_PIPE_NAME,
};
use deepdoc_rule_engine::CompiledRuleSet;
use deepdoc_source_fs::{
    blake3_bytes, blake3_file, enumerate_roots_with_options, is_drive_root_path,
    query_ntfs_usn_state, stream_root_with_options, try_read_ntfs_usn_delta, DiscoveredFile,
};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use supervisor::{find_sibling_exe, WorkerPool};
use tokio::sync::{mpsc, Mutex, Semaphore};

struct DaemonState {
    store: Arc<IndexStore>,
    parser_pool: Arc<WorkerPool>,
    ext_pool: Option<Arc<WorkerPool>>,
    worker_count: usize,
    active_jobs: Mutex<HashMap<String, Arc<AtomicBool>>>,
    cached_worker_engines: Mutex<Option<Vec<String>>>,
    cached_ext_engines: Mutex<Option<Vec<String>>>,
    ephemeral_docs: Mutex<HashMap<u64, ExtractedDocument>>,
    next_ephemeral_id: AtomicU64,
    next_task_id: AtomicU64,
    shutdown_notify: Arc<tokio::sync::Notify>,
}

fn default_data_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("DeepDocEngine").join("data");
    }
    PathBuf::from("./deepdoc_data")
}

fn parse_cli_args() -> (String, PathBuf, usize) {
    let mut pipe_name = DEFAULT_PIPE_NAME.to_string();
    let mut data_dir = default_data_dir();
    let mut workers = std::thread::available_parallelism()
        .map(|n| n.get().clamp(2, 8))
        .unwrap_or(4);

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--pipe" if i + 1 < args.len() => {
                pipe_name = args[i + 1].clone();
                i += 2;
            }
            "--data-dir" if i + 1 < args.len() => {
                data_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--workers" if i + 1 < args.len() => {
                workers = args[i + 1].parse().unwrap_or(2).clamp(1, 16);
                i += 2;
            }
            _ => i += 1,
        }
    }
    (pipe_name, data_dir, workers)
}

#[tokio::main]
async fn main() {
    let (pipe_name, data_dir, worker_count) = parse_cli_args();
    eprintln!(
        "[engine-daemon] starting: pipe=`{pipe_name}`, data=`{}`",
        data_dir.display()
    );

    let store = Arc::new(IndexStore::open(&data_dir).expect("failed to open IndexStore"));
    cleanup_stale_deepdoc_temp_dirs(Some(Duration::from_secs(60)));
    let parser_exe = find_sibling_exe("parser-worker.exe");
    let parser_pool = WorkerPool::start(parser_exe, worker_count)
        .await
        .expect("failed to start parser-worker pool");

    let ext_exe = find_sibling_exe("ext-worker.exe");
    let ext_pool = if ext_exe.exists() {
        WorkerPool::start(ext_exe, (worker_count / 2).clamp(1, 2))
            .await
            .ok()
    } else {
        None
    };

    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let state = Arc::new(DaemonState {
        store,
        parser_pool,
        ext_pool,
        worker_count,
        active_jobs: Mutex::new(HashMap::new()),
        cached_worker_engines: Mutex::new(None),
        cached_ext_engines: Mutex::new(None),
        ephemeral_docs: Mutex::new(HashMap::new()),
        next_ephemeral_id: AtomicU64::new(1_000_000_000),
        next_task_id: AtomicU64::new(1),
        shutdown_notify: shutdown_notify.clone(),
    });

    #[cfg(windows)]
    run_named_pipe_server(pipe_name, state, shutdown_notify).await;

    #[cfg(not(windows))]
    {
        let _ = state;
        eprintln!("[engine-daemon] Windows Named Pipe server is Windows-only");
    }
}

#[cfg(windows)]
struct PipeSecurityHolder {
    sd: *mut std::ffi::c_void,
}

#[cfg(windows)]
impl Drop for PipeSecurityHolder {
    fn drop(&mut self) {
        if !self.sd.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.sd as _);
            }
        }
    }
}

#[cfg(windows)]
fn current_user_sid_string() -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            CloseHandle(token);
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut _,
            needed,
            &mut needed,
        );
        CloseHandle(token);
        if ok == 0 {
            return None;
        }
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut str_sid: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(tu.User.Sid, &mut str_sid) == 0 || str_sid.is_null() {
            return None;
        }
        let mut len = 0usize;
        while *str_sid.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(str_sid, len));
        LocalFree(str_sid as _);
        Some(s)
    }
}

#[cfg(windows)]
fn build_cross_uac_pipe_sd() -> Option<PipeSecurityHolder> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };

    // Allow SYSTEM, Built-in Administrators, and exact current user across High<->Medium UAC integrity levels
    let sddl = if let Some(sid) = current_user_sid_string() {
        format!("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})S:(ML;;NW;;;ME)")
    } else {
        "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)S:(ML;;NW;;;ME)".to_string()
    };
    let mut wide: Vec<u16> = sddl.encode_utf16().collect();
    wide.push(0);

    let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut sd as *mut _ as *mut _,
            std::ptr::null_mut(),
        )
    };
    if ok != 0 && !sd.is_null() {
        Some(PipeSecurityHolder { sd })
    } else {
        None
    }
}

#[cfg(windows)]
fn create_pipe_instance(
    pipe_name: &str,
    first: bool,
    sd_holder: Option<&PipeSecurityHolder>,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    let mut opts = ServerOptions::new();
    if first {
        opts.first_pipe_instance(true);
    }
    if let Some(holder) = sd_holder {
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: holder.sd,
            bInheritHandle: 0,
        };
        let res = unsafe {
            opts.create_with_security_attributes_raw(pipe_name, &mut sa as *mut _ as *mut _)
        };
        if res.is_ok() {
            return res;
        }
    }
    opts.create(pipe_name)
}

#[cfg(windows)]
async fn run_named_pipe_server(
    pipe_name: String,
    state: Arc<DaemonState>,
    shutdown_notify: Arc<tokio::sync::Notify>,
) {
    let sd_holder = build_cross_uac_pipe_sd();
    let mut server = create_pipe_instance(&pipe_name, true, sd_holder.as_ref())
        .expect("failed to create initial Named Pipe instance");

    loop {
        tokio::select! {
            _ = shutdown_notify.notified() => {
                eprintln!("[engine-daemon] shutdown requested");
                break;
            }
            res = server.connect() => {
                if let Err(e) = res {
                    eprintln!("[engine-daemon] pipe accept error: {e}");
                    continue;
                }
                let connected_pipe = server;
                match create_pipe_instance(&pipe_name, false, sd_holder.as_ref()) {
                    Ok(next) => server = next,
                    Err(e) => {
                        eprintln!("[engine-daemon] recreate pipe failed: {e}");
                        break;
                    }
                }
                let st = state.clone();
                tokio::spawn(async move {
                    handle_client(connected_pipe, st).await;
                });
            }
        }
    }
}

#[cfg(windows)]
async fn handle_client(
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    state: Arc<DaemonState>,
) {
    let (mut reader, mut writer) = tokio::io::split(pipe);
    let (tx, mut rx) = mpsc::channel::<DaemonMessage>(256);

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write_frame_async(&mut writer, &msg).await.is_err() {
                break;
            }
        }
    });

    loop {
        let env: ClientEnvelope = match read_frame_async(&mut reader).await {
            Ok(e) => e,
            Err(_) => break,
        };
        let req_id = env.req_id;
        let tx_clone = tx.clone();
        let st_clone = state.clone();

        match env.request {
            ClientRequest::Ping => {
                let worker_engines = {
                    let cached = st_clone.cached_worker_engines.lock().await.clone();
                    if let Some(list) = cached {
                        list
                    } else {
                        let list = st_clone
                            .parser_pool
                            .health_check()
                            .await
                            .map(|c| c.engines)
                            .unwrap_or_default();
                        if st_clone.active_jobs.lock().await.is_empty() {
                            st_clone.parser_pool.shrink_idle(0).await;
                        }
                        if !list.is_empty() {
                            *st_clone.cached_worker_engines.lock().await = Some(list.clone());
                        }
                        list
                    }
                };
                let ext_worker_engines = {
                    let cached = st_clone.cached_ext_engines.lock().await.clone();
                    if let Some(list) = cached {
                        list
                    } else {
                        let list = match &st_clone.ext_pool {
                            Some(ep) => {
                                let res = ep.health_check().await.map(|c| c.engines).unwrap_or_default();
                                if st_clone.active_jobs.lock().await.is_empty() {
                                    ep.shrink_idle(0).await;
                                }
                                res
                            }
                            None => Vec::new(),
                        };
                        if !list.is_empty() {
                            *st_clone.cached_ext_engines.lock().await = Some(list.clone());
                        }
                        list
                    }
                };
                let indexed_docs = st_clone
                    .store
                    .stats()
                    .map(|s| s.total_documents)
                    .unwrap_or(0);
                let active_jobs = st_clone.active_jobs.lock().await.len();
                let _ = tx_clone
                    .send(DaemonMessage::Pong {
                        req_id,
                        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
                        worker_engines,
                        ext_worker_engines,
                        indexed_docs,
                        active_jobs,
                    })
                    .await;
            }
            ClientRequest::StartScan {
                job_id,
                roots,
                ruleset,
                options,
            } => {
                let cancel = Arc::new(AtomicBool::new(false));
                {
                    let mut jobs = st_clone.active_jobs.lock().await;
                    jobs.insert(job_id.clone(), cancel.clone());
                }
                let _ = tx_clone
                    .send(DaemonMessage::Ack {
                        req_id,
                        ok: true,
                        message: format!("scan job `{job_id}` started"),
                    })
                    .await;
                tokio::spawn(async move {
                    run_scan_job(st_clone, job_id, roots, ruleset, options, cancel, tx_clone).await;
                });
            }
            ClientRequest::DirectSearch {
                job_id,
                roots,
                query,
                use_regex,
                file_ext_filter,
                options,
                match_all_terms,
                cancel_active_jobs,
            } => {
                let compiled = match build_direct_search_ruleset(&query, use_regex, match_all_terms) {
                    Ok(c) => c,
                    Err(msg) => {
                        let _ = tx_clone
                            .send(DaemonMessage::Error {
                                req_id,
                                code: "DIRECT_SEARCH_QUERY_ERROR".into(),
                                message: msg,
                            })
                            .await;
                        continue;
                    }
                };
                let cancel = Arc::new(AtomicBool::new(false));
                {
                    let mut jobs = st_clone.active_jobs.lock().await;
                    if cancel_active_jobs {
                        for flag in jobs.values() {
                            flag.store(true, Ordering::SeqCst);
                        }
                    }
                    jobs.insert(job_id.clone(), cancel.clone());
                }
                let _ = tx_clone
                    .send(DaemonMessage::Ack {
                        req_id,
                        ok: true,
                        message: format!("direct search job `{job_id}` started (ephemeral)"),
                    })
                    .await;
                tokio::spawn(async move {
                    run_direct_search_job(
                        st_clone,
                        job_id,
                        roots,
                        Arc::new(compiled),
                        file_ext_filter,
                        options,
                        cancel_active_jobs,
                        cancel,
                        tx_clone,
                    )
                    .await;
                });
            }
            ClientRequest::CancelScan { job_id } => {
                let jobs = st_clone.active_jobs.lock().await;
                let found = if job_id == "*" {
                    for flag in jobs.values() {
                        flag.store(true, Ordering::SeqCst);
                    }
                    !jobs.is_empty()
                } else if let Some(flag) = jobs.get(&job_id) {
                    flag.store(true, Ordering::SeqCst);
                    true
                } else {
                    false
                };
                let _ = tx_clone
                    .send(DaemonMessage::Ack {
                        req_id,
                        ok: found,
                        message: if found {
                            format!("cancellation signaled for `{job_id}`")
                        } else {
                            format!("job `{job_id}` not active")
                        },
                    })
                    .await;
            }
            ClientRequest::Search { query } => {
                let t0 = Instant::now();
                let res = tokio::task::spawn_blocking(move || st_clone.store.search(&query)).await;
                match res {
                    Ok(Ok((total_hits, items))) => {
                        let _ = tx_clone
                            .send(DaemonMessage::SearchResult {
                                req_id,
                                total_hits,
                                took_ms: t0.elapsed().as_millis() as u64,
                                items,
                            })
                            .await;
                    }
                    Ok(Err(e)) => {
                        let _ = tx_clone
                            .send(DaemonMessage::Error {
                                req_id,
                                code: "SEARCH_ERROR".into(),
                                message: e.to_string(),
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = tx_clone
                            .send(DaemonMessage::Error {
                                req_id,
                                code: "INTERNAL".into(),
                                message: e.to_string(),
                            })
                            .await;
                    }
                }
            }
            ClientRequest::EvaluateRules {
                ruleset,
                doc_ids,
                path_prefix,
                file_ext_filter,
            } => {
                let t0 = Instant::now();
                match CompiledRuleSet::compile(&ruleset) {
                    Ok(compiled) => {
                        let res = tokio::task::spawn_blocking(move || {
                            let effective_ids = if doc_ids.is_some() {
                                doc_ids
                            } else {
                                st_clone.store.find_doc_ids_filtered(
                                    path_prefix.as_deref(),
                                    file_ext_filter.as_deref(),
                                )?
                            };
                            if let Some(ref ids) = effective_ids {
                                if ids.is_empty() {
                                    return Ok(Vec::new());
                                }
                            }
                            st_clone
                                .store
                                .evaluate_rules_over_store(&compiled, effective_ids.as_deref())
                        })
                        .await;
                        match res {
                            Ok(Ok(hits)) => {
                                let _ = tx_clone
                                    .send(DaemonMessage::RuleEvalResult {
                                        req_id,
                                        took_ms: t0.elapsed().as_millis() as u64,
                                        hits,
                                    })
                                    .await;
                            }
                            Ok(Err(e)) => {
                                let _ = tx_clone
                                    .send(DaemonMessage::Error {
                                        req_id,
                                        code: "RULE_EVAL_ERROR".into(),
                                        message: e.to_string(),
                                    })
                                    .await;
                            }
                            Err(e) => {
                                let _ = tx_clone
                                    .send(DaemonMessage::Error {
                                        req_id,
                                        code: "INTERNAL".into(),
                                        message: e.to_string(),
                                    })
                                    .await;
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx_clone
                            .send(DaemonMessage::Error {
                                req_id,
                                code: "RULE_COMPILE_ERROR".into(),
                                message: e.to_string(),
                            })
                            .await;
                    }
                }
            }
            ClientRequest::GetDocumentPreview {
                doc_id,
                highlight_terms,
                max_chars,
            } => {
                if let Some(ephemeral) = st_clone.ephemeral_docs.lock().await.get(&doc_id).cloned()
                {
                    let preview =
                        build_document_preview(doc_id, ephemeral, &highlight_terms, max_chars);
                    let _ = tx_clone
                        .send(DaemonMessage::PreviewResult {
                            req_id,
                            doc: preview,
                        })
                        .await;
                    continue;
                }
                let res = tokio::task::spawn_blocking(move || {
                    st_clone
                        .store
                        .get_preview(doc_id, &highlight_terms, max_chars)
                })
                .await;
                match res {
                    Ok(Ok(doc)) => {
                        let _ = tx_clone
                            .send(DaemonMessage::PreviewResult { req_id, doc })
                            .await;
                    }
                    Ok(Err(e)) => {
                        let _ = tx_clone
                            .send(DaemonMessage::Error {
                                req_id,
                                code: "PREVIEW_ERROR".into(),
                                message: e.to_string(),
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = tx_clone
                            .send(DaemonMessage::Error {
                                req_id,
                                code: "INTERNAL".into(),
                                message: e.to_string(),
                            })
                            .await;
                    }
                }
            }
            ClientRequest::GetStats => match st_clone.store.stats() {
                Ok(stats) => {
                    let _ = tx_clone
                        .send(DaemonMessage::StatsResult { req_id, stats })
                        .await;
                }
                Err(e) => {
                    let _ = tx_clone
                        .send(DaemonMessage::Error {
                            req_id,
                            code: "STATS_ERROR".into(),
                            message: e.to_string(),
                        })
                        .await;
                }
            },
            ClientRequest::ClearIndex => match st_clone.store.clear_all() {
                Ok(()) => {
                    st_clone.ephemeral_docs.lock().await.clear();
                    let _ = tx_clone
                        .send(DaemonMessage::Ack {
                            req_id,
                            ok: true,
                            message: "index cleared".into(),
                        })
                        .await;
                }
                Err(e) => {
                    let _ = tx_clone
                        .send(DaemonMessage::Error {
                            req_id,
                            code: "CLEAR_ERROR".into(),
                            message: e.to_string(),
                        })
                        .await;
                }
            },
            ClientRequest::ResetIndexKeepOcr => match st_clone.store.reset_keep_ocr_cache() {
                Ok(()) => {
                    st_clone.ephemeral_docs.lock().await.clear();
                    let _ = tx_clone
                        .send(DaemonMessage::Ack {
                            req_id,
                            ok: true,
                            message: "index reset (ocr cache preserved)".into(),
                        })
                        .await;
                }
                Err(e) => {
                    let _ = tx_clone
                        .send(DaemonMessage::Error {
                            req_id,
                            code: "RESET_ERROR".into(),
                            message: e.to_string(),
                        })
                        .await;
                }
            },
            ClientRequest::DeepDeleteFiles {
                job_id,
                paths,
                cancel_active_jobs,
            } => {
                let cancel = Arc::new(AtomicBool::new(false));
                {
                    let mut jobs = st_clone.active_jobs.lock().await;
                    if cancel_active_jobs {
                        for flag in jobs.values() {
                            flag.store(true, Ordering::SeqCst);
                        }
                    }
                    jobs.insert(job_id.clone(), cancel.clone());
                }
                let _ = tx_clone
                    .send(DaemonMessage::Ack {
                        req_id,
                        ok: true,
                        message: format!("deep delete job `{job_id}` started ({} targets)", paths.len()),
                    })
                    .await;
                tokio::spawn(async move {
                    run_deep_delete_job(
                        st_clone,
                        job_id,
                        paths,
                        cancel_active_jobs,
                        cancel,
                        tx_clone,
                    )
                    .await;
                });
            }
            ClientRequest::Shutdown => {
                {
                    let jobs = st_clone.active_jobs.lock().await;
                    for flag in jobs.values() {
                        flag.store(true, Ordering::SeqCst);
                    }
                }
                st_clone.parser_pool.shrink_idle(0).await;
                if let Some(ep) = &st_clone.ext_pool {
                    ep.shrink_idle(0).await;
                }
                let s_commit = st_clone.store.clone();
                let _ = tokio::task::spawn_blocking(move || s_commit.commit()).await;
                let _ = tx_clone
                    .send(DaemonMessage::Ack {
                        req_id,
                        ok: true,
                        message: "shutting down".into(),
                    })
                    .await;
                st_clone.shutdown_notify.notify_waiters();
                break;
            }
        }
    }

    drop(tx);
    let _ = writer_task.await;
}

async fn warm_worker_pools(state: &DaemonState) {
    let entries = tokio::task::spawn_blocking({
        let s = state.store.clone();
        move || s.load_ocr_cache(8192).unwrap_or_default()
    })
    .await
    .unwrap_or_default();
    if entries.is_empty() {
        return;
    }
    let shared = Arc::new(entries);
    state.parser_pool.set_ocr_warmup(shared.clone()).await;
    if let Some(ep) = &state.ext_pool {
        ep.set_ocr_warmup(shared).await;
    }
}

fn cleanup_stale_deepdoc_temp_dirs(min_age: Option<Duration>) {
    let temp_dir = std::env::temp_dir();
    let Ok(rd) = std::fs::read_dir(&temp_dir) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in rd.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("deepdoc_") {
            continue;
        }
        if let Some(age) = min_age {
            let Ok(meta) = entry.metadata() else { continue };
            let Ok(modified) = meta.modified() else { continue };
            if now.duration_since(modified).unwrap_or_default() < age {
                continue;
            }
        }
        let path = entry.path();
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(path);
        } else {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn is_priority_core_doc_ext(ext: &str) -> bool {
    matches!(
        ext,
        "doc" | "docx" | "wps" | "rtf" | "odt"
            | "xls" | "xlsx" | "xlsm" | "xlsb" | "csv" | "et" | "ods"
            | "ppt" | "pptx" | "dps" | "odp"
            | "pdf" | "ofd" | "xps"
            | "txt" | "md" | "log"
            | "dwg" | "dxf"
            | "zip" | "7z" | "rar" | "tar" | "gz" | "bz2" | "xz" | "zst" | "cab" | "iso"
            | "eml" | "msg" | "pst" | "ost"
    )
}

struct DeferredFlushMeta {
    outer_vp: String,
    outer_disk_path: String,
    passwords: Vec<String>,
    deferred_images: Vec<DeferredOcrImage>,
    deferred_pdf_pages: Vec<usize>,
    pure_image_file: Option<(String, String)>, // (disk_path, label)
}

type StagedDocRecord = (
    String,            // source_root
    ExtractedDocument, // doc
    i64,               // mtime_ns
    String,            // status
    Option<DeferredFlushMeta>,
);

fn try_send_progress(tx: &mpsc::Sender<DaemonMessage>, msg: DaemonMessage) {
    let _ = tx.try_send(msg);
}

async fn send_with_timeout(tx: &mpsc::Sender<DaemonMessage>, msg: DaemonMessage) {
    let _ = tokio::time::timeout(Duration::from_secs(2), tx.send(msg)).await;
}

async fn finish_job_and_shrink(state: &DaemonState, job_id: &str) {
    let no_active_jobs = {
        let mut jobs = state.active_jobs.lock().await;
        jobs.remove(job_id);
        jobs.is_empty()
    };
    if no_active_jobs {
        state.parser_pool.set_low_resource(false).await;
        state.parser_pool.shrink_idle(0).await;
        if let Some(ep) = &state.ext_pool {
            ep.set_low_resource(false).await;
            ep.shrink_idle(0).await;
        }
        let _ = tokio::task::spawn_blocking(|| cleanup_stale_deepdoc_temp_dirs(None)).await;
    }
}

async fn run_scan_job(
    state: Arc<DaemonState>,
    job_id: String,
    roots: Vec<String>,
    ruleset: Option<RuleSet>,
    options: ScanOptions,
    cancel: Arc<AtomicBool>,
    tx: mpsc::Sender<DaemonMessage>,
) {
    let t0 = Instant::now();
    warm_worker_pools(&state).await;

    let compiled_rules = match ruleset {
        Some(ref rs) if !rs.rules.is_empty() => match CompiledRuleSet::compile(rs) {
            Ok(c) => Some(Arc::new(c)),
            Err(e) => {
                let _ = tx
                    .send(DaemonMessage::Error {
                        req_id: 0,
                        code: "RULE_COMPILE_ERROR".into(),
                        message: e.to_string(),
                    })
                    .await;
                None
            }
        },
        _ => None,
    };

    // Load existing incremental snapshot & queued OCR doc IDs before streaming discovery starts
    let snapshot_store = state.store.clone();
    let (snapshot, queued_doc_ids) = tokio::task::spawn_blocking(move || {
        let snap = snapshot_store.load_incremental_snapshot().unwrap_or_default();
        let queued: std::collections::HashSet<u64> = snapshot_store
            .load_pending_ocr_tasks()
            .map(|rows| rows.into_iter().map(|r| r.doc_id).collect())
            .unwrap_or_default();
        (snap, queued)
    })
    .await
    .unwrap_or_default();

    let (disc_tx, mut disc_rx) = mpsc::channel::<(String, DiscoveredFile)>(2048);
    let roots_clone = roots.clone();
    let opts_clone = options.clone();
    let store_snap = state.store.clone();
    let cancel_disc = cancel.clone();

    // Everything-style streaming producer: feeds files live into Stage 1 without waiting minutes for full drive crawl
    let disc_handle = tokio::task::spawn_blocking(move || {
        let mut pending_usn: Vec<(String, u64, i64)> = Vec::new();
        let mut removed_count = 0usize;

        for root_str in roots_clone {
            if cancel_disc.load(Ordering::SeqCst) {
                break;
            }
            let root_path = Path::new(&root_str);
            let is_ntfs_root = opts_clone.use_usn_if_available
                && opts_clone.parse.passwords.is_empty()
                && is_drive_root_path(root_path);

            if is_ntfs_root {
                if let Ok(Some((jid, saved_usn))) = store_snap.get_usn_checkpoint(&root_str) {
                    if let Ok(delta) =
                        try_read_ntfs_usn_delta(root_path, jid, saved_usn, &opts_clone)
                    {
                        let removed: Vec<String> = delta
                            .removed_paths
                            .iter()
                            .map(|p| p.to_string_lossy().into_owned())
                            .collect();
                        if !removed.is_empty() {
                            removed_count += store_snap
                                .remove_documents_by_paths(&removed)
                                .unwrap_or(0);
                        }
                        for entry in delta.upserts {
                            if cancel_disc.load(Ordering::SeqCst)
                                || disc_tx.blocking_send((root_str.clone(), entry)).is_err()
                            {
                                break;
                            }
                        }
                        pending_usn.push((root_str, delta.journal_id, delta.next_usn));
                        continue;
                    }
                }
                if let Some((jid, cur_usn)) = query_ntfs_usn_state(root_path) {
                    pending_usn.push((root_str.clone(), jid, cur_usn));
                }
            }

            stream_root_with_options(&root_str, &opts_clone, |entry| {
                if cancel_disc.load(Ordering::SeqCst) {
                    return false;
                }
                disc_tx.blocking_send((root_str.clone(), entry)).is_ok()
            });
        }
        (pending_usn, removed_count)
    });

    let mut scanned_files = 0u64;
    let mut parsed_ok = 0u64;
    let mut child_docs_indexed = 0u64;
    let mut skipped_cached = 0u64;
    let mut encrypted_files = 0u64;
    let mut failed_files = 0u64;
    let mut rule_hits = 0u64;

    let mut timeout = Duration::from_millis(options.worker_timeout_ms.max(2_000));
    if options.parse.enable_ocr {
        timeout = timeout.max(Duration::from_secs(300));
    }
    let two_phase_ocr = options.parse.enable_ocr;
    let mut fast_parse_opts = options.parse.clone();
    if two_phase_ocr {
        fast_parse_opts.enable_ocr = false;
        fast_parse_opts.extract_deferred_images = true;
    }

    let low_res = options.low_resource_mode;
    state.parser_pool.set_low_resource(low_res).await;
    if let Some(ep) = &state.ext_pool {
        ep.set_low_resource(low_res).await;
    }
    let max_in_flight = if low_res {
        1
    } else {
        (state.worker_count.min(options.worker_count.max(1)) * 2).clamp(4, 16)
    };
    let heavy_concurrency = if low_res {
        1
    } else {
        state
            .worker_count
            .min(options.worker_count.max(1))
            .div_ceil(3)
            .clamp(2, 3)
    };
    let heavy_sem = Arc::new(Semaphore::new(heavy_concurrency));
    let batch_flush_len = if low_res { 64usize } else { 256usize };
    let commit_every_docs = if low_res { 400u64 } else { 8000u64 };

    enum IndexPipelineMsg {
        Flush(Vec<StagedDocRecord>, Vec<(String, u32, u32, String)>),
        Commit,
        Sync(tokio::sync::oneshot::Sender<u64>),
    }

    let (idx_tx, mut idx_rx) = mpsc::channel::<IndexPipelineMsg>(4);
    let idx_store = state.store.clone();
    let idx_rules = compiled_rules.clone();
    let idx_prog_tx = tx.clone();
    let idx_job_id = job_id.clone();
    let indexer_handle = tokio::spawn(async move {
        let mut total_hits = 0u64;
        while let Some(msg) = idx_rx.recv().await {
            match msg {
                IndexPipelineMsg::Flush(drained, ocr_drained) => {
                    total_hits += flush_staged_batch(
                        idx_store.clone(),
                        drained,
                        ocr_drained,
                        idx_rules.clone(),
                        &idx_prog_tx,
                        &idx_job_id,
                    )
                    .await;
                }
                IndexPipelineMsg::Commit => {
                    let st_c = idx_store.clone();
                    let _ = tokio::task::spawn_blocking(move || st_c.commit()).await;
                }
                IndexPipelineMsg::Sync(reply) => {
                    let st_c = idx_store.clone();
                    let _ = tokio::task::spawn_blocking(move || st_c.commit()).await;
                    let _ = reply.send(total_hits);
                    total_hits = 0;
                }
            }
        }
        total_hits
    });

    let mut join_set: tokio::task::JoinSet<Vec<(String, DiscoveredFile, WorkerResponse)>> =
        tokio::task::JoinSet::new();
    let mut other_queue: Vec<(String, DiscoveredFile)> = Vec::new();
    let mut cached_eval_ids: Vec<u64> = Vec::new();
    let mut batch: Vec<StagedDocRecord> = Vec::with_capacity(batch_flush_len);
    let mut pending_ocr_cache: Vec<(String, u32, u32, String)> = Vec::new();
    let mut since_last_commit = 0u64;
    let mut last_progress = Instant::now();
    let mut discovery_open = true;

    let build_meta_doc_record = |source_root: String, entry: &DiscoveredFile, vp: &str| {
        let hash_key = format!("meta:{vp}:{}", entry.byte_size);
        let warn = if entry.byte_size > options.parse.max_single_file_bytes {
            format!(
                "文件体积 ({:.1} MB) 超过单文件深解析上限，已保留文件名与属性索引",
                entry.byte_size as f64 / (1024.0 * 1024.0)
            )
        } else {
            "二进制程序/系统/大型三维组件，已仅建立文件名与属性索引".into()
        };
        let meta_doc = build_metadata_only_doc(
            entry.file_name.clone(),
            vp,
            &entry.ext_lower,
            entry.byte_size,
            blake3_bytes(hash_key.as_bytes()),
            warn,
        );
        (source_root, meta_doc, entry.mtime_ns, "ok".to_string(), None)
    };

    // Stage 1 (Core Docs Pass): stream-parse Word/Excel/PPT/PDF/TXT/DWG/Archives immediately as discovered
    let mut deferred_stage1_nonbatch: Option<(String, DiscoveredFile)> = None;
    let mut deferred_heavy_s1: VecDeque<(String, DiscoveredFile)> = VecDeque::new();
    while discovery_open
        || !join_set.is_empty()
        || deferred_stage1_nonbatch.is_some()
        || !deferred_heavy_s1.is_empty()
    {
        while join_set.len() < max_in_flight && !cancel.load(Ordering::SeqCst) {
            if !deferred_heavy_s1.is_empty() {
                if let Ok(permit) = heavy_sem.clone().try_acquire_owned() {
                    let (sr, ent) = deferred_heavy_s1.pop_front().unwrap();
                    let st_clone = state.clone();
                    let parse_opts = fast_parse_opts.clone();
                    join_set.spawn(async move {
                        let _p = permit;
                        vec![dispatch_parse_task(st_clone, sr, ent, parse_opts, timeout).await]
                    });
                    continue;
                }
            }

            let (already_counted, next_pair) = if let Some(pair) = deferred_stage1_nonbatch.take() {
                (true, Some(pair))
            } else if !discovery_open {
                (false, None)
            } else if join_set.is_empty() && deferred_heavy_s1.is_empty() {
                (false, disc_rx.recv().await)
            } else {
                match disc_rx.try_recv() {
                    Ok(v) => (false, Some(v)),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                        if deferred_heavy_s1.is_empty() {
                            break;
                        }
                        (false, None)
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        discovery_open = false;
                        (false, None)
                    }
                }
            };
            let Some((source_root, entry)) = next_pair else {
                if !discovery_open && !deferred_heavy_s1.is_empty() && join_set.len() < max_in_flight {
                    if let Ok(permit) = heavy_sem.clone().try_acquire_owned() {
                        let (sr, ent) = deferred_heavy_s1.pop_front().unwrap();
                        let st_clone = state.clone();
                        let parse_opts = fast_parse_opts.clone();
                        join_set.spawn(async move {
                            let _p = permit;
                            vec![dispatch_parse_task(st_clone, sr, ent, parse_opts, timeout).await]
                        });
                        continue;
                    }
                }
                if deferred_heavy_s1.is_empty() && next_pair.is_none() && discovery_open {
                    discovery_open = false;
                }
                break;
            };

            if !already_counted {
                scanned_files += 1;
            }
            let vp = entry.disk_path.to_string_lossy().into_owned();
            if let Some(&(cached_doc_id, old_sz, old_mt, ref st)) = snapshot.get(&vp) {
                let is_ready_or_queued = st == "ok"
                    || (st == "pending_ocr" && (!two_phase_ocr || queued_doc_ids.contains(&cached_doc_id)))
                    || (st == "encrypted" && options.parse.passwords.is_empty())
                    || (st != "ok" && st != "encrypted" && st != "pending_ocr");
                if old_sz == entry.byte_size && old_mt == entry.mtime_ns && is_ready_or_queued {
                    skipped_cached += 1;
                    if st == "ok" && compiled_rules.is_some() {
                        cached_eval_ids.push(cached_doc_id);
                    }
                    continue;
                }
            }

            if !is_priority_core_doc_ext(&entry.ext_lower) {
                other_queue.push((source_root, entry));
                continue;
            }

            if is_metadata_only_binary_ext(&entry.ext_lower)
                || entry.byte_size > options.parse.max_single_file_bytes
            {
                parsed_ok += 1;
                since_last_commit += 1;
                batch.push(build_meta_doc_record(source_root, &entry, &vp));
                continue;
            }

            // Lane A: Heavy PDFs / Archives / Large files (>4 MB) -> isolated heavy semaphore so fast files never stall
            if is_heavy_file(&entry) {
                if let Ok(permit) = heavy_sem.clone().try_acquire_owned() {
                    let st_clone = state.clone();
                    let parse_opts = fast_parse_opts.clone();
                    join_set.spawn(async move {
                        let _p = permit;
                        vec![dispatch_parse_task(st_clone, source_root, entry, parse_opts, timeout).await]
                    });
                } else {
                    deferred_heavy_s1.push_back((source_root, entry));
                }
                continue;
            }

            // Lane B: Safe Plain-Text In-Process Fast Path (zero cross-process pipe IPC!)
            if is_inproc_text_eligible(&entry, options.parse.max_single_file_bytes) {
                let mut text_group = Vec::with_capacity(16);
                text_group.push((source_root, entry));
                while text_group.len() < 16 && !cancel.load(Ordering::SeqCst) {
                    match disc_rx.try_recv() {
                        Ok((sr2, e2)) => {
                            scanned_files += 1;
                            let vp2 = e2.disk_path.to_string_lossy().into_owned();
                            if let Some(&(cid2, osz2, omt2, ref st2)) = snapshot.get(&vp2) {
                                let ready2 = st2 == "ok"
                                    || (st2 == "pending_ocr" && (!two_phase_ocr || queued_doc_ids.contains(&cid2)))
                                    || (st2 == "encrypted" && options.parse.passwords.is_empty())
                                    || (st2 != "ok" && st2 != "encrypted" && st2 != "pending_ocr");
                                if osz2 == e2.byte_size && omt2 == e2.mtime_ns && ready2 {
                                    skipped_cached += 1;
                                    if st2 == "ok" && compiled_rules.is_some() {
                                        cached_eval_ids.push(cid2);
                                    }
                                    continue;
                                }
                            }
                            if !is_priority_core_doc_ext(&e2.ext_lower) {
                                other_queue.push((sr2, e2));
                                continue;
                            }
                            if is_metadata_only_binary_ext(&e2.ext_lower)
                                || e2.byte_size > options.parse.max_single_file_bytes
                            {
                                parsed_ok += 1;
                                since_last_commit += 1;
                                batch.push(build_meta_doc_record(sr2, &e2, &vp2));
                                continue;
                            }
                            if is_inproc_text_eligible(&e2, options.parse.max_single_file_bytes) {
                                text_group.push((sr2, e2));
                            } else {
                                deferred_stage1_nonbatch = Some((sr2, e2));
                                break;
                            }
                        }
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                            discovery_open = false;
                            break;
                        }
                    }
                }
                let st_clone = state.clone();
                let parse_opts = fast_parse_opts.clone();
                join_set.spawn(async move {
                    dispatch_inproc_text_batch_task(st_clone, text_group, parse_opts, timeout).await
                });
                continue;
            }

            // Lane C: Small binary/Office/DWG batch via sandboxed parser-worker (16 items per IPC call)
            if !low_res && is_batchable_small_file(&entry, options.parse.max_single_file_bytes) {
                let mut group = Vec::with_capacity(16);
                group.push((source_root, entry));
                while group.len() < 16 && !cancel.load(Ordering::SeqCst) {
                    match disc_rx.try_recv() {
                        Ok((sr2, e2)) => {
                            scanned_files += 1;
                            let vp2 = e2.disk_path.to_string_lossy().into_owned();
                            if let Some(&(cid2, osz2, omt2, ref st2)) = snapshot.get(&vp2) {
                                let ready2 = st2 == "ok"
                                    || (st2 == "pending_ocr" && (!two_phase_ocr || queued_doc_ids.contains(&cid2)))
                                    || (st2 == "encrypted" && options.parse.passwords.is_empty())
                                    || (st2 != "ok" && st2 != "encrypted" && st2 != "pending_ocr");
                                if osz2 == e2.byte_size && omt2 == e2.mtime_ns && ready2 {
                                    skipped_cached += 1;
                                    if st2 == "ok" && compiled_rules.is_some() {
                                        cached_eval_ids.push(cid2);
                                    }
                                    continue;
                                }
                            }
                            if !is_priority_core_doc_ext(&e2.ext_lower) {
                                other_queue.push((sr2, e2));
                                continue;
                            }
                            if is_metadata_only_binary_ext(&e2.ext_lower)
                                || e2.byte_size > options.parse.max_single_file_bytes
                            {
                                parsed_ok += 1;
                                since_last_commit += 1;
                                batch.push(build_meta_doc_record(sr2, &e2, &vp2));
                                continue;
                            }
                            if !is_heavy_file(&e2)
                                && !is_inproc_text_eligible(&e2, options.parse.max_single_file_bytes)
                                && is_batchable_small_file(&e2, options.parse.max_single_file_bytes)
                            {
                                group.push((sr2, e2));
                            } else {
                                deferred_stage1_nonbatch = Some((sr2, e2));
                                break;
                            }
                        }
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                            discovery_open = false;
                            break;
                        }
                    }
                }
                let st_clone = state.clone();
                let parse_opts = fast_parse_opts.clone();
                join_set.spawn(async move {
                    if group.len() == 1 {
                        let (sr, ent) = group.pop().unwrap();
                        vec![dispatch_parse_task(st_clone, sr, ent, parse_opts, timeout).await]
                    } else {
                        dispatch_parse_batch_task(st_clone, group, parse_opts, timeout).await
                    }
                });
            } else {
                let st_clone = state.clone();
                let parse_opts = fast_parse_opts.clone();
                join_set.spawn(async move {
                    vec![dispatch_parse_task(st_clone, source_root, entry, parse_opts, timeout).await]
                });
            }
        }

        // If only deferred heavy tasks remain in Stage 1, wait directly for a heavy permit when idle
        if join_set.is_empty()
            && !deferred_heavy_s1.is_empty()
            && !cancel.load(Ordering::SeqCst)
        {
            if let Ok(permit) = heavy_sem.clone().acquire_owned().await {
                let (sr, ent) = deferred_heavy_s1.pop_front().unwrap();
                let st_clone = state.clone();
                let parse_opts = fast_parse_opts.clone();
                join_set.spawn(async move {
                    let _p = permit;
                    vec![dispatch_parse_task(st_clone, sr, ent, parse_opts, timeout).await]
                });
            }
        }

        if let Some(joined) = join_set.join_next().await {
            if let Ok(results) = joined {
                let mut last_vp = String::new();
                for (source_root, entry, resp) in results {
                    last_vp = entry.disk_path.to_string_lossy().into_owned();
                    absorb_worker_parse_response(
                        &source_root,
                        &entry,
                        resp,
                        two_phase_ocr,
                        &options.parse.passwords,
                        &mut parsed_ok,
                        &mut child_docs_indexed,
                        &mut encrypted_files,
                        &mut failed_files,
                        &mut since_last_commit,
                        &mut batch,
                        &mut pending_ocr_cache,
                    );
                }

                if batch.len() >= batch_flush_len || pending_ocr_cache.len() >= 32 {
                    let drained = std::mem::take(&mut batch);
                    let ocr_drained = std::mem::take(&mut pending_ocr_cache);
                    let _ = idx_tx.send(IndexPipelineMsg::Flush(drained, ocr_drained)).await;
                }
                if since_last_commit >= commit_every_docs {
                    since_last_commit = 0;
                    let _ = idx_tx.send(IndexPipelineMsg::Commit).await;
                }
                if low_res {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                if !last_vp.is_empty() && last_progress.elapsed() >= Duration::from_millis(200) {
                    last_progress = Instant::now();
                    try_send_progress(
                        &tx,
                        DaemonMessage::ScanProgress {
                            job_id: job_id.clone(),
                            scanned_files,
                            parsed_ok,
                            skipped_cached,
                            encrypted_files,
                            failed_files,
                            current_path: last_vp,
                            elapsed_ms: t0.elapsed().as_millis() as u64,
                            phase: "fast".into(),
                            ocr_pending: 0,
                            ocr_done: 0,
                        },
                    );
                }
            }
        } else if (discovery_open || deferred_stage1_nonbatch.is_some()) && !cancel.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        } else {
            break;
        }
    }

    let (usn_updates, removed_via_usn) = disc_handle.await.unwrap_or_default();

    if !cached_eval_ids.is_empty() {
        if let Some(ref compiled) = compiled_rules {
            let st_eval = state.store.clone();
            let comp_eval = compiled.clone();
            let hits = tokio::task::spawn_blocking(move || {
                st_eval
                    .evaluate_rules_over_store(&comp_eval, Some(&cached_eval_ids))
                    .unwrap_or_default()
            })
            .await
            .unwrap_or_default();
            for hit in hits {
                rule_hits += 1;
                send_with_timeout(
                    &tx,
                    DaemonMessage::ScanHit {
                        job_id: job_id.clone(),
                        hit,
                    },
                )
                .await;
            }
        }
    }

    if !batch.is_empty() || !pending_ocr_cache.is_empty() {
        let drained = std::mem::take(&mut batch);
        let ocr_drained = std::mem::take(&mut pending_ocr_cache);
        let _ = idx_tx.send(IndexPipelineMsg::Flush(drained, ocr_drained)).await;
    }

    let queued_ocr_after_core = if !cancel.load(Ordering::SeqCst) {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        if idx_tx.send(IndexPipelineMsg::Sync(done_tx)).await.is_ok() {
            rule_hits += done_rx.await.unwrap_or(0);
        }
        since_last_commit = 0;
        let st_c = state.store.clone();
        tokio::task::spawn_blocking(move || st_c.count_pending_ocr_tasks().unwrap_or(0))
            .await
            .unwrap_or(0)
    } else {
        0
    };
    let est_img_in_other = other_queue
        .iter()
        .filter(|(_, e)| two_phase_ocr && is_ocr_image_ext(&e.ext_lower))
        .count() as u64;
    let total_deferred_hint = queued_ocr_after_core + est_img_in_other;

    // Notify UI right after Word/Excel/PPT/PDF/TXT/DWG/Archives finish so rushed users can search immediately!
    if (!other_queue.is_empty() || queued_ocr_after_core > 0) && !cancel.load(Ordering::SeqCst) {
        send_with_timeout(
            &tx,
            DaemonMessage::ScanFastPassCompleted {
                job_id: job_id.clone(),
                fast_parsed_ok: parsed_ok,
                skipped_cached,
                deferred_ocr_count: total_deferred_hint,
                elapsed_ms: t0.elapsed().as_millis() as u64,
            },
        )
        .await;
    }

    // Stage 2 (Other Non-OCR Pass): index code/html/xml/chm/metadata binaries and enqueue standalone image files
    if !other_queue.is_empty() && !cancel.load(Ordering::SeqCst) {
        let mut other_iter = other_queue.into_iter().peekable();
        let mut deferred_heavy_s2: VecDeque<(String, DiscoveredFile)> = VecDeque::new();
        loop {
            while join_set.len() < max_in_flight && !cancel.load(Ordering::SeqCst) {
                if !deferred_heavy_s2.is_empty() {
                    if let Ok(permit) = heavy_sem.clone().try_acquire_owned() {
                        let (sr, ent) = deferred_heavy_s2.pop_front().unwrap();
                        let st_clone = state.clone();
                        let parse_opts = fast_parse_opts.clone();
                        join_set.spawn(async move {
                            let _p = permit;
                            vec![dispatch_parse_task(st_clone, sr, ent, parse_opts, timeout).await]
                        });
                        continue;
                    }
                }

                let Some((src_root, entry)) = other_iter.next() else {
                    break;
                };
                let vp_fast = entry.disk_path.to_string_lossy().into_owned();
                if is_metadata_only_binary_ext(&entry.ext_lower)
                    || entry.byte_size > options.parse.max_single_file_bytes
                    || (two_phase_ocr && is_ocr_image_ext(&entry.ext_lower))
                {
                    let defer_img = two_phase_ocr && is_ocr_image_ext(&entry.ext_lower);
                    let hash_key = format!("meta:{vp_fast}:{}", entry.byte_size);
                    let warn = if defer_img {
                        "图片已完成文件名索引，等待后台低负载队列进行 OCR 识图".into()
                    } else if entry.byte_size > options.parse.max_single_file_bytes {
                        format!(
                            "文件体积 ({:.1} MB) 超过单文件深解析上限，已保留文件名与属性索引",
                            entry.byte_size as f64 / (1024.0 * 1024.0)
                        )
                    } else {
                        "二进制程序/系统/大型三维组件，已仅建立文件名与属性索引".into()
                    };
                    let meta_doc = build_metadata_only_doc(
                        entry.file_name.clone(),
                        &vp_fast,
                        &entry.ext_lower,
                        entry.byte_size,
                        blake3_bytes(hash_key.as_bytes()),
                        warn,
                    );
                    parsed_ok += 1;
                    since_last_commit += 1;
                    let row_status = if defer_img { "pending_ocr" } else { "ok" }.to_string();
                    let defer_meta = defer_img.then(|| DeferredFlushMeta {
                        outer_vp: vp_fast.clone(),
                        outer_disk_path: vp_fast.clone(),
                        passwords: Vec::new(),
                        deferred_images: Vec::new(),
                        deferred_pdf_pages: Vec::new(),
                        pure_image_file: Some((vp_fast.clone(), entry.file_name.clone())),
                    });
                    batch.push((src_root, meta_doc, entry.mtime_ns, row_status, defer_meta));
                    if batch.len() >= batch_flush_len {
                        let drained = std::mem::take(&mut batch);
                        let ocr_drained = std::mem::take(&mut pending_ocr_cache);
                        let _ = idx_tx.send(IndexPipelineMsg::Flush(drained, ocr_drained)).await;
                    }
                    if since_last_commit >= commit_every_docs {
                        since_last_commit = 0;
                        let _ = idx_tx.send(IndexPipelineMsg::Commit).await;
                    }
                    if last_progress.elapsed() >= Duration::from_millis(200) {
                        last_progress = Instant::now();
                        try_send_progress(
                            &tx,
                            DaemonMessage::ScanProgress {
                                job_id: job_id.clone(),
                                scanned_files,
                                parsed_ok,
                                skipped_cached,
                                encrypted_files,
                                failed_files,
                                current_path: vp_fast,
                                elapsed_ms: t0.elapsed().as_millis() as u64,
                                phase: "other".into(),
                                ocr_pending: total_deferred_hint,
                                ocr_done: 0,
                            },
                        );
                    }
                    continue;
                }

                if is_heavy_file(&entry) {
                    if let Ok(permit) = heavy_sem.clone().try_acquire_owned() {
                        let st_clone = state.clone();
                        let parse_opts = fast_parse_opts.clone();
                        join_set.spawn(async move {
                            let _p = permit;
                            vec![dispatch_parse_task(st_clone, src_root, entry, parse_opts, timeout).await]
                        });
                    } else {
                        deferred_heavy_s2.push_back((src_root, entry));
                    }
                    continue;
                }

                if is_inproc_text_eligible(&entry, options.parse.max_single_file_bytes) {
                    let mut text_group = Vec::with_capacity(16);
                    text_group.push((src_root, entry));
                    while text_group.len() < 16 {
                        let can_take = other_iter.peek().is_some_and(|(_, e2)| {
                            !(two_phase_ocr && is_ocr_image_ext(&e2.ext_lower))
                                && is_inproc_text_eligible(e2, options.parse.max_single_file_bytes)
                        });
                        if can_take {
                            text_group.push(other_iter.next().unwrap());
                        } else {
                            break;
                        }
                    }
                    let st_clone = state.clone();
                    let parse_opts = fast_parse_opts.clone();
                    join_set.spawn(async move {
                        dispatch_inproc_text_batch_task(st_clone, text_group, parse_opts, timeout).await
                    });
                    continue;
                }

                if !low_res && is_batchable_small_file(&entry, options.parse.max_single_file_bytes) {
                    let mut group = Vec::with_capacity(16);
                    group.push((src_root, entry));
                    while group.len() < 16 {
                        let can_take = other_iter.peek().is_some_and(|(_, e2)| {
                            !(two_phase_ocr && is_ocr_image_ext(&e2.ext_lower))
                                && !is_heavy_file(e2)
                                && !is_inproc_text_eligible(e2, options.parse.max_single_file_bytes)
                                && is_batchable_small_file(e2, options.parse.max_single_file_bytes)
                        });
                        if can_take {
                            group.push(other_iter.next().unwrap());
                        } else {
                            break;
                        }
                    }
                    let st_clone = state.clone();
                    let parse_opts = fast_parse_opts.clone();
                    join_set.spawn(async move {
                        if group.len() == 1 {
                            let (sr, ent) = group.pop().unwrap();
                            vec![dispatch_parse_task(st_clone, sr, ent, parse_opts, timeout).await]
                        } else {
                            dispatch_parse_batch_task(st_clone, group, parse_opts, timeout).await
                        }
                    });
                } else {
                    let st_clone = state.clone();
                    let parse_opts = fast_parse_opts.clone();
                    join_set.spawn(async move {
                        vec![dispatch_parse_task(st_clone, src_root, entry, parse_opts, timeout).await]
                    });
                }
            }

            if join_set.is_empty()
                && !deferred_heavy_s2.is_empty()
                && !cancel.load(Ordering::SeqCst)
            {
                if let Ok(permit) = heavy_sem.clone().acquire_owned().await {
                    let (sr, ent) = deferred_heavy_s2.pop_front().unwrap();
                    let st_clone = state.clone();
                    let parse_opts = fast_parse_opts.clone();
                    join_set.spawn(async move {
                        let _p = permit;
                        vec![dispatch_parse_task(st_clone, sr, ent, parse_opts, timeout).await]
                    });
                }
            }

            let Some(joined) = join_set.join_next().await else {
                break;
            };
            let Ok(results) = joined else {
                continue;
            };
            let mut last_vp = String::new();
            for (source_root, entry, resp) in results {
                last_vp = entry.disk_path.to_string_lossy().into_owned();
                absorb_worker_parse_response(
                    &source_root,
                    &entry,
                    resp,
                    two_phase_ocr,
                    &options.parse.passwords,
                    &mut parsed_ok,
                    &mut child_docs_indexed,
                    &mut encrypted_files,
                    &mut failed_files,
                    &mut since_last_commit,
                    &mut batch,
                    &mut pending_ocr_cache,
                );
            }

            if batch.len() >= batch_flush_len || pending_ocr_cache.len() >= 32 {
                let drained = std::mem::take(&mut batch);
                let ocr_drained = std::mem::take(&mut pending_ocr_cache);
                let _ = idx_tx.send(IndexPipelineMsg::Flush(drained, ocr_drained)).await;
            }
            if since_last_commit >= commit_every_docs {
                since_last_commit = 0;
                let _ = idx_tx.send(IndexPipelineMsg::Commit).await;
            }
            if low_res {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if !last_vp.is_empty() && last_progress.elapsed() >= Duration::from_millis(200) {
                last_progress = Instant::now();
                try_send_progress(
                    &tx,
                    DaemonMessage::ScanProgress {
                        job_id: job_id.clone(),
                        scanned_files,
                        parsed_ok,
                        skipped_cached,
                        encrypted_files,
                        failed_files,
                        current_path: last_vp,
                        elapsed_ms: t0.elapsed().as_millis() as u64,
                        phase: "other".into(),
                        ocr_pending: total_deferred_hint,
                        ocr_done: 0,
                    },
                );
            }
        }

        if !batch.is_empty() || !pending_ocr_cache.is_empty() {
            let drained = std::mem::take(&mut batch);
            let ocr_drained = std::mem::take(&mut pending_ocr_cache);
            let _ = idx_tx.send(IndexPipelineMsg::Flush(drained, ocr_drained)).await;
        }
    }

    drop(idx_tx);
    rule_hits += indexer_handle.await.unwrap_or(0);

    // Stage 3 (Unified Deduplicated Background OCR Pass): standalone images + extracted embedded images + 8-page PDF batches
    if two_phase_ocr && !cancel.load(Ordering::SeqCst) {
        let st_load = state.store.clone();
        let pending_tasks = tokio::task::spawn_blocking(move || {
            let _ = st_load.commit();
            st_load.load_pending_ocr_tasks().unwrap_or_default()
        })
        .await
        .unwrap_or_default();

        if !pending_tasks.is_empty() {
            // Release extra parser workers down to 1 so background OCR keeps RAM/CPU low while user searches
            state.parser_pool.shrink_idle(1).await;

            // Group staged_image tasks by `img_blake3` so duplicate embedded images OCR exactly once across all docs
            let mut staged_groups: HashMap<String, Vec<PendingOcrTaskRow>> = HashMap::new();
            let mut unit_queue: Vec<OcrExecutionUnit> = Vec::new();
            for row in pending_tasks {
                if row.kind == "staged_image" && !row.img_blake3.is_empty() {
                    staged_groups
                        .entry(row.img_blake3.clone())
                        .or_default()
                        .push(row);
                } else if row.kind == "pdf_pages" {
                    unit_queue.push(OcrExecutionUnit::PdfPages(row));
                } else {
                    unit_queue.push(OcrExecutionUnit::ImageFile(row));
                }
            }
            for (_h, rows) in staged_groups {
                unit_queue.push(OcrExecutionUnit::StagedGroup(rows));
            }

            let ocr_total = unit_queue.len() as u64;
            let mut ocr_done = 0u64;
            let mut since_ocr_commit = 0u64;
            let ocr_timeout = Duration::from_secs(300);

            for unit in unit_queue {
                if cancel.load(Ordering::SeqCst) {
                    break;
                }
                let display_path = execute_ocr_unit(
                    &state,
                    &unit,
                    options.parse.ocr_min_image_dim,
                    ocr_timeout,
                    &compiled_rules,
                    &tx,
                    &job_id,
                    &mut rule_hits,
                )
                .await;
                ocr_done += 1;
                since_ocr_commit += 1;

                if since_ocr_commit >= 16 {
                    since_ocr_commit = 0;
                    let st_commit = state.store.clone();
                    let _ = tokio::task::spawn_blocking(move || st_commit.commit()).await;
                }
                if low_res {
                    tokio::time::sleep(Duration::from_millis(120)).await;
                }

                if last_progress.elapsed() >= Duration::from_millis(200) || ocr_done == ocr_total {
                    last_progress = Instant::now();
                    try_send_progress(
                        &tx,
                        DaemonMessage::ScanProgress {
                            job_id: job_id.clone(),
                            scanned_files,
                            parsed_ok,
                            skipped_cached,
                            encrypted_files,
                            failed_files,
                            current_path: display_path,
                            elapsed_ms: t0.elapsed().as_millis() as u64,
                            phase: "ocr".into(),
                            ocr_pending: ocr_total,
                            ocr_done,
                        },
                    );
                }
            }
        }
    }

    let cancelled = cancel.load(Ordering::SeqCst);
    let st_commit = state.store.clone();
    let should_prune = parsed_ok > 0 || removed_via_usn > 0;
    let _ = tokio::task::spawn_blocking(move || {
        let _ = st_commit.commit_and_release();
        if should_prune {
            let _ = st_commit.prune_orphaned_blobs();
        }
        if !cancelled {
            for (drive_root, jid, next_usn) in usn_updates {
                let _ = st_commit.set_usn_checkpoint(&drive_root, jid, next_usn);
            }
        }
    })
    .await;

    finish_job_and_shrink(&state, &job_id).await;

    send_with_timeout(
        &tx,
        DaemonMessage::ScanCompleted {
            job_id: job_id.clone(),
            summary: ScanSummary {
                job_id,
                scanned_files,
                parsed_ok,
                child_docs_indexed,
                skipped_cached,
                encrypted_files,
                failed_files,
                rule_hits,
                cancelled,
                elapsed_ms: t0.elapsed().as_millis() as u64,
            },
        },
    )
    .await;
}

async fn preempt_other_active_jobs(
    state: &Arc<DaemonState>,
    self_job_id: &str,
    cancel: &AtomicBool,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let others_left = {
            let jobs = state.active_jobs.lock().await;
            for (id, flag) in jobs.iter() {
                if id != self_job_id {
                    flag.store(true, Ordering::SeqCst);
                }
            }
            jobs.keys().any(|id| id != self_job_id)
        };
        if !others_left || cancel.load(Ordering::SeqCst) || Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}

fn build_direct_search_ruleset(
    query: &str,
    use_regex: bool,
    match_all_terms: bool,
) -> Result<CompiledRuleSet, String> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err("direct search query must not be empty".into());
    }

    let expression = if use_regex {
        if trimmed.starts_with("re:/") {
            trimmed.to_string()
        } else {
            // Escape unescaped forward slashes so parser accepts arbitrary regex syntax
            let mut esc = String::with_capacity(trimmed.len() + 8);
            let mut backslashes = 0usize;
            for ch in trimmed.chars() {
                if ch == '\\' {
                    backslashes += 1;
                    esc.push(ch);
                } else {
                    if ch == '/' && backslashes % 2 == 0 {
                        esc.push('\\');
                    }
                    backslashes = 0;
                    esc.push(ch);
                }
            }
            format!("re:/{esc}/i")
        }
    } else if !trimmed.contains(['&', '|', '!', '(', ')', ':', '"'])
        && !trimmed.contains("re:/")
        && !trimmed.to_ascii_uppercase().contains(" AND ")
        && !trimmed.to_ascii_uppercase().contains(" OR ")
        && !trimmed.to_ascii_uppercase().contains(" NOT ")
    {
        let sep = if match_all_terms { " & " } else { " | " };
        trimmed
            .split_whitespace()
            .map(|t| {
                let safe = t.replace('\\', "\\\\").replace('"', "\\\"");
                format!("\"{safe}\"")
            })
            .collect::<Vec<_>>()
            .join(sep)
    } else {
        trimmed.to_string()
    };

    let rs = RuleSet {
        ruleset_id: format!("direct-{}", blake3_bytes_hex(expression.as_bytes())),
        rules: vec![RuleDefinition {
            id: "direct-search".into(),
            name: format!("深度直查: {trimmed}"),
            category: "DirectSearch".into(),
            severity: "Match".into(),
            expression,
            mode: RuleMatchMode::FullHits,
        }],
    };
    CompiledRuleSet::compile(&rs).map_err(|e| e.to_string())
}

fn blake3_bytes_hex(bytes: &[u8]) -> String {
    let h = blake3_bytes(bytes);
    h[..16.min(h.len())].to_string()
}

fn doc_matches_ext_filter(doc: &ExtractedDocument, exts: &[String]) -> bool {
    if exts.is_empty() {
        return true;
    }
    let file_ext = Path::new(&doc.file_name)
        .extension()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let det = doc.detected_format.to_ascii_lowercase();
    exts.iter().any(|e| e == &file_ext || e == &det)
}

#[allow(clippy::too_many_arguments)]
async fn run_direct_search_job(
    state: Arc<DaemonState>,
    job_id: String,
    roots: Vec<String>,
    compiled: Arc<CompiledRuleSet>,
    file_ext_filter: Option<String>,
    options: ScanOptions,
    cancel_active_jobs: bool,
    cancel: Arc<AtomicBool>,
    tx: mpsc::Sender<DaemonMessage>,
) {
    let t0 = Instant::now();
    if cancel_active_jobs {
        preempt_other_active_jobs(&state, &job_id, &cancel).await;
    }
    warm_worker_pools(&state).await;

    let ext_filters: Vec<String> = file_ext_filter
        .as_deref()
        .unwrap_or("")
        .split([',', ';', ' '])
        .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let mut enum_opts = options.clone();
    if !ext_filters.is_empty() && enum_opts.include_extensions.is_empty() {
        let mut allowed = ext_filters.clone();
        // Still traverse containers so matching nested files (e.g. .docx inside .zip) are found
        for arch in ["zip", "7z", "tar", "gz", "bz2", "xz", "zst", "cab", "iso", "eml", "msg", "pst", "ost"] {
            if !allowed.iter().any(|e| e == arch) {
                allowed.push(arch.into());
            }
        }
        enum_opts.include_extensions = allowed;
    }

    let discovered = tokio::task::spawn_blocking(move || {
        enumerate_roots_with_options(&roots, &enum_opts)
    })
    .await
    .unwrap_or_default();

    let scanned_files = discovered.len() as u64;
    let mut parsed_ok = 0u64;
    let mut child_docs_indexed = 0u64;
    let mut encrypted_files = 0u64;
    let mut failed_files = 0u64;
    let mut rule_hits = 0u64;

    let mut timeout = Duration::from_millis(options.worker_timeout_ms.max(2_000));
    if options.parse.enable_ocr {
        timeout = timeout.max(Duration::from_secs(300));
    }
    let low_res = options.low_resource_mode;
    state.parser_pool.set_low_resource(low_res).await;
    if let Some(ep) = &state.ext_pool {
        ep.set_low_resource(low_res).await;
    }
    let max_in_flight = if low_res {
        1
    } else {
        (state.worker_count.min(options.worker_count.max(1)) * 2).clamp(4, 8)
    };
    let mut join_set = tokio::task::JoinSet::new();
    let mut iter = discovered.into_iter();
    let mut last_progress = Instant::now();

    loop {
        while join_set.len() < max_in_flight && !cancel.load(Ordering::SeqCst) {
            let Some(entry) = iter.next() else {
                break;
            };
            let st_clone = state.clone();
            let parse_opts = options.parse.clone();
            join_set.spawn(async move {
                dispatch_parse_task(st_clone, String::new(), entry, parse_opts, timeout).await
            });
        }

        let Some(joined) = join_set.join_next().await else {
            break;
        };
        let Ok((_, entry, resp)) = joined else {
            continue;
        };
        let vp = entry.disk_path.to_string_lossy().into_owned();

        match resp {
            WorkerResponse::Parsed { doc, child_docs, .. } => {
                parsed_ok += 1;
                if doc.encrypted {
                    encrypted_files += 1;
                }
                let child_count = child_docs.len() as u64;
                child_docs_indexed += child_count;
                for cdoc in std::iter::once(doc).chain(child_docs.into_iter()) {
                    if cdoc.encrypted {
                        encrypted_files += 1;
                    }
                    if !doc_matches_ext_filter(&cdoc, &ext_filters) {
                        continue;
                    }
                    let provisional_id = state.next_ephemeral_id.fetch_add(1, Ordering::Relaxed);
                    let (mut hits, _) = compiled.evaluate_document(provisional_id, &cdoc, 5);
                    if !hits.is_empty() {
                        let mod_ms = entry.mtime_ns / 1_000_000;
                        {
                            let mut eph = state.ephemeral_docs.lock().await;
                            if eph.len() >= 2_000 {
                                if let Some(&oldest) = eph.keys().min() {
                                    eph.remove(&oldest);
                                }
                            }
                            eph.insert(provisional_id, cdoc);
                        }
                        for hit in &mut hits {
                            hit.modified_unix_ms = mod_ms;
                        }
                        for hit in hits {
                            rule_hits += 1;
                            send_with_timeout(
                                &tx,
                                DaemonMessage::ScanHit {
                                    job_id: job_id.clone(),
                                    hit,
                                },
                            )
                            .await;
                        }
                    }
                }
            }
            WorkerResponse::Failed { .. } => {
                failed_files += 1;
            }
            WorkerResponse::Health { .. }
            | WorkerResponse::OcrCacheWarmed { .. }
            | WorkerResponse::OcrCompleted { .. }
            | WorkerResponse::ParsedBatch { .. } => {}
        }

        if last_progress.elapsed() >= Duration::from_millis(200) {
            last_progress = Instant::now();
            try_send_progress(
                &tx,
                DaemonMessage::ScanProgress {
                    job_id: job_id.clone(),
                    scanned_files,
                    parsed_ok,
                    skipped_cached: 0,
                    encrypted_files,
                    failed_files,
                    current_path: vp,
                    elapsed_ms: t0.elapsed().as_millis() as u64,
                    phase: "direct".into(),
                    ocr_pending: 0,
                    ocr_done: 0,
                },
            );
        }
    }

    finish_job_and_shrink(&state, &job_id).await;
    let cancelled = cancel.load(Ordering::SeqCst);

    send_with_timeout(
        &tx,
        DaemonMessage::ScanCompleted {
            job_id: job_id.clone(),
            summary: ScanSummary {
                job_id,
                scanned_files,
                parsed_ok,
                child_docs_indexed,
                skipped_cached: 0,
                encrypted_files,
                failed_files,
                rule_hits,
                cancelled,
                elapsed_ms: t0.elapsed().as_millis() as u64,
            },
        },
    )
    .await;
}

fn is_ext_worker_ext(ext: &str) -> bool {
    matches!(ext, "pst" | "ost" | "chm" | "djvu" | "shp")
}

fn is_heavy_file(entry: &DiscoveredFile) -> bool {
    entry.byte_size > 4 * 1024 * 1024
        || matches!(
            entry.ext_lower.as_str(),
            "zip" | "7z" | "rar" | "tar" | "gz" | "bz2" | "xz" | "zst" | "cab" | "iso" | "eml" | "mbox" | "msg" | "pst" | "ost"
        )
        || (entry.ext_lower == "pdf" && entry.byte_size > 1_500_000)
}

fn is_safe_plain_text_ext(ext: &str) -> bool {
    matches!(
        ext,
        "txt"
            | "md"
            | "markdown"
            | "log"
            | "json"
            | "jsonl"
            | "ndjson"
            | "geojson"
            | "yaml"
            | "yml"
            | "toml"
            | "ini"
            | "cfg"
            | "conf"
            | "env"
            | "properties"
            | "rs"
            | "py"
            | "js"
            | "ts"
            | "tsx"
            | "jsx"
            | "mjs"
            | "cjs"
            | "cs"
            | "c"
            | "cc"
            | "cpp"
            | "cxx"
            | "h"
            | "hpp"
            | "java"
            | "go"
            | "rb"
            | "php"
            | "sql"
            | "sh"
            | "bash"
            | "zsh"
            | "ps1"
            | "bat"
            | "cmd"
            | "css"
            | "scss"
            | "less"
            | "vue"
            | "svelte"
            | "tex"
    )
}

fn is_inproc_text_eligible(entry: &DiscoveredFile, max_single: u64) -> bool {
    is_safe_plain_text_ext(&entry.ext_lower)
        && entry.byte_size <= (2 * 1024 * 1024).min(max_single)
}

fn is_plain_text_bytes_safe(bytes: &[u8]) -> bool {
    if bytes.starts_with(b"%PDF-")
        || bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"Rar!")
        || bytes.starts_with(b"7z\xBC\xAF")
        || bytes.starts_with(b"\xD0\xCF\x11\xE0")
        || bytes.starts_with(b"\x89PNG")
        || bytes.starts_with(b"\xFF\xD8\xFF")
        || bytes.starts_with(b"GIF8")
        || bytes.starts_with(b"MZ")
        || bytes.starts_with(b"AC10")
    {
        return false;
    }
    let has_utf16_bom = bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]);
    if !has_utf16_bom && bytes[..bytes.len().min(1024)].contains(&0) {
        return false;
    }
    true
}

fn decode_text_fast(bytes: &[u8]) -> (String, &'static str) {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        let (s, _, _) = encoding_rs::UTF_8.decode(&bytes[3..]);
        return (s.into_owned(), "utf-8-bom");
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let (s, _, _) = encoding_rs::UTF_16LE.decode(&bytes[2..]);
        return (s.into_owned(), "utf-16le");
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let (s, _, _) = encoding_rs::UTF_16BE.decode(&bytes[2..]);
        return (s.into_owned(), "utf-16be");
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return (s.to_string(), "utf-8");
    }
    let mut det = chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Deny);
    det.feed(&bytes[..bytes.len().min(64 * 1024)], true);
    let enc = det.guess(None, chardetng::Utf8Detection::Allow);
    let (decoded, _, _) = enc.decode(bytes);
    (decoded.into_owned(), enc.name())
}

fn build_head_tail_fast(text: &str) -> Option<TextSegment> {
    let base = text.as_ptr() as usize;
    let mut out = String::new();
    let mut head_count = 0usize;
    let mut head_end_byte = 0usize;
    for raw in text.lines() {
        let l = raw.trim();
        if l.is_empty() {
            continue;
        }
        out.push_str(l);
        out.push('\n');
        head_count += 1;
        if head_count >= 10 {
            head_end_byte = (raw.as_ptr() as usize - base + raw.len()).min(text.len());
            break;
        }
    }
    if head_count == 0 {
        return None;
    }
    if head_count >= 10 && head_end_byte < text.len() {
        let rest = &text[head_end_byte..];
        let mut tail_rev: Vec<&str> = Vec::with_capacity(10);
        for raw in rest.rsplit('\n') {
            let l = raw.trim();
            if l.is_empty() {
                continue;
            }
            tail_rev.push(l);
            if tail_rev.len() >= 10 {
                break;
            }
        }
        for l in tail_rev.into_iter().rev() {
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

fn try_parse_safe_text_inproc(entry: &DiscoveredFile, vp: &str, task_id: u64) -> Option<WorkerResponse> {
    let bytes = match std::fs::read(&entry.disk_path) {
        Ok(b) => b,
        Err(e)
            if e.kind() == std::io::ErrorKind::PermissionDenied
                || matches!(e.raw_os_error(), Some(5 | 32 | 33)) =>
        {
            let key = format!("meta:{vp}:0");
            return Some(WorkerResponse::Parsed {
                task_id,
                doc: build_metadata_only_doc(
                    entry.file_name.clone(),
                    vp,
                    &entry.ext_lower,
                    entry.byte_size,
                    blake3_bytes(key.as_bytes()),
                    format!("文件正被其它程序独占锁定 ({e})，已仅保留文件名与属性索引"),
                ),
                child_docs: Vec::new(),
                new_ocr_entries: Vec::new(),
                deferred_images: Vec::new(),
                deferred_pdf_pages: Vec::new(),
            });
        }
        Err(_) => return None,
    };

    if !is_plain_text_bytes_safe(&bytes) {
        return None;
    }

    let blake3_hex = blake3_bytes(&bytes);
    let (txt, enc) = decode_text_fast(&bytes);
    let detected_format = match entry.ext_lower.as_str() {
        "json" | "jsonl" | "ndjson" => "json",
        "geojson" => "geojson",
        "md" | "markdown" => "md",
        _ => "txt",
    };

    let mut segments = Vec::with_capacity(2);
    if let Some(ht) = build_head_tail_fast(&txt) {
        segments.push(ht);
    }
    if !txt.trim().is_empty() {
        segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: format!("{} 正文", detected_format.to_ascii_uppercase()),
            text: txt,
        });
    }

    let doc = ExtractedDocument {
        virtual_path: vp.to_string(),
        file_name: entry.file_name.clone(),
        detected_format: detected_format.to_string(),
        blake3_hex,
        byte_size: bytes.len() as u64,
        encrypted: false,
        segments,
        metadata: vec![("encoding".into(), enc.into())],
        warnings: Vec::new(),
    };
    Some(WorkerResponse::Parsed {
        task_id,
        doc,
        child_docs: Vec::new(),
        new_ocr_entries: Vec::new(),
        deferred_images: Vec::new(),
        deferred_pdf_pages: Vec::new(),
    })
}

async fn dispatch_inproc_text_batch_task(
    state: Arc<DaemonState>,
    group: Vec<(String, DiscoveredFile)>,
    parse_opts: deepdoc_protocol::ParseOptions,
    timeout: Duration,
) -> Vec<(String, DiscoveredFile, WorkerResponse)> {
    let task_base = state.next_task_id.fetch_add(group.len() as u64, Ordering::Relaxed);
    let (parsed_results, fallbacks) = tokio::task::spawn_blocking(move || {
        let mut ready = Vec::with_capacity(group.len());
        let mut need_worker = Vec::new();
        for (i, (sr, entry)) in group.into_iter().enumerate() {
            let vp = entry.disk_path.to_string_lossy().into_owned();
            if let Some(resp) = try_parse_safe_text_inproc(&entry, &vp, task_base + i as u64) {
                ready.push((sr, entry, resp));
            } else {
                need_worker.push((sr, entry));
            }
        }
        (ready, need_worker)
    })
    .await
    .unwrap_or_default();

    let mut out = parsed_results;
    for (sr, entry) in fallbacks {
        out.push(dispatch_parse_task(state.clone(), sr, entry, parse_opts.clone(), timeout).await);
    }
    out
}

fn is_batchable_small_file(entry: &DiscoveredFile, max_single: u64) -> bool {
    !is_ext_worker_ext(&entry.ext_lower)
        && !is_metadata_only_binary_ext(&entry.ext_lower)
        && entry.byte_size <= (512 * 1024).min(max_single)
}

async fn dispatch_parse_batch_task(
    state: Arc<DaemonState>,
    group: Vec<(String, DiscoveredFile)>,
    parse_opts: deepdoc_protocol::ParseOptions,
    timeout: Duration,
) -> Vec<(String, DiscoveredFile, WorkerResponse)> {
    let task_id = state.next_task_id.fetch_add(1, Ordering::Relaxed);
    let items: Vec<(String, String)> = group
        .iter()
        .map(|(_, e)| {
            let vp = e.disk_path.to_string_lossy().into_owned();
            (vp.clone(), vp)
        })
        .collect();

    let req = WorkerRequest::ParseFilesBatch {
        task_id,
        items,
        options: parse_opts.clone(),
    };
    let batch_timeout = timeout.max(Duration::from_secs(60));
    match state.parser_pool.execute_parse(req, batch_timeout).await {
        WorkerResponse::ParsedBatch { items, .. } if items.len() == group.len() => {
            group
                .into_iter()
                .zip(items)
                .map(|((sr, ent), resp)| {
                    if let WorkerResponse::Failed {
                        kind: FailureKind::InternalError | FailureKind::Timeout | FailureKind::ZipBombTripped,
                        ref detail,
                        ..
                    } = resp
                    {
                        let vp = ent.disk_path.to_string_lossy().into_owned();
                        let hash_key = format!("fallback:{vp}:{}", ent.byte_size);
                        let warn_msg = if detail.contains("ZipBomb") || detail.contains("展开") || detail.contains("膨胀") {
                            "归档解压体积超过安全配额，已仅保留文件名与属性索引".to_string()
                        } else {
                            format!("深解析异常已安全隔离，保留文件名与属性索引 ({detail})")
                        };
                        let fallback_doc = build_metadata_only_doc(
                            ent.file_name.clone(),
                            &vp,
                            &ent.ext_lower,
                            ent.byte_size,
                            blake3_bytes(hash_key.as_bytes()),
                            warn_msg,
                        );
                        (
                            sr,
                            ent,
                            WorkerResponse::Parsed {
                                task_id,
                                doc: fallback_doc,
                                child_docs: Vec::new(),
                                new_ocr_entries: Vec::new(),
                                deferred_images: Vec::new(),
                                deferred_pdf_pages: Vec::new(),
                            },
                        )
                    } else {
                        (sr, ent, resp)
                    }
                })
                .collect()
        }
        _ => {
            // If worker crashed or timed out mid-batch, isolate each item individually so one bad file never hides others
            let mut out = Vec::with_capacity(group.len());
            for (sr, ent) in group {
                out.push(dispatch_parse_task(state.clone(), sr, ent, parse_opts.clone(), timeout).await);
            }
            out
        }
    }
}

async fn dispatch_parse_task(
    state: Arc<DaemonState>,
    source_root: String,
    entry: DiscoveredFile,
    parse_opts: deepdoc_protocol::ParseOptions,
    timeout: Duration,
) -> (String, DiscoveredFile, WorkerResponse) {
    let vp = entry.disk_path.to_string_lossy().into_owned();
    let task_id = state.next_task_id.fetch_add(1, Ordering::Relaxed);
    if is_inproc_text_eligible(&entry, parse_opts.max_single_file_bytes) {
        let entry_c = entry.clone();
        let vp_c = vp.clone();
        if let Ok(Some(inproc_resp)) = tokio::task::spawn_blocking(move || {
            try_parse_safe_text_inproc(&entry_c, &vp_c, task_id)
        })
        .await
        {
            return (source_root, entry, inproc_resp);
        }
    }

    let use_ext = is_ext_worker_ext(&entry.ext_lower) && state.ext_pool.is_some();

    let req = WorkerRequest::ParseFile {
        task_id,
        disk_path: vp.clone(),
        virtual_path: vp.clone(),
        options: parse_opts.clone(),
    };

    let mut resp = if use_ext {
        state
            .ext_pool
            .as_ref()
            .unwrap()
            .execute_parse(req, timeout)
            .await
    } else {
        state.parser_pool.execute_parse(req, timeout).await
    };

    if let WorkerResponse::Failed {
        kind: FailureKind::InternalError | FailureKind::Timeout,
        ref detail,
        ..
    } = resp
    {
        if entry.ext_lower == "dwg" {
            if let Some(ref ep) = state.ext_pool {
                let retry_id = state.next_task_id.fetch_add(1, Ordering::Relaxed);
                let mut dwg_opts = parse_opts.clone();
                dwg_opts.enable_ocr = false;
                let fallback_req = WorkerRequest::ParseFile {
                    task_id: retry_id,
                    disk_path: vp.clone(),
                    virtual_path: vp.clone(),
                    options: dwg_opts,
                };
                resp = ep.execute_parse(fallback_req, timeout).await;
            }
        } else if parse_opts.enable_ocr {
            let retry_id = state.next_task_id.fetch_add(1, Ordering::Relaxed);
            let mut no_ocr_opts = parse_opts;
            no_ocr_opts.enable_ocr = false;
            let retry_req = WorkerRequest::ParseFile {
                task_id: retry_id,
                disk_path: vp.clone(),
                virtual_path: vp.clone(),
                options: no_ocr_opts,
            };
            resp = if use_ext {
                state
                    .ext_pool
                    .as_ref()
                    .unwrap()
                    .execute_parse(retry_req, timeout)
                    .await
            } else {
                state.parser_pool.execute_parse(retry_req, timeout).await
            };
        } else {
            let _ = detail;
        }
    }

    if let WorkerResponse::Failed {
        kind: FailureKind::InternalError | FailureKind::Timeout | FailureKind::ZipBombTripped,
        detail,
        ..
    } = resp
    {
        let hash_key = format!("fallback:{vp}:{}", entry.byte_size);
        let warn_msg = if detail.contains("ZipBomb") || detail.contains("展开") || detail.contains("膨胀") {
            "归档解压体积超过安全配额，已仅保留文件名与属性索引".to_string()
        } else {
            format!("深解析异常已安全隔离，保留文件名与属性索引 ({detail})")
        };
        let fallback_doc = build_metadata_only_doc(
            entry.file_name.clone(),
            &vp,
            &entry.ext_lower,
            entry.byte_size,
            blake3_bytes(hash_key.as_bytes()),
            warn_msg,
        );
        resp = WorkerResponse::Parsed {
            task_id,
            doc: fallback_doc,
            child_docs: Vec::new(),
            new_ocr_entries: Vec::new(),
            deferred_images: Vec::new(),
            deferred_pdf_pages: Vec::new(),
        };
    }

    (source_root, entry, resp)
}

#[allow(clippy::too_many_arguments)]
fn absorb_worker_parse_response(
    source_root: &str,
    entry: &DiscoveredFile,
    resp: WorkerResponse,
    two_phase_ocr: bool,
    passwords: &[String],
    parsed_ok: &mut u64,
    child_docs_indexed: &mut u64,
    encrypted_files: &mut u64,
    failed_files: &mut u64,
    since_last_commit: &mut u64,
    batch: &mut Vec<StagedDocRecord>,
    pending_ocr_cache: &mut Vec<(String, u32, u32, String)>,
) {
    let vp = entry.disk_path.to_string_lossy().into_owned();
    match resp {
        WorkerResponse::Parsed {
            doc,
            child_docs,
            new_ocr_entries,
            deferred_images,
            deferred_pdf_pages,
            ..
        } => {
            *parsed_ok += 1;
            *since_last_commit += 1;
            if doc.encrypted {
                *encrypted_files += 1;
            }
            let outer_vp = doc.virtual_path.clone();
            let mut deferred_targets: std::collections::HashSet<String> =
                deferred_images.iter().map(|d| d.doc_virtual_path.clone()).collect();
            if !deferred_pdf_pages.is_empty() {
                deferred_targets.insert(outer_vp.clone());
            }
            let has_any_deferred = two_phase_ocr && !deferred_targets.is_empty();
            let status = if doc.encrypted {
                "encrypted"
            } else if has_any_deferred && deferred_targets.contains(&doc.virtual_path) {
                "pending_ocr"
            } else {
                "ok"
            }
            .to_string();

            let defer_meta = if has_any_deferred {
                Some(DeferredFlushMeta {
                    outer_vp,
                    outer_disk_path: vp,
                    passwords: passwords.to_vec(),
                    deferred_images,
                    deferred_pdf_pages,
                    pure_image_file: None,
                })
            } else {
                None
            };
            batch.push((source_root.to_string(), doc, entry.mtime_ns, status, defer_meta));

            for cdoc in child_docs {
                *child_docs_indexed += 1;
                *since_last_commit += 1;
                if cdoc.encrypted {
                    *encrypted_files += 1;
                }
                let cstatus = if cdoc.encrypted {
                    "encrypted"
                } else if has_any_deferred && deferred_targets.contains(&cdoc.virtual_path) {
                    "pending_ocr"
                } else {
                    "ok"
                }
                .to_string();
                batch.push((source_root.to_string(), cdoc, entry.mtime_ns, cstatus, None));
            }
            pending_ocr_cache.extend(new_ocr_entries);
        }
        WorkerResponse::Failed { kind, .. } => {
            *failed_files += 1;
            *since_last_commit += 1;
            let err_kind = format!("{kind:?}");
            if let Some(fail_doc) =
                build_failed_doc(&entry.disk_path, &vp, entry.byte_size, &err_kind)
            {
                if fail_doc.encrypted {
                    *encrypted_files += 1;
                }
                batch.push((source_root.to_string(), fail_doc, entry.mtime_ns, err_kind, None));
            }
        }
        WorkerResponse::Health { .. }
        | WorkerResponse::OcrCacheWarmed { .. }
        | WorkerResponse::OcrCompleted { .. }
        | WorkerResponse::ParsedBatch { .. } => {}
    }
}

async fn flush_staged_batch(
    store: Arc<IndexStore>,
    batch: Vec<StagedDocRecord>,
    ocr_entries: Vec<(String, u32, u32, String)>,
    compiled_rules: Option<Arc<CompiledRuleSet>>,
    tx: &mpsc::Sender<DaemonMessage>,
    job_id: &str,
) -> u64 {
    let hits = tokio::task::spawn_blocking(move || {
        if !ocr_entries.is_empty() {
            let _ = store.upsert_ocr_cache_batch(&ocr_entries);
        }
        if batch.is_empty() {
            return Vec::new();
        }
        let refs: Vec<(&str, &ExtractedDocument, i64, &str)> = batch
            .iter()
            .map(|(sr, doc, mt, st, _)| (sr.as_str(), doc, *mt, st.as_str()))
            .collect();
        let Ok(doc_ids) = store.upsert_documents_batch(&refs) else {
            return Vec::new();
        };

        let mut vp_to_doc_id = HashMap::with_capacity(doc_ids.len());
        let mut ready_doc_ids = Vec::new();
        for ((_, doc, _, st, _), &doc_id) in batch.iter().zip(doc_ids.iter()) {
            vp_to_doc_id.insert(doc.virtual_path.clone(), doc_id);
            if st != "pending_ocr" {
                ready_doc_ids.push(doc_id);
            }
        }
        if !ready_doc_ids.is_empty() {
            let _ = store.clear_pending_ocr_for_doc_ids(&ready_doc_ids);
        }

        // Persist extracted Stage-1 deferred OCR images & PDF page chunks into `pending_ocr_queue`
        let staging_dir = store.ocr_staging_dir();
        let mut staging_ready = false;
        let mut ocr_queue_inputs: Vec<PendingOcrTaskInput> = Vec::new();

        for (_, _, _, _, meta_opt) in &batch {
            let Some(meta) = meta_opt else { continue };
            if let Some((ref disk_path, ref label)) = meta.pure_image_file {
                if let Some(&doc_id) = vp_to_doc_id.get(&meta.outer_vp) {
                    ocr_queue_inputs.push(PendingOcrTaskInput {
                        doc_id,
                        kind: "image_file".into(),
                        img_blake3: String::new(),
                        label: label.clone(),
                        source_path: disk_path.clone(),
                        payload_path: String::new(),
                        pages: Vec::new(),
                        passwords: Vec::new(),
                    });
                }
            }

            if !meta.deferred_pdf_pages.is_empty() {
                if let Some(&doc_id) = vp_to_doc_id.get(&meta.outer_vp) {
                    for chunk in meta.deferred_pdf_pages.chunks(8) {
                        ocr_queue_inputs.push(PendingOcrTaskInput {
                            doc_id,
                            kind: "pdf_pages".into(),
                            img_blake3: String::new(),
                            label: format!("PDF 页 {}-{}", chunk.first().unwrap_or(&0) + 1, chunk.last().unwrap_or(&0) + 1),
                            source_path: meta.outer_disk_path.clone(),
                            payload_path: String::new(),
                            pages: chunk.to_vec(),
                            passwords: meta.passwords.clone(),
                        });
                    }
                }
            }

            for img in &meta.deferred_images {
                let target_id = vp_to_doc_id
                    .get(&img.doc_virtual_path)
                    .or_else(|| vp_to_doc_id.get(&meta.outer_vp))
                    .copied();
                let Some(doc_id) = target_id else { continue };
                if !staging_ready {
                    let _ = std::fs::create_dir_all(&staging_dir);
                    staging_ready = true;
                }
                let payload_path = staging_dir.join(format!("{}.bin", img.img_blake3));
                if !payload_path.exists() {
                    if let Some(ref sp) = img.staged_path {
                        if std::fs::rename(sp, &payload_path).is_err() {
                            if let Ok(b) = std::fs::read(sp) {
                                let _ = std::fs::write(&payload_path, b);
                            }
                            let _ = std::fs::remove_file(sp);
                        }
                    } else if !img.data.is_empty() {
                        let _ = std::fs::write(&payload_path, &img.data);
                    }
                } else if let Some(ref sp) = img.staged_path {
                    let _ = std::fs::remove_file(sp);
                }
                if payload_path.exists() {
                    ocr_queue_inputs.push(PendingOcrTaskInput {
                        doc_id,
                        kind: "staged_image".into(),
                        img_blake3: img.img_blake3.clone(),
                        label: img.label.clone(),
                        source_path: meta.outer_disk_path.clone(),
                        payload_path: payload_path.to_string_lossy().into_owned(),
                        pages: Vec::new(),
                        passwords: Vec::new(),
                    });
                }
            }
        }
        if !ocr_queue_inputs.is_empty() {
            let _ = store.enqueue_pending_ocr_tasks(&ocr_queue_inputs);
        }

        let Some(ref compiled) = compiled_rules else {
            return Vec::new();
        };
        let mut all_hits = Vec::new();
        for ((_, doc, mt, _, _), doc_id) in batch.iter().zip(doc_ids.into_iter()) {
            let (mut h, _) = compiled.evaluate_document(doc_id, doc, 5);
            let mod_ms = *mt / 1_000_000;
            for rec in &mut h {
                rec.modified_unix_ms = mod_ms;
            }
            all_hits.extend(h);
        }
        all_hits
    })
    .await
    .unwrap_or_default();

    let count = hits.len() as u64;
    for hit in hits {
        send_with_timeout(
            tx,
            DaemonMessage::ScanHit {
                job_id: job_id.to_string(),
                hit,
            },
        )
        .await;
    }
    count
}

enum OcrExecutionUnit {
    StagedGroup(Vec<PendingOcrTaskRow>),
    ImageFile(PendingOcrTaskRow),
    PdfPages(PendingOcrTaskRow),
}

#[allow(clippy::too_many_arguments)]
async fn execute_ocr_unit(
    state: &Arc<DaemonState>,
    unit: &OcrExecutionUnit,
    min_dim: u32,
    timeout: Duration,
    compiled_rules: &Option<Arc<CompiledRuleSet>>,
    tx: &mpsc::Sender<DaemonMessage>,
    job_id: &str,
    rule_hits: &mut u64,
) -> String {
    let task_id = state.next_task_id.fetch_add(1, Ordering::Relaxed);
    match unit {
        OcrExecutionUnit::StagedGroup(rows) => {
            let first = &rows[0];
            let data = tokio::fs::read(&first.payload_path).await.unwrap_or_default();
            let (segs, warns, new_cache) = if data.is_empty() {
                (Vec::new(), Vec::new(), Vec::new())
            } else {
                let req = WorkerRequest::OcrImageBytes {
                    task_id,
                    label: first.label.clone(),
                    data,
                    min_dim,
                };
                match state.parser_pool.execute_parse(req, timeout).await {
                    WorkerResponse::OcrCompleted {
                        segments,
                        warnings,
                        new_ocr_entries,
                        ..
                    } => (segments, warnings, new_ocr_entries),
                    WorkerResponse::Failed { detail, .. } => (
                        Vec::new(),
                        vec![format!("后台图像 OCR 异常已隔离 ({detail})")],
                        Vec::new(),
                    ),
                    _ => (Vec::new(), Vec::new(), Vec::new()),
                }
            };

            let qids: Vec<i64> = rows.iter().map(|r| r.queue_id).collect();
            let mut per_doc: HashMap<u64, Vec<deepdoc_protocol::TextSegment>> = HashMap::new();
            for row in rows {
                let entry = per_doc.entry(row.doc_id).or_default();
                for s in &segs {
                    let mut adjusted = s.clone();
                    if row.label != first.label && adjusted.location_label.starts_with(&first.label) {
                        adjusted.location_label =
                            adjusted.location_label.replacen(&first.label, &row.label, 1);
                    }
                    entry.push(adjusted);
                }
            }
            let doc_updates: Vec<_> = per_doc
                .into_iter()
                .map(|(doc_id, dsegs)| (doc_id, dsegs, warns.clone()))
                .collect();
            let payload_cleanup = vec![first.payload_path.clone()];
            persist_ocr_unit_updates(
                state,
                qids,
                doc_updates,
                new_cache,
                payload_cleanup,
                compiled_rules,
                tx,
                job_id,
                rule_hits,
            )
            .await;
            format!("{} ({} 处文档复用)", first.label, rows.len())
        }
        OcrExecutionUnit::ImageFile(row) => {
            let disk_p = row.source_path.clone();
            let data = tokio::fs::read(&disk_p).await.unwrap_or_default();
            let (segs, warns, new_cache) = if data.is_empty() {
                (Vec::new(), Vec::new(), Vec::new())
            } else {
                let req = WorkerRequest::OcrImageBytes {
                    task_id,
                    label: row.label.clone(),
                    data,
                    min_dim,
                };
                match state.parser_pool.execute_parse(req, timeout).await {
                    WorkerResponse::OcrCompleted {
                        segments,
                        warnings,
                        new_ocr_entries,
                        ..
                    } => (segments, warnings, new_ocr_entries),
                    WorkerResponse::Failed { detail, .. } => (
                        Vec::new(),
                        vec![format!("后台图像 OCR 异常已隔离 ({detail})")],
                        Vec::new(),
                    ),
                    _ => (Vec::new(), Vec::new(), Vec::new()),
                }
            };
            persist_ocr_unit_updates(
                state,
                vec![row.queue_id],
                vec![(row.doc_id, segs, warns)],
                new_cache,
                Vec::new(),
                compiled_rules,
                tx,
                job_id,
                rule_hits,
            )
            .await;
            row.source_path.clone()
        }
        OcrExecutionUnit::PdfPages(row) => {
            let req = WorkerRequest::OcrPdfPages {
                task_id,
                disk_path: row.source_path.clone(),
                passwords: row.passwords.clone(),
                page_indices: row.pages.clone(),
                min_dim,
            };
            let (segs, warns, new_cache) = match state.parser_pool.execute_parse(req, timeout).await {
                WorkerResponse::OcrCompleted {
                    segments,
                    warnings,
                    new_ocr_entries,
                    ..
                } => (segments, warnings, new_ocr_entries),
                WorkerResponse::Failed { detail, .. } => (
                    Vec::new(),
                    vec![format!("后台 PDF 分页 OCR 异常已隔离 ({detail})")],
                    Vec::new(),
                ),
                _ => (Vec::new(), Vec::new(), Vec::new()),
            };
            persist_ocr_unit_updates(
                state,
                vec![row.queue_id],
                vec![(row.doc_id, segs, warns)],
                new_cache,
                Vec::new(),
                compiled_rules,
                tx,
                job_id,
                rule_hits,
            )
            .await;
            format!("{} ({})", row.source_path, row.label)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn persist_ocr_unit_updates(
    state: &Arc<DaemonState>,
    queue_ids: Vec<i64>,
    doc_updates: Vec<(u64, Vec<deepdoc_protocol::TextSegment>, Vec<String>)>,
    new_ocr_entries: Vec<(String, u32, u32, String)>,
    cleanup_payloads: Vec<String>,
    compiled_rules: &Option<Arc<CompiledRuleSet>>,
    tx: &mpsc::Sender<DaemonMessage>,
    job_id: &str,
    rule_hits: &mut u64,
) {
    let store = state.store.clone();
    let comp = compiled_rules.clone();
    let hits = tokio::task::spawn_blocking(move || {
        if !new_ocr_entries.is_empty() {
            let _ = store.upsert_ocr_cache_batch(&new_ocr_entries);
        }
        let updated = store
            .attach_ocr_segments_and_complete(&queue_ids, &doc_updates, &cleanup_payloads)
            .unwrap_or_default();
        let Some(ref compiled) = comp else {
            return Vec::new();
        };
        let mut all_hits = Vec::new();
        for (doc_id, doc, mtime_ns) in updated {
            let (mut h, _) = compiled.evaluate_document(doc_id, &doc, 5);
            let mod_ms = mtime_ns / 1_000_000;
            for rec in &mut h {
                rec.modified_unix_ms = mod_ms;
            }
            all_hits.extend(h);
        }
        all_hits
    })
    .await
    .unwrap_or_default();

    *rule_hits += hits.len() as u64;
    for hit in hits {
        send_with_timeout(
            tx,
            DaemonMessage::ScanHit {
                job_id: job_id.to_string(),
                hit,
            },
        )
        .await;
    }
}

fn build_failed_doc(
    disk_path: &Path,
    vp: &str,
    byte_size: u64,
    err_kind: &str,
) -> Option<ExtractedDocument> {
    let b3 = blake3_file(disk_path).unwrap_or_else(|_| format!("err:{vp}"));
    Some(ExtractedDocument {
        virtual_path: vp.to_string(),
        file_name: disk_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        detected_format: "failed".into(),
        blake3_hex: b3,
        byte_size,
        encrypted: err_kind == "Encrypted",
        segments: Vec::new(),
        metadata: vec![("failure_kind".into(), err_kind.into())],
        warnings: vec![format!("worker failed: {err_kind}")],
    })
}

fn is_reparse_or_symlink(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        return (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    }
    #[cfg(not(windows))]
    {
        false
    }
}

enum DeepDeleteTargetKind {
    File(PathBuf),
    Directory(PathBuf),
}

fn validate_deep_delete_target(raw_path: &str, engine_data_dir: &Path) -> Result<DeepDeleteTargetKind, String> {
    if raw_path.contains("!/") || raw_path.contains("!\\") {
        return Err("条目位于压缩包内部，已跳过（如需彻底粉碎请直接选择外层归档文件）".into());
    }
    let path = PathBuf::from(raw_path);
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|e| format!("无法访问 `{raw_path}`: {e}"))?;
    if is_reparse_or_symlink(&meta) || (!meta.is_file() && !meta.is_dir()) {
        return Err(format!("为防止符号链接/目录联接误伤外部路径，已跳过 `{raw_path}`"));
    }

    let canon = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    let norm = canon.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
    let clean_norm = norm.strip_prefix("\\\\?\\").unwrap_or(&norm).trim_end_matches('\\');

    let data_canon = std::fs::canonicalize(engine_data_dir)
        .unwrap_or_else(|_| engine_data_dir.to_path_buf());
    let data_norm = data_canon.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
    let clean_data = data_norm.strip_prefix("\\\\?\\").unwrap_or(&data_norm).trim_end_matches('\\');
    if clean_norm == clean_data
        || clean_norm.starts_with(&format!("{clean_data}\\"))
        || (meta.is_dir() && clean_data.starts_with(&format!("{clean_norm}\\")))
    {
        return Err("已拒绝删除引擎自身索引库目录或包含它的父级目录".into());
    }

    let blocked_segments = [
        "\\windows",
        "\\program files",
        "\\program files (x86)",
        "\\programdata",
        "\\system volume information",
        "\\$recycle.bin",
    ];
    if clean_norm.len() <= 3
        || clean_norm.starts_with("unc\\")
        || blocked_segments
            .iter()
            .any(|b| clean_norm.ends_with(b) || clean_norm.contains(&format!("{b}\\")))
    {
        return Err(format!("为防止系统受损，拒绝深度擦除受保护路径: `{raw_path}`"));
    }

    if meta.is_dir() {
        let trimmed = clean_norm.trim_start_matches(|c: char| c.is_ascii_alphabetic() || c == ':');
        let parts: Vec<&str> = trimmed.split('\\').filter(|s| !s.is_empty()).collect();
        if parts.len() <= 2 && parts.first().copied() == Some("users") {
            return Err(format!("为防止误删用户主目录，拒绝整目录擦除 `{raw_path}`"));
        }
        Ok(DeepDeleteTargetKind::Directory(canon))
    } else {
        Ok(DeepDeleteTargetKind::File(canon))
    }
}

fn collect_directory_deep_delete_plan(
    root_dir: &Path,
    engine_data_dir: &Path,
) -> (Vec<PathBuf>, Vec<PathBuf>, Vec<String>) {
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    let mut skipped_errs = Vec::new();
    let mut stack = vec![(root_dir.to_path_buf(), 0usize)];

    while let Some((cur_dir, depth)) = stack.pop() {
        dirs.push((depth, cur_dir.clone()));
        let entries = match std::fs::read_dir(&cur_dir) {
            Ok(rd) => rd,
            Err(e) => {
                skipped_errs.push(format!("读取目录 `{}` 失败: {e}", cur_dir.display()));
                continue;
            }
        };
        for ent in entries.flatten() {
            let p = ent.path();
            let meta = match std::fs::symlink_metadata(&p) {
                Ok(m) => m,
                Err(e) => {
                    skipped_errs.push(format!("读取属性 `{}` 失败: {e}", p.display()));
                    continue;
                }
            };
            if is_reparse_or_symlink(&meta) {
                skipped_errs.push(format!("安全跳过符号链接/联接 `{}`", p.display()));
                continue;
            }
            if meta.is_dir() {
                stack.push((p, depth + 1));
            } else if meta.is_file() {
                match validate_deep_delete_target(&p.to_string_lossy(), engine_data_dir) {
                    Ok(DeepDeleteTargetKind::File(valid_file)) => files.push(valid_file),
                    Ok(DeepDeleteTargetKind::Directory(_)) => {}
                    Err(e) => skipped_errs.push(e),
                }
            }
        }
    }

    // Remove subdirectories deepest-first before removing root_dir itself
    dirs.sort_by(|a, b| b.0.cmp(&a.0));
    let sorted_dirs = dirs.into_iter().map(|(_, p)| p).collect();
    (files, sorted_dirs, skipped_errs)
}

/// Gentle, zero-entropy 3-pass wipe (0xAA -> 0x55 -> 0x00 + truncate + rename + unlink).
/// Paced slowly using sequential standard file writes with low Shannon entropy so Windows Defender,
/// Huorong, 360, etc. do not misclassify it as ransomware burst encryption.
fn deep_wipe_file_safely(path: &Path, cancel: &AtomicBool, seq: u64) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};

    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(path, perms);
        }
    }

    {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("打开待擦除文件失败 `{}`: {e}", path.display()))?;

        let total_len = file
            .metadata()
            .map_err(|e| format!("读取文件大小失败: {e}"))?
            .len();

        if total_len > 0 {
            const CHUNK: usize = 64 * 1024;
            let patterns = [0xAAu8, 0x55u8, 0x00u8];
            let mut buf = vec![0u8; CHUNK];

            for (pass_idx, &byte_pat) in patterns.iter().enumerate() {
                if cancel.load(Ordering::SeqCst) {
                    // If user requested stop before starting next pass, keep zeroed safety check:
                    // finish a single clean zero pass only if already modified, otherwise leave abort clean.
                    if pass_idx > 0 && byte_pat != 0x00 {
                        buf.fill(0x00);
                        let _ = file.seek(SeekFrom::Start(0));
                        let mut rem = total_len;
                        while rem > 0 {
                            let n = (rem as usize).min(CHUNK);
                            let _ = file.write_all(&buf[..n]);
                            rem -= n as u64;
                        }
                        let _ = file.sync_all();
                        return Err("用户已取消深度删除".into());
                    } else if pass_idx == 0 {
                        return Err("用户已取消深度删除".into());
                    }
                }

                buf.fill(byte_pat);
                file.seek(SeekFrom::Start(0))
                    .map_err(|e| format!("文件定位失败: {e}"))?;
                let mut remaining = total_len;
                let mut chunks_since_pace = 0usize;
                while remaining > 0 {
                    let n = (remaining as usize).min(CHUNK);
                    file.write_all(&buf[..n])
                        .map_err(|e| format!("安全覆写失败: {e}"))?;
                    remaining -= n as u64;
                    chunks_since_pace += 1;
                    if chunks_since_pace >= 16 {
                        // ~1 MiB written -> flush calmly & yield I/O so AV / foreground stay smooth
                        chunks_since_pace = 0;
                        let _ = file.flush();
                        std::thread::sleep(Duration::from_millis(8));
                    }
                }
                let _ = file.sync_data();
                std::thread::sleep(Duration::from_millis(25));
            }
        }

        let _ = file.set_len(0);
        let _ = file.sync_all();
    }

    let delete_target = if let Some(parent) = path.parent() {
        let tmp_name = format!("~deepdoc_clean_{}_{seq}.tmp", std::process::id());
        let renamed = parent.join(tmp_name);
        if std::fs::rename(path, &renamed).is_ok() {
            renamed
        } else {
            path.to_path_buf()
        }
    } else {
        path.to_path_buf()
    };

    std::fs::remove_file(&delete_target)
        .map_err(|e| format!("移除文件句柄失败 `{}`: {e}", delete_target.display()))?;
    std::thread::sleep(Duration::from_millis(120));
    Ok(())
}

async fn run_deep_delete_job(
    state: Arc<DaemonState>,
    job_id: String,
    paths: Vec<String>,
    cancel_active_jobs: bool,
    cancel: Arc<AtomicBool>,
    tx: mpsc::Sender<DaemonMessage>,
) {
    if cancel_active_jobs {
        preempt_other_active_jobs(&state, &job_id, &cancel).await;
    }

    let store_clone = state.store.clone();
    let cancel_clone = cancel.clone();
    let tx_prog = tx.clone();
    let jid_prog = job_id.clone();
    let raw_count = paths.len() as u64;

    let (deleted_file_origs, deleted_dir_prefixes, errors, deleted_files, skipped_or_failed) =
        tokio::task::spawn_blocking(move || {
            let mut wiped_files: Vec<String> = Vec::new();
            let mut wiped_dirs: Vec<String> = Vec::new();
            let mut errs: Vec<String> = Vec::new();
            let mut ok_cnt = 0u64;
            let mut err_cnt = 0u64;
            let data_dir = store_clone.data_dir().to_path_buf();

            enum WorkItem {
                SingleFile { orig: String, disk: PathBuf },
                Folder { orig: String, files: Vec<PathBuf>, subdirs: Vec<PathBuf>, had_pre_err: bool },
            }

            let mut plan = Vec::with_capacity(paths.len());
            let mut total_files = 0u64;
            for raw in paths {
                match validate_deep_delete_target(&raw, &data_dir) {
                    Ok(DeepDeleteTargetKind::File(disk)) => {
                        total_files += 1;
                        plan.push(WorkItem::SingleFile { orig: raw, disk });
                    }
                    Ok(DeepDeleteTargetKind::Directory(dir)) => {
                        let (files, subdirs, pre_errs) =
                            collect_directory_deep_delete_plan(&dir, &data_dir);
                        let had_pre_err = !pre_errs.is_empty();
                        if had_pre_err {
                            err_cnt += pre_errs.len() as u64;
                            errs.extend(pre_errs);
                        }
                        total_files += files.len() as u64;
                        plan.push(WorkItem::Folder {
                            orig: raw,
                            files,
                            subdirs,
                            had_pre_err,
                        });
                    }
                    Err(e) => {
                        err_cnt += 1;
                        errs.push(e);
                    }
                }
            }

            let progress_total = total_files.max(raw_count).max(1);
            let mut seq = 0u64;
            for item in plan {
                if cancel_clone.load(Ordering::SeqCst) {
                    errs.push("已按用户请求中止剩余文件/目录擦除".into());
                    break;
                }
                match item {
                    WorkItem::SingleFile { orig, disk } => {
                        try_send_progress(
                            &tx_prog,
                            DaemonMessage::DeepDeleteProgress {
                                job_id: jid_prog.clone(),
                                completed: seq,
                                total: progress_total,
                                current_path: orig.clone(),
                            },
                        );
                        seq += 1;
                        match deep_wipe_file_safely(&disk, &cancel_clone, seq) {
                            Ok(()) => {
                                ok_cnt += 1;
                                wiped_files.push(orig);
                            }
                            Err(e) => {
                                err_cnt += 1;
                                errs.push(e);
                            }
                        }
                    }
                    WorkItem::Folder {
                        orig,
                        files,
                        subdirs,
                        had_pre_err,
                    } => {
                        let mut folder_ok = !had_pre_err;
                        for f in files {
                            if cancel_clone.load(Ordering::SeqCst) {
                                folder_ok = false;
                                errs.push("已按用户请求中止剩余目录内文件擦除".into());
                                break;
                            }
                            let disp = f.to_string_lossy().into_owned();
                            let clean_disp = disp.strip_prefix("\\\\?\\").unwrap_or(&disp).to_string();
                            try_send_progress(
                                &tx_prog,
                                DaemonMessage::DeepDeleteProgress {
                                    job_id: jid_prog.clone(),
                                    completed: seq,
                                    total: progress_total,
                                    current_path: clean_disp.clone(),
                                },
                            );
                            seq += 1;
                            match deep_wipe_file_safely(&f, &cancel_clone, seq) {
                                Ok(()) => {
                                    ok_cnt += 1;
                                    wiped_files.push(clean_disp);
                                }
                                Err(e) => {
                                    folder_ok = false;
                                    err_cnt += 1;
                                    errs.push(e);
                                }
                            }
                        }
                        if folder_ok && !cancel_clone.load(Ordering::SeqCst) {
                            for (d_idx, sub) in subdirs.into_iter().enumerate() {
                                let del_dir = if let Some(parent) = sub.parent() {
                                    let tmp = format!("~deepdoc_dir_{}_{d_idx}.tmp", std::process::id());
                                    let renamed = parent.join(tmp);
                                    if std::fs::rename(&sub, &renamed).is_ok() {
                                        renamed
                                    } else {
                                        sub
                                    }
                                } else {
                                    sub
                                };
                                if let Err(e) = std::fs::remove_dir(&del_dir) {
                                    folder_ok = false;
                                    err_cnt += 1;
                                    errs.push(format!("移除空目录失败 `{}`: {e}", del_dir.display()));
                                }
                            }
                        }
                        if folder_ok {
                            wiped_dirs.push(orig);
                        }
                    }
                }
            }
            (wiped_files, wiped_dirs, errs, ok_cnt, err_cnt)
        })
        .await
        .unwrap_or_else(|e| (Vec::new(), Vec::new(), vec![e.to_string()], 0, raw_count));

    let purged_index_docs = if !deleted_file_origs.is_empty() || !deleted_dir_prefixes.is_empty() {
        let store_purge = state.store.clone();
        let purged_paths = deleted_file_origs.clone();
        let purged_dirs = deleted_dir_prefixes.clone();
        let removed_cnt = tokio::task::spawn_blocking(move || {
            let cnt = store_purge
                .remove_documents_by_targets(&purged_paths, &purged_dirs)
                .unwrap_or(0);
            let _ = store_purge.secure_compact_after_delete();
            cnt as u64
        })
        .await
        .unwrap_or(0);

        let mut eph = state.ephemeral_docs.lock().await;
        eph.retain(|_, d| {
            let exact_match = deleted_file_origs
                .iter()
                .any(|p| d.virtual_path.eq_ignore_ascii_case(p));
            let dir_match = deleted_dir_prefixes.iter().any(|dir| {
                let t = dir.trim_end_matches(['\\', '/']).to_ascii_lowercase();
                let vp_l = d.virtual_path.to_ascii_lowercase();
                !t.is_empty()
                    && (vp_l.starts_with(&format!("{t}\\")) || vp_l.starts_with(&format!("{t}/")))
            });
            !exact_match && !dir_match
        });
        removed_cnt
    } else {
        0
    };

    finish_job_and_shrink(&state, &job_id).await;
    send_with_timeout(
        &tx,
        DaemonMessage::DeepDeleteCompleted {
            job_id,
            deleted_files,
            purged_index_docs,
            skipped_or_failed,
            errors,
        },
    )
    .await;
}
