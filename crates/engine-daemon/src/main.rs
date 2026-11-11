mod supervisor;

use deepdoc_indexer::{build_document_preview, IndexStore};
use deepdoc_protocol::framing::async_codec::{read_frame_async, write_frame_async};
use deepdoc_protocol::{
    ClientEnvelope, ClientRequest, DaemonMessage, ExtractedDocument, RuleDefinition,
    RuleMatchMode, RuleSet, ScanOptions, ScanSummary, WorkerRequest, WorkerResponse,
    DEFAULT_PIPE_NAME,
};
use deepdoc_rule_engine::CompiledRuleSet;
use deepdoc_source_fs::{
    blake3_bytes, blake3_file, enumerate_roots_with_options, is_drive_root_path,
    query_ntfs_usn_state, try_read_ntfs_usn_delta, DiscoveredFile,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use supervisor::{find_sibling_exe, WorkerPool};
use tokio::sync::{mpsc, Mutex};

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
        .map(|n| n.get().clamp(2, 6))
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
async fn run_named_pipe_server(
    pipe_name: String,
    state: Arc<DaemonState>,
    shutdown_notify: Arc<tokio::sync::Notify>,
) {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)
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
                match ServerOptions::new().create(&pipe_name) {
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
                let _ = tx_clone
                    .send(DaemonMessage::Pong {
                        req_id,
                        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
                        worker_engines,
                        ext_worker_engines,
                        indexed_docs,
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
            } => {
                let compiled = match build_direct_search_ruleset(&query, use_regex) {
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
                        cancel,
                        tx_clone,
                    )
                    .await;
                });
            }
            ClientRequest::CancelScan { job_id } => {
                let jobs = st_clone.active_jobs.lock().await;
                let found = if let Some(flag) = jobs.get(&job_id) {
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
            ClientRequest::DeepDeleteFiles { job_id, paths } => {
                let cancel = Arc::new(AtomicBool::new(false));
                {
                    let mut jobs = st_clone.active_jobs.lock().await;
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
                    run_deep_delete_job(st_clone, job_id, paths, cancel, tx_clone).await;
                });
            }
            ClientRequest::Shutdown => {
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

async fn finish_job_and_shrink(state: &DaemonState, job_id: &str) {
    let no_active_jobs = {
        let mut jobs = state.active_jobs.lock().await;
        jobs.remove(job_id);
        jobs.is_empty()
    };
    if no_active_jobs {
        state.parser_pool.shrink_idle(0).await;
        if let Some(ep) = &state.ext_pool {
            ep.shrink_idle(0).await;
        }
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

    let roots_clone = roots.clone();
    let opts_clone = options.clone();
    let store_snap = state.store.clone();
    let (discovered, snapshot, usn_updates, removed_via_usn) =
        tokio::task::spawn_blocking(move || {
            let mut items: Vec<(String, DiscoveredFile)> = Vec::new();
            let mut pending_usn: Vec<(String, u64, i64)> = Vec::new();
            let mut removed_count = 0usize;

            for root_str in roots_clone {
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
                                items.push((root_str.clone(), entry));
                            }
                            pending_usn.push((root_str, delta.journal_id, delta.next_usn));
                            continue;
                        }
                    }
                    if let Some((jid, cur_usn)) = query_ntfs_usn_state(root_path) {
                        pending_usn.push((root_str.clone(), jid, cur_usn));
                    }
                }

                for entry in enumerate_roots_with_options(std::slice::from_ref(&root_str), &opts_clone) {
                    items.push((root_str.clone(), entry));
                }
            }

            let snap = store_snap.load_incremental_snapshot().unwrap_or_default();
            (items, snap, pending_usn, removed_count)
        })
        .await
        .unwrap_or_default();

    let mut scanned_files = 0u64;
    let mut parsed_ok = 0u64;
    let mut child_docs_indexed = 0u64;
    let mut skipped_cached = 0u64;
    let mut encrypted_files = 0u64;
    let mut failed_files = 0u64;
    let mut rule_hits = 0u64;

    let timeout = Duration::from_millis(options.worker_timeout_ms.max(2_000));
    let mut last_progress = Instant::now();
    let mut pending_to_parse: Vec<(String, DiscoveredFile)> = Vec::new();
    let mut cached_eval_ids: Vec<u64> = Vec::new();

    for (source_root, entry) in discovered {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        scanned_files += 1;
        let vp = entry.disk_path.to_string_lossy().into_owned();

        if let Some(&(cached_doc_id, old_sz, old_mt, ref st)) = snapshot.get(&vp) {
            let can_skip = old_sz == entry.byte_size
                && old_mt == entry.mtime_ns
                && (st == "ok"
                    || (st == "encrypted" && options.parse.passwords.is_empty())
                    || (st != "ok" && st != "encrypted"));
            if can_skip {
                skipped_cached += 1;
                if st == "ok" && compiled_rules.is_some() {
                    cached_eval_ids.push(cached_doc_id);
                }
                continue;
            }
        }
        pending_to_parse.push((source_root, entry));
    }

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
                let _ = tx
                    .send(DaemonMessage::ScanHit {
                        job_id: job_id.clone(),
                        hit,
                    })
                    .await;
            }
        }
    }

    // Concurrent worker pipeline: saturate all parser-worker & ext-worker slots in parallel
    let max_in_flight = (state.worker_count.max(options.worker_count) * 2).clamp(4, 16);
    let mut join_set = tokio::task::JoinSet::new();
    let mut iter = pending_to_parse.into_iter();
    let mut batch: Vec<(String, ExtractedDocument, i64, String)> = Vec::with_capacity(64);
    let mut pending_ocr: Vec<(String, u32, u32, String)> = Vec::new();
    let mut since_last_commit = 0u64;

    loop {
        while join_set.len() < max_in_flight && !cancel.load(Ordering::SeqCst) {
            let Some((src_root, entry)) = iter.next() else {
                break;
            };
            let st_clone = state.clone();
            let parse_opts = options.parse.clone();
            join_set.spawn(async move {
                dispatch_parse_task(st_clone, src_root, entry, parse_opts, timeout).await
            });
        }

        let Some(joined) = join_set.join_next().await else {
            break;
        };
        let Ok((source_root, entry, resp)) = joined else {
            continue;
        };
        let vp = entry.disk_path.to_string_lossy().into_owned();

        match resp {
            WorkerResponse::Parsed {
                doc,
                child_docs,
                new_ocr_entries,
                ..
            } => {
                parsed_ok += 1;
                since_last_commit += 1;
                if doc.encrypted {
                    encrypted_files += 1;
                }
                let status = if doc.encrypted { "encrypted" } else { "ok" }.to_string();
                batch.push((source_root.clone(), doc, entry.mtime_ns, status));

                for cdoc in child_docs {
                    child_docs_indexed += 1;
                    since_last_commit += 1;
                    if cdoc.encrypted {
                        encrypted_files += 1;
                    }
                    let cstatus = if cdoc.encrypted { "encrypted" } else { "ok" }.to_string();
                    batch.push((source_root.clone(), cdoc, entry.mtime_ns, cstatus));
                }
                pending_ocr.extend(new_ocr_entries);
            }
            WorkerResponse::Failed { kind, .. } => {
                failed_files += 1;
                since_last_commit += 1;
                let err_kind = format!("{kind:?}");
                if let Some(fail_doc) = build_failed_doc(
                    &entry.disk_path,
                    &vp,
                    entry.byte_size,
                    &err_kind,
                ) {
                    if fail_doc.encrypted {
                        encrypted_files += 1;
                    }
                    batch.push((source_root, fail_doc, entry.mtime_ns, err_kind));
                }
            }
            WorkerResponse::Health { .. } | WorkerResponse::OcrCacheWarmed { .. } => {}
        }

        if batch.len() >= 64 || pending_ocr.len() >= 32 {
            let drained = std::mem::take(&mut batch);
            let ocr_drained = std::mem::take(&mut pending_ocr);
            rule_hits += flush_batch(
                state.store.clone(),
                drained,
                ocr_drained,
                compiled_rules.clone(),
                &tx,
                &job_id,
            )
            .await;
        }

        if since_last_commit >= 2000 {
            since_last_commit = 0;
            let st_commit = state.store.clone();
            let _ = tokio::task::spawn_blocking(move || st_commit.commit()).await;
        }

        if last_progress.elapsed() >= Duration::from_millis(200) {
            last_progress = Instant::now();
            let _ = tx
                .send(DaemonMessage::ScanProgress {
                    job_id: job_id.clone(),
                    scanned_files,
                    parsed_ok,
                    skipped_cached,
                    encrypted_files,
                    failed_files,
                    current_path: vp,
                    elapsed_ms: t0.elapsed().as_millis() as u64,
                })
                .await;
        }
    }

    if !batch.is_empty() || !pending_ocr.is_empty() {
        rule_hits += flush_batch(
            state.store.clone(),
            batch,
            pending_ocr,
            compiled_rules.clone(),
            &tx,
            &job_id,
        )
        .await;
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

    let _ = tx
        .send(DaemonMessage::ScanCompleted {
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
        })
        .await;
}

fn build_direct_search_ruleset(query: &str, use_regex: bool) -> Result<CompiledRuleSet, String> {
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
        trimmed
            .split_whitespace()
            .map(|t| {
                let safe = t.replace('\\', "\\\\").replace('"', "\\\"");
                format!("\"{safe}\"")
            })
            .collect::<Vec<_>>()
            .join(" & ")
    } else {
        trimmed.to_string()
    };

    let rs = RuleSet {
        ruleset_id: format!("direct-{}", blake3_bytes_hex(expression.as_bytes())),
        rules: vec![RuleDefinition {
            id: "direct-search".into(),
            name: format!("临时直搜: {trimmed}"),
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
    cancel: Arc<AtomicBool>,
    tx: mpsc::Sender<DaemonMessage>,
) {
    let t0 = Instant::now();
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

    let timeout = Duration::from_millis(options.worker_timeout_ms.max(2_000));
    let max_in_flight = (state.worker_count.max(options.worker_count) * 2).clamp(4, 16);
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
                    let (hits, _) = compiled.evaluate_document(provisional_id, &cdoc, 5);
                    if !hits.is_empty() {
                        {
                            let mut eph = state.ephemeral_docs.lock().await;
                            if eph.len() >= 500 {
                                if let Some(&oldest) = eph.keys().min() {
                                    eph.remove(&oldest);
                                }
                            }
                            eph.insert(provisional_id, cdoc);
                        }
                        for hit in hits {
                            rule_hits += 1;
                            let _ = tx
                                .send(DaemonMessage::ScanHit {
                                    job_id: job_id.clone(),
                                    hit,
                                })
                                .await;
                        }
                    }
                }
            }
            WorkerResponse::Failed { .. } => {
                failed_files += 1;
            }
            WorkerResponse::Health { .. } | WorkerResponse::OcrCacheWarmed { .. } => {}
        }

        if last_progress.elapsed() >= Duration::from_millis(200) {
            last_progress = Instant::now();
            let _ = tx
                .send(DaemonMessage::ScanProgress {
                    job_id: job_id.clone(),
                    scanned_files,
                    parsed_ok,
                    skipped_cached: 0,
                    encrypted_files,
                    failed_files,
                    current_path: vp,
                    elapsed_ms: t0.elapsed().as_millis() as u64,
                })
                .await;
        }
    }

    finish_job_and_shrink(&state, &job_id).await;
    let cancelled = cancel.load(Ordering::SeqCst);

    let _ = tx
        .send(DaemonMessage::ScanCompleted {
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
        })
        .await;
}

async fn dispatch_parse_task(
    state: Arc<DaemonState>,
    source_root: String,
    entry: DiscoveredFile,
    parse_opts: deepdoc_protocol::ParseOptions,
    timeout: Duration,
) -> (String, DiscoveredFile, WorkerResponse) {
    let vp = entry.disk_path.to_string_lossy().into_owned();
    let use_ext = matches!(
        entry.ext_lower.as_str(),
        "pst" | "ost" | "chm" | "djvu" | "shp"
    ) && state.ext_pool.is_some();

    let task_id = state.next_task_id.fetch_add(1, Ordering::Relaxed);
    let req = WorkerRequest::ParseFile {
        task_id,
        disk_path: vp.clone(),
        virtual_path: vp,
        options: parse_opts,
    };

    let resp = if use_ext {
        state
            .ext_pool
            .as_ref()
            .unwrap()
            .execute_parse(req, timeout)
            .await
    } else {
        state.parser_pool.execute_parse(req, timeout).await
    };
    (source_root, entry, resp)
}

async fn flush_batch(
    store: Arc<IndexStore>,
    batch: Vec<(String, ExtractedDocument, i64, String)>,
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
            .map(|(sr, doc, mt, st)| (sr.as_str(), doc, *mt, st.as_str()))
            .collect();
        let Ok(doc_ids) = store.upsert_documents_batch(&refs) else {
            return Vec::new();
        };
        let Some(ref compiled) = compiled_rules else {
            return Vec::new();
        };
        let mut all_hits = Vec::new();
        for ((_, doc, _, _), doc_id) in batch.iter().zip(doc_ids.into_iter()) {
            let (h, _) = compiled.evaluate_document(doc_id, doc, 5);
            all_hits.extend(h);
        }
        all_hits
    })
    .await
    .unwrap_or_default();

    let count = hits.len() as u64;
    for hit in hits {
        let _ = tx
            .send(DaemonMessage::ScanHit {
                job_id: job_id.to_string(),
                hit,
            })
            .await;
    }
    count
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

fn validate_deep_delete_target(raw_path: &str, engine_data_dir: &Path) -> Result<PathBuf, String> {
    if raw_path.contains("!/") || raw_path.contains("!\\") {
        return Err("条目位于压缩包内部，已跳过（如需彻底粉碎请直接选择外层归档文件）".into());
    }
    let path = PathBuf::from(raw_path);
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|e| format!("无法访问 `{raw_path}`: {e}"))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(format!("深度删除仅支持普通文件，已跳过 `{raw_path}`"));
    }

    let canon = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    let norm = canon.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
    let clean_norm = norm.strip_prefix("\\\\?\\").unwrap_or(&norm);

    let data_canon = std::fs::canonicalize(engine_data_dir)
        .unwrap_or_else(|_| engine_data_dir.to_path_buf());
    let data_norm = data_canon.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
    let clean_data = data_norm.strip_prefix("\\\\?\\").unwrap_or(&data_norm);
    if clean_norm.starts_with(clean_data) {
        return Err("已拒绝删除引擎自身索引库目录中的文件".into());
    }

    let blocked_segments = [
        "\\windows\\",
        "\\program files\\",
        "\\program files (x86)\\",
        "\\programdata\\",
        "\\system volume information\\",
        "\\$recycle.bin\\",
    ];
    if clean_norm.len() <= 3 || blocked_segments.iter().any(|b| clean_norm.contains(b)) {
        return Err(format!("为防止系统受损，拒绝深度删除受保护路径: `{raw_path}`"));
    }
    Ok(canon)
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
    cancel: Arc<AtomicBool>,
    tx: mpsc::Sender<DaemonMessage>,
) {
    let total = paths.len() as u64;
    let store_clone = state.store.clone();
    let cancel_clone = cancel.clone();
    let tx_prog = tx.clone();
    let jid_prog = job_id.clone();

    let (deleted_paths_orig, errors, deleted_files, skipped_or_failed) =
        tokio::task::spawn_blocking(move || {
            let mut wiped_originals: Vec<String> = Vec::new();
            let mut errs: Vec<String> = Vec::new();
            let mut ok_cnt = 0u64;
            let mut err_cnt = 0u64;
            let data_dir = store_clone.data_dir().to_path_buf();

            for (idx, raw) in paths.iter().enumerate() {
                if cancel_clone.load(Ordering::SeqCst) {
                    errs.push("已按用户请求中止剩余文件删除".into());
                    break;
                }
                let _ = tx_prog.blocking_send(DaemonMessage::DeepDeleteProgress {
                    job_id: jid_prog.clone(),
                    completed: idx as u64,
                    total,
                    current_path: raw.clone(),
                });

                match validate_deep_delete_target(raw, &data_dir) {
                    Ok(valid_path) => match deep_wipe_file_safely(&valid_path, &cancel_clone, idx as u64) {
                        Ok(()) => {
                            ok_cnt += 1;
                            wiped_originals.push(raw.clone());
                        }
                        Err(e) => {
                            err_cnt += 1;
                            errs.push(e);
                        }
                    },
                    Err(e) => {
                        err_cnt += 1;
                        errs.push(e);
                    }
                }
            }
            (wiped_originals, errs, ok_cnt, err_cnt)
        })
        .await
        .unwrap_or_else(|e| (Vec::new(), vec![e.to_string()], 0, total));

    let purged_index_docs = if !deleted_paths_orig.is_empty() {
        let store_purge = state.store.clone();
        let purged_paths = deleted_paths_orig.clone();
        let removed_cnt = tokio::task::spawn_blocking(move || {
            let cnt = store_purge.remove_documents_by_paths(&purged_paths).unwrap_or(0);
            let _ = store_purge.secure_compact_after_delete();
            cnt as u64
        })
        .await
        .unwrap_or(0);

        let mut eph = state.ephemeral_docs.lock().await;
        eph.retain(|_, d| !deleted_paths_orig.iter().any(|p| d.virtual_path == *p));
        removed_cnt
    } else {
        0
    };

    finish_job_and_shrink(&state, &job_id).await;
    let _ = tx
        .send(DaemonMessage::DeepDeleteCompleted {
            job_id,
            deleted_files,
            purged_index_docs,
            skipped_or_failed,
            errors,
        })
        .await;
}
