use deepdoc_parsers::{ocr_pdf_pages, parse_bytes_staged, parse_file_staged, ParserContext};
use deepdoc_protocol::{
    read_frame_sync, write_frame_sync, DeferredOcrImage, FrameError, WorkerCapabilities,
    WorkerRequest, WorkerResponse,
};
use std::io::{BufReader, BufWriter};
use std::path::Path;

fn spill_oversized_deferred_images(items: &mut [DeferredOcrImage]) {
    const INLINE_BUDGET: usize = 36 * 1024 * 1024;
    let total: usize = items.iter().map(|i| i.data.len()).sum();
    if total <= INLINE_BUDGET {
        return;
    }
    let stage_dir = std::env::temp_dir().join(format!("deepdoc_stage_{}", std::process::id()));
    if std::fs::create_dir_all(&stage_dir).is_err() {
        return;
    }
    let mut remaining = total;
    for item in items.iter_mut() {
        if remaining <= INLINE_BUDGET {
            break;
        }
        if item.data.is_empty() {
            continue;
        }
        let out_p = stage_dir.join(format!("{}.bin", item.img_blake3));
        if out_p.exists() || std::fs::write(&out_p, &item.data).is_ok() {
            remaining = remaining.saturating_sub(item.data.len());
            item.data.clear();
            item.data.shrink_to_fit();
            item.staged_path = Some(out_p.to_string_lossy().into_owned());
        }
    }
}

fn handle_parse_file(
    ctx: &ParserContext,
    task_id: u64,
    disk_path: &str,
    virtual_path: String,
    options: &deepdoc_protocol::ParseOptions,
    include_ocr_cache: bool,
) -> WorkerResponse {
    match parse_file_staged(ctx, Path::new(disk_path), &virtual_path, options) {
        Ok(mut staged) => {
            spill_oversized_deferred_images(&mut staged.deferred_images);
            WorkerResponse::Parsed {
                task_id,
                doc: staged.doc,
                child_docs: staged.children,
                new_ocr_entries: if include_ocr_cache {
                    ctx.ocr.take_new_cache_entries()
                } else {
                    Vec::new()
                },
                deferred_images: staged.deferred_images,
                deferred_pdf_pages: staged.deferred_pdf_pages,
            }
        }
        Err(err) => WorkerResponse::Failed {
            task_id,
            virtual_path,
            kind: err.kind,
            detail: err.detail,
        },
    }
}

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());

    let ctx = ParserContext::new();

    loop {
        let req: WorkerRequest = match read_frame_sync(&mut reader) {
            Ok(r) => r,
            Err(FrameError::Eof) => break,
            Err(e) => {
                eprintln!("[parser-worker] frame read error: {e}");
                break;
            }
        };

        let resp = match req {
            WorkerRequest::HealthCheck => WorkerResponse::Health {
                capabilities: WorkerCapabilities {
                    worker_kind: "parser-worker".into(),
                    license_tier: "permissive (MIT/Apache-2.0)".into(),
                    engines: ctx.available_engines(),
                },
            },
            WorkerRequest::WarmOcrCache { entries } => {
                let loaded = entries.len().min(16384);
                ctx.ocr.warm_cache(&entries);
                WorkerResponse::OcrCacheWarmed { loaded }
            }
            WorkerRequest::ParseFile {
                task_id,
                disk_path,
                virtual_path,
                options,
            } => handle_parse_file(&ctx, task_id, &disk_path, virtual_path, &options, true),
            WorkerRequest::ParseFilesBatch {
                task_id,
                items,
                options,
            } => {
                let total = items.len();
                let mut results = Vec::with_capacity(total);
                for (idx, (disk_path, virtual_path)) in items.into_iter().enumerate() {
                    let is_last = idx + 1 == total;
                    results.push(handle_parse_file(
                        &ctx,
                        task_id,
                        &disk_path,
                        virtual_path,
                        &options,
                        is_last,
                    ));
                }
                WorkerResponse::ParsedBatch {
                    task_id,
                    items: results,
                }
            }
            WorkerRequest::ParseBytes {
                task_id,
                data,
                virtual_path,
                hint_ext: _,
                options,
            } => match parse_bytes_staged(&ctx, &data, &virtual_path, &options) {
                Ok(mut staged) => {
                    spill_oversized_deferred_images(&mut staged.deferred_images);
                    WorkerResponse::Parsed {
                        task_id,
                        doc: staged.doc,
                        child_docs: staged.children,
                        new_ocr_entries: ctx.ocr.take_new_cache_entries(),
                        deferred_images: staged.deferred_images,
                        deferred_pdf_pages: staged.deferred_pdf_pages,
                    }
                }
                Err(err) => WorkerResponse::Failed {
                    task_id,
                    virtual_path,
                    kind: err.kind,
                    detail: err.detail,
                },
            },
            WorkerRequest::OcrImageBytes {
                task_id,
                label,
                data,
                min_dim,
            } => {
                let mut warnings = Vec::new();
                let segments = ctx.ocr.process_image(&label, &data, min_dim, &mut warnings);
                WorkerResponse::OcrCompleted {
                    task_id,
                    segments,
                    warnings,
                    new_ocr_entries: ctx.ocr.take_new_cache_entries(),
                }
            }
            WorkerRequest::OcrPdfPages {
                task_id,
                disk_path,
                passwords,
                page_indices,
                min_dim,
            } => match ocr_pdf_pages(&ctx, Path::new(&disk_path), &passwords, &page_indices, min_dim) {
                Ok((segments, warnings)) => WorkerResponse::OcrCompleted {
                    task_id,
                    segments,
                    warnings,
                    new_ocr_entries: ctx.ocr.take_new_cache_entries(),
                },
                Err(err) => WorkerResponse::Failed {
                    task_id,
                    virtual_path: disk_path,
                    kind: err.kind,
                    detail: err.detail,
                },
            },
        };

        if let Err(e) = write_frame_sync(&mut writer, &resp) {
            eprintln!("[parser-worker] frame write error: {e}");
            break;
        }
    }
}
