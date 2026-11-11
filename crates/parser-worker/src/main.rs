use deepdoc_parsers::{parse_bytes, parse_file, ParserContext};
use deepdoc_protocol::{
    read_frame_sync, write_frame_sync, FrameError, WorkerCapabilities, WorkerRequest,
    WorkerResponse,
};
use std::io::{BufReader, BufWriter};
use std::path::Path;

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
            } => match parse_file(&ctx, Path::new(&disk_path), &virtual_path, &options) {
                Ok((doc, child_docs)) => WorkerResponse::Parsed {
                    task_id,
                    doc,
                    child_docs,
                    new_ocr_entries: ctx.ocr.take_new_cache_entries(),
                },
                Err(err) => WorkerResponse::Failed {
                    task_id,
                    virtual_path,
                    kind: err.kind,
                    detail: err.detail,
                },
            },
            WorkerRequest::ParseBytes {
                task_id,
                data,
                virtual_path,
                hint_ext: _,
                options,
            } => match parse_bytes(&ctx, &data, &virtual_path, &options) {
                Ok((doc, child_docs)) => WorkerResponse::Parsed {
                    task_id,
                    doc,
                    child_docs,
                    new_ocr_entries: ctx.ocr.take_new_cache_entries(),
                },
                Err(err) => WorkerResponse::Failed {
                    task_id,
                    virtual_path,
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
