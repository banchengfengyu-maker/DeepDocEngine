pub mod adapters;
pub mod dwg;
pub mod email_cad;
pub mod extra_formats;
pub mod legacy_ole;
pub mod ocr;
pub mod ofd_uof;
pub mod office;
pub mod sniffer;
pub mod text;

use crate::adapters::{
    convert_via_onlyoffice_x2t, parse_pdf_document_mode_ext, render_pdf_scan_pages,
    try_decrypt_ms_office,
};
use crate::dwg::parse_dwg_document;
use crate::email_cad::{parse_eml, parse_msg};
use crate::extra_formats::{
    parse_3d_gis, parse_access_db, parse_av_metadata, parse_dbf, parse_dxf_smart, parse_fb2, parse_iwork,
    parse_kmz, parse_mbox, parse_mht, parse_mmap, parse_mobi, parse_sqlite_db, parse_svg,
    parse_tnef, parse_vcf_or_ics, parse_vsdx, parse_xps,
};
use crate::legacy_ole::{parse_legacy_doc_or_wps, parse_legacy_ppt_or_dps};
use crate::ocr::{ImageStageCheck, OcrPipeline};
use crate::ofd_uof::{parse_ofd, parse_uof};
use crate::office::{
    parse_docx_opt, parse_epub, parse_odf_xml, parse_pptx_opt, parse_spreadsheet_calamine_opt,
    parse_xmind, OfficeParseResult,
};
use crate::sniffer::{sniff_format, DetectedFormat};
use crate::text::{
    build_head_tail_segment, decode_text_auto, extract_html_text_and_images, extract_rtf_text,
    extract_xml_text, parse_csv_segments,
};
use deepdoc_protocol::{
    DeferredOcrImage, ExtractedDocument, FailureKind, ParseOptions, SegmentScope, TextSegment,
};
use deepdoc_source_fs::blake3_bytes;
use deepdoc_unpacker::{unpack_archive, UnpackBudget, UnpackError};
use std::path::Path;

pub struct ParserContext {
    pub ocr: OcrPipeline,
}

impl ParserContext {
    pub fn new() -> Self {
        Self {
            ocr: OcrPipeline::discover(),
        }
    }

    pub fn available_engines(&self) -> Vec<String> {
        let mut list = vec![
            "sniffer:magic-ole2-zip-55+formats".into(),
            "text:chardetng+encoding_rs+csv+xml+html+mht+rtf+svg+vcf+ics".into(),
            "office:calamine+ooxml+odf+xmind+xps+vsdx+mmap+iwork+ms-offcrypto".into(),
            "legacy-fallback:ole2-doc-ppt-wps-et-dps".into(),
            "national:ofd+uof".into(),
            "ebook:epub+mobi+fb2".into(),
            "email:eml+mbox+msg+tnef".into(),
            "cad-gis-db:dwg(acadrust)+dxf(gbk)+dbf+kmz+kml+gpx+b3dm+glb+las+sqlite".into(),
            "image-meta:exif+png-text+multipage-tif+gif".into(),
            "unpacker:zip+7z+cab+iso9660+tar+gz+bz2+xz+zst".into(),
        ];
        if adapters::find_pdfium_dll().is_some() {
            list.push("pdf:pdfium+lopdf".into());
        } else {
            list.push("pdf:lopdf(flate+tounicode+xobject-img) (pdfium.dll slot ready)".into());
        }
        if adapters::find_x2t_binary().is_some() {
            list.push("legacy-office:onlyoffice-x2t+ole2".into());
        }
        list.push(self.ocr.backend_label().into());
        list
    }
}

impl Default for ParserContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct ParseFailure {
    pub kind: FailureKind,
    pub detail: String,
}

pub use deepdoc_protocol::{build_metadata_only_doc, is_metadata_only_binary_ext};

fn is_os_file_lock_or_perm(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied
        || matches!(err.raw_os_error(), Some(5 | 32 | 33))
}

fn synthetic_meta_hash(virtual_path: &str, byte_size: u64) -> String {
    let key = format!("meta:{virtual_path}:{byte_size}");
    blake3_bytes(key.as_bytes())
}

#[derive(Debug, Clone)]
pub struct StagedParseResult {
    pub doc: ExtractedDocument,
    pub children: Vec<ExtractedDocument>,
    pub deferred_images: Vec<DeferredOcrImage>,
    pub deferred_pdf_pages: Vec<usize>,
}

struct ParseAccumulator<'a> {
    children: &'a mut Vec<ExtractedDocument>,
    budget: &'a mut UnpackBudget,
    deferred_images: &'a mut Vec<DeferredOcrImage>,
    deferred_pdf_pages: &'a mut Vec<usize>,
}

pub fn parse_file(
    ctx: &ParserContext,
    disk_path: &Path,
    virtual_path: &str,
    options: &ParseOptions,
) -> Result<(ExtractedDocument, Vec<ExtractedDocument>), ParseFailure> {
    let staged = parse_file_staged(ctx, disk_path, virtual_path, options)?;
    Ok((staged.doc, staged.children))
}

pub fn parse_file_staged(
    ctx: &ParserContext,
    disk_path: &Path,
    virtual_path: &str,
    options: &ParseOptions,
) -> Result<StagedParseResult, ParseFailure> {
    let file_name = disk_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| virtual_path.to_string());
    let ext_lower = disk_path
        .extension()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    let meta = match std::fs::metadata(disk_path) {
        Ok(m) => m,
        Err(e) if is_os_file_lock_or_perm(&e) => {
            return Ok(StagedParseResult {
                doc: build_metadata_only_doc(
                    file_name,
                    virtual_path,
                    &ext_lower,
                    0,
                    synthetic_meta_hash(virtual_path, 0),
                    format!("文件权限受限或被系统占用锁定 ({e})，已仅保留文件名索引"),
                ),
                children: Vec::new(),
                deferred_images: Vec::new(),
                deferred_pdf_pages: Vec::new(),
            });
        }
        Err(e) => {
            return Err(ParseFailure {
                kind: FailureKind::IoError,
                detail: e.to_string(),
            });
        }
    };

    if is_metadata_only_binary_ext(&ext_lower) {
        return Ok(StagedParseResult {
            doc: build_metadata_only_doc(
                file_name,
                virtual_path,
                &ext_lower,
                meta.len(),
                synthetic_meta_hash(virtual_path, meta.len()),
                "二进制程序/系统/大型三维组件，已仅建立文件名与属性索引",
            ),
            children: Vec::new(),
            deferred_images: Vec::new(),
            deferred_pdf_pages: Vec::new(),
        });
    }

    if meta.len() > options.max_single_file_bytes {
        return Ok(StagedParseResult {
            doc: build_metadata_only_doc(
                file_name,
                virtual_path,
                &ext_lower,
                meta.len(),
                synthetic_meta_hash(virtual_path, meta.len()),
                format!(
                    "文件体积 ({:.1} MB) 超过单文件深解析上限，已保留文件名与属性索引",
                    meta.len() as f64 / (1024.0 * 1024.0)
                ),
            ),
            children: Vec::new(),
            deferred_images: Vec::new(),
            deferred_pdf_pages: Vec::new(),
        });
    }

    let bytes = match std::fs::read(disk_path) {
        Ok(b) => b,
        Err(e) if is_os_file_lock_or_perm(&e) => {
            return Ok(StagedParseResult {
                doc: build_metadata_only_doc(
                    file_name,
                    virtual_path,
                    &ext_lower,
                    meta.len(),
                    synthetic_meta_hash(virtual_path, meta.len()),
                    format!("文件正被其它程序独占锁定 ({e})，已仅保留文件名与属性索引"),
                ),
                children: Vec::new(),
                deferred_images: Vec::new(),
                deferred_pdf_pages: Vec::new(),
            });
        }
        Err(e) => {
            return Err(ParseFailure {
                kind: FailureKind::IoError,
                detail: e.to_string(),
            });
        }
    };

    parse_bytes_staged(ctx, &bytes, virtual_path, options)
}

pub fn parse_bytes(
    ctx: &ParserContext,
    bytes: &[u8],
    virtual_path: &str,
    options: &ParseOptions,
) -> Result<(ExtractedDocument, Vec<ExtractedDocument>), ParseFailure> {
    let staged = parse_bytes_staged(ctx, bytes, virtual_path, options)?;
    Ok((staged.doc, staged.children))
}

pub fn parse_bytes_staged(
    ctx: &ParserContext,
    bytes: &[u8],
    virtual_path: &str,
    options: &ParseOptions,
) -> Result<StagedParseResult, ParseFailure> {
    let mut budget = UnpackBudget::from_options(options);
    let mut children = Vec::new();
    let mut deferred_images = Vec::new();
    let mut deferred_pdf_pages = Vec::new();
    let mut acc = ParseAccumulator {
        children: &mut children,
        budget: &mut budget,
        deferred_images: &mut deferred_images,
        deferred_pdf_pages: &mut deferred_pdf_pages,
    };
    let doc = parse_bytes_internal(ctx, bytes, virtual_path, options, 0, &mut acc)?;
    Ok(StagedParseResult {
        doc,
        children,
        deferred_images,
        deferred_pdf_pages,
    })
}

/// Render and OCR a specific batch of 0-based PDF scan pages for Stage-2 background OCR.
pub fn ocr_pdf_pages(
    ctx: &ParserContext,
    disk_path: &Path,
    passwords: &[String],
    page_indices: &[usize],
    min_dim: u32,
) -> Result<(Vec<TextSegment>, Vec<String>), ParseFailure> {
    let bytes = std::fs::read(disk_path).map_err(|e| ParseFailure {
        kind: FailureKind::IoError,
        detail: e.to_string(),
    })?;
    let rendered = render_pdf_scan_pages(&bytes, passwords, page_indices).map_err(|e| ParseFailure {
        kind: FailureKind::InternalError,
        detail: e,
    })?;
    let mut segs = Vec::new();
    let mut warnings = Vec::new();
    for (label, png_bytes) in rendered {
        let out = ctx.ocr.process_image(&label, &png_bytes, min_dim, &mut warnings);
        segs.extend(out.into_iter().filter(|s| s.scope == SegmentScope::Ocr));
    }
    Ok((segs, warnings))
}

fn parse_bytes_internal(
    ctx: &ParserContext,
    bytes: &[u8],
    virtual_path: &str,
    options: &ParseOptions,
    depth: u32,
    acc: &mut ParseAccumulator<'_>,
) -> Result<ExtractedDocument, ParseFailure> {
    let file_name = virtual_path
        .rsplit(['/', '\\', '!'])
        .find(|s| !s.is_empty())
        .unwrap_or(virtual_path)
        .to_string();

    let sniff = sniff_format(bytes, &file_name);

    // Attempt transparent `[MS-OFFCRYPTO]` decryption when Office file is encrypted
    if sniff.encrypted && sniff.format.is_office_encrypted_container() {
        let is_ooxml = matches!(
            sniff.format,
            DetectedFormat::Docx | DetectedFormat::Xlsx | DetectedFormat::Pptx
        );
        if let Some(decrypted) = try_decrypt_ms_office(bytes, is_ooxml, &options.passwords) {
            if let Ok(mut inner_doc) =
                parse_bytes_internal(ctx, &decrypted, virtual_path, options, depth, acc)
            {
                inner_doc
                    .metadata
                    .push(("offcrypto_decrypted".into(), "true".into()));
                return Ok(inner_doc);
            }
        }
    }

    let blake3_hex = blake3_bytes(bytes);
    let mut doc = ExtractedDocument {
        virtual_path: virtual_path.to_string(),
        file_name: file_name.clone(),
        detected_format: sniff.format.code().to_string(),
        blake3_hex,
        byte_size: bytes.len() as u64,
        encrypted: sniff.encrypted,
        segments: Vec::new(),
        metadata: Vec::new(),
        warnings: Vec::new(),
    };

    if sniff.encrypted && !matches!(sniff.format, DetectedFormat::Pdf) {
        doc.warnings.push(format!(
            "检测到加密/密码保护头 (`{}`)",
            doc.detected_format
        ));
        return Ok(doc);
    }

    let want_images = options.enable_ocr || options.extract_deferred_images;
    match &sniff.format {
        DetectedFormat::Ceb => {
            doc.warnings
                .push("方正 CEB/CEBX 按当前范围约定暂不解析".into());
            return Ok(doc);
        }
        DetectedFormat::Pst
        | DetectedFormat::Chm
        | DetectedFormat::Djvu
        | DetectedFormat::Shp
        | DetectedFormat::DiskImage(_) => {
            doc.warnings.push(format!(
                "格式 `{}` 属于隔离扩展格式（应路由至 ext-worker 处理）",
                doc.detected_format
            ));
            return Ok(doc);
        }
        DetectedFormat::PlainText | DetectedFormat::Json | DetectedFormat::Markdown | DetectedFormat::GeoJson | DetectedFormat::Gltf => {
            let (txt, enc) = decode_text_auto(bytes);
            doc.metadata.push(("encoding".into(), enc.into()));
            if let Some(ht) = build_head_tail_segment(&txt) {
                doc.segments.push(ht);
            }
            if !txt.trim().is_empty() {
                doc.segments.push(TextSegment {
                    scope: SegmentScope::Body,
                    location_label: format!("{} 正文", sniff.format.code().to_ascii_uppercase()),
                    text: txt,
                });
            }
        }
        DetectedFormat::Csv => {
            doc.segments.extend(parse_csv_segments(bytes));
        }
        DetectedFormat::Xml | DetectedFormat::Kml | DetectedFormat::Gpx => {
            let txt = extract_xml_text(bytes);
            if let Some(ht) = build_head_tail_segment(&txt) {
                doc.segments.push(ht);
            }
            if !txt.trim().is_empty() {
                doc.segments.push(TextSegment {
                    scope: SegmentScope::Body,
                    location_label: format!("{} 正文", sniff.format.code().to_ascii_uppercase()),
                    text: txt,
                });
            }
        }
        DetectedFormat::Html => {
            let (txt, imgs) = extract_html_text_and_images(bytes);
            if let Some(ht) = build_head_tail_segment(&txt) {
                doc.segments.push(ht);
            }
            if !txt.trim().is_empty() {
                doc.segments.push(TextSegment {
                    scope: SegmentScope::Body,
                    location_label: "HTML 正文".into(),
                    text: txt,
                });
            }
            process_embedded_images(ctx, options, &imgs, &mut doc, acc.deferred_images);
        }
        DetectedFormat::Mht => {
            let res = parse_mht(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Rtf => {
            let txt = extract_rtf_text(bytes);
            if let Some(ht) = build_head_tail_segment(&txt) {
                doc.segments.push(ht);
            }
            if !txt.trim().is_empty() {
                doc.segments.push(TextSegment {
                    scope: SegmentScope::Body,
                    location_label: "RTF 正文".into(),
                    text: txt,
                });
            }
        }
        DetectedFormat::Svg => {
            let res = parse_svg(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Vcf => {
            let res = parse_vcf_or_ics(bytes, "vCard 联系人");
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Ics => {
            let res = parse_vcf_or_ics(bytes, "iCalendar 日历");
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Xlsx | DetectedFormat::Xls | DetectedFormat::Ods => {
            let res = parse_spreadsheet_calamine_opt(bytes, want_images);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Docx => {
            let res = parse_docx_opt(bytes, want_images);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Pptx => {
            let res = parse_pptx_opt(bytes, want_images);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Odt | DetectedFormat::Odp => {
            let res = parse_odf_xml(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Ofd => {
            let res = parse_ofd(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Uof => {
            let res = parse_uof(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Xmind => {
            let res = parse_xmind(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Epub => {
            let res = parse_epub(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Mobi => {
            let res = parse_mobi(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Fb2 => {
            let res = parse_fb2(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Xps => {
            let res = parse_xps(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Vsdx => {
            let res = parse_vsdx(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Mmap => {
            let res = parse_mmap(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::IWorkPages | DetectedFormat::IWorkNumbers | DetectedFormat::IWorkKey => {
            let res = parse_iwork(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Kmz => {
            let res = parse_kmz(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::B3dm | DetectedFormat::Glb | DetectedFormat::Las => {
            let res = parse_3d_gis(bytes, sniff.format.code());
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Dbf => {
            let res = parse_dbf(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Sqlite => {
            let res = parse_sqlite_db(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Access => {
            let (res, is_enc, meta) = parse_access_db(bytes, &options.passwords);
            if is_enc && res.segments.is_empty() {
                doc.encrypted = true;
            }
            doc.metadata.extend(meta);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Doc | DetectedFormat::Ppt | DetectedFormat::Wps | DetectedFormat::Et | DetectedFormat::Dps => {
            // Fast path: pure-Rust native OLE2 / Calamine extraction + embedded image carving (0 subprocess spawn)
            let native_res = match sniff.format {
                DetectedFormat::Ppt | DetectedFormat::Dps => parse_legacy_ppt_or_dps(bytes),
                DetectedFormat::Et => {
                    let cal = parse_spreadsheet_calamine_opt(bytes, want_images);
                    if cal.segments.is_empty() {
                        parse_legacy_doc_or_wps(bytes)
                    } else {
                        cal
                    }
                }
                _ => parse_legacy_doc_or_wps(bytes),
            };
            if !native_res.segments.is_empty() || !options.enable_x2t {
                doc.metadata.push(("parsed_by".into(), "native-ole2".into()));
                absorb_office_result(ctx, options, native_res, virtual_path, depth, &mut doc, acc);
            } else if let Ok((target_fmt, converted_bytes)) = convert_via_onlyoffice_x2t(bytes, &sniff.format) {
                let res = match target_fmt {
                    DetectedFormat::Docx => parse_docx_opt(&converted_bytes, want_images),
                    DetectedFormat::Pptx => parse_pptx_opt(&converted_bytes, want_images),
                    DetectedFormat::Xlsx => parse_spreadsheet_calamine_opt(&converted_bytes, want_images),
                    _ => unreachable!(),
                };
                doc.metadata.push(("converted_by".into(), "onlyoffice-x2t".into()));
                absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
            } else {
                doc.metadata.push(("parsed_by".into(), "native-ole2".into()));
                absorb_office_result(ctx, options, native_res, virtual_path, depth, &mut doc, acc);
            }
        }
        DetectedFormat::Pdf => {
            let pdf_out =
                parse_pdf_document_mode_ext(bytes, &options.passwords, options.enable_ocr, want_images);
            doc.encrypted = pdf_out.encrypted_locked;
            doc.segments.extend(pdf_out.segments);
            doc.warnings.extend(pdf_out.warnings);
            process_embedded_images(ctx, options, &pdf_out.embedded_images, &mut doc, acc.deferred_images);
            if !options.enable_ocr
                && options.extract_deferred_images
                && !pdf_out.encrypted_locked
                && !pdf_out.deferred_scan_pages.is_empty()
            {
                if depth == 0 {
                    acc.deferred_pdf_pages.extend(pdf_out.deferred_scan_pages);
                } else if let Ok(rendered) =
                    render_pdf_scan_pages(bytes, &options.passwords, &pdf_out.deferred_scan_pages)
                {
                    process_embedded_images(ctx, options, &rendered, &mut doc, acc.deferred_images);
                }
            }
        }
        DetectedFormat::Dwg => {
            let (res, dwg_meta) = parse_dwg_document(bytes);
            doc.metadata.extend(dwg_meta);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Dxf => {
            let res = parse_dxf_smart(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Eml => {
            let res = parse_eml(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Mbox => {
            let res = parse_mbox(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Msg => {
            let res = parse_msg(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Tnef => {
            let res = parse_tnef(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::AudioVideo(kind) => {
            let res = parse_av_metadata(bytes, kind);
            absorb_office_result(ctx, options, res, virtual_path, depth, &mut doc, acc);
        }
        DetectedFormat::Image(img_kind) => {
            if *img_kind == "ico" {
                // Skip desktop icon resources cleanly
            } else if options.enable_ocr {
                let segs = ctx
                    .ocr
                    .process_image(&file_name, bytes, options.ocr_min_image_dim, &mut doc.warnings);
                doc.segments.extend(segs);
            } else if options.extract_deferred_images {
                match ctx
                    .ocr
                    .check_stage1_image(&file_name, bytes, options.ocr_min_image_dim)
                {
                    ImageStageCheck::Skip => {}
                    ImageStageCheck::Cached(seg_opt) => {
                        if let Some(seg) = seg_opt {
                            doc.segments.push(seg);
                        }
                    }
                    ImageStageCheck::NeedsOcr(img_blake3) => {
                        acc.deferred_images.push(DeferredOcrImage {
                            doc_virtual_path: doc.virtual_path.clone(),
                            label: file_name.clone(),
                            img_blake3,
                            data: bytes.to_vec(),
                            staged_path: None,
                        });
                    }
                }
            } else {
                doc.metadata.push(("ocr_deferred".into(), "true".into()));
            }
        }
        DetectedFormat::Archive(arch_kind) => {
            if depth >= options.max_extract_depth {
                doc.warnings.push(format!(
                    "压缩包递归深度达到上限 {}，停止展开",
                    options.max_extract_depth
                ));
            } else {
                match unpack_archive(*arch_kind, bytes, &file_name, &options.passwords, acc.budget) {
                    Ok(outcome) => {
                        if outcome.archive_encrypted {
                            doc.encrypted = true;
                        }
                        doc.warnings.extend(outcome.warnings);
                        for enc_name in outcome.encrypted_entries {
                            doc.warnings
                                .push(format!("压缩包内受密码保护条目已跳过: {enc_name}"));
                        }
                        let mut manifest = Vec::new();
                        for entry in outcome.entries {
                            manifest.push(entry.inner_path.clone());
                            let child_vp = format!("{virtual_path}!/{}", entry.inner_path);
                            match parse_bytes_internal(
                                ctx,
                                &entry.data,
                                &child_vp,
                                options,
                                depth + 1,
                                acc,
                            ) {
                                Ok(c_doc) => {
                                    acc.children.push(c_doc);
                                }
                                Err(e) => {
                                    doc.warnings
                                        .push(format!("子条目 `{child_vp}` 解析失败: {}", e.detail));
                                }
                            }
                        }
                        if !manifest.is_empty() {
                            doc.segments.push(TextSegment {
                                scope: SegmentScope::Metadata,
                                location_label: "压缩包目录清单".into(),
                                text: manifest.join("\n"),
                            });
                        }
                    }
                    Err(UnpackError::Encrypted(msg)) => {
                        doc.encrypted = true;
                        doc.warnings.push(msg);
                    }
                    Err(UnpackError::ZipBomb(msg)) => {
                        return Err(ParseFailure {
                            kind: FailureKind::ZipBombTripped,
                            detail: msg,
                        });
                    }
                    Err(e) => {
                        doc.warnings.push(format!("归档解包失败: {e}"));
                    }
                }
            }
        }
        DetectedFormat::UnknownBinary => {
            doc.warnings.push("未识别二进制格式，已记录元数据".into());
        }
    }

    Ok(doc)
}

fn process_embedded_images(
    ctx: &ParserContext,
    options: &ParseOptions,
    images: &[(String, Vec<u8>)],
    doc: &mut ExtractedDocument,
    deferred_images: &mut Vec<DeferredOcrImage>,
) {
    if images.is_empty() {
        return;
    }
    if !options.enable_ocr {
        if options.extract_deferred_images {
            for (label, img_bytes) in images {
                match ctx
                    .ocr
                    .check_stage1_image(label, img_bytes, options.ocr_min_image_dim)
                {
                    ImageStageCheck::Skip => {}
                    ImageStageCheck::Cached(seg_opt) => {
                        if let Some(seg) = seg_opt {
                            doc.segments.push(seg);
                        }
                    }
                    ImageStageCheck::NeedsOcr(img_blake3) => {
                        deferred_images.push(DeferredOcrImage {
                            doc_virtual_path: doc.virtual_path.clone(),
                            label: label.clone(),
                            img_blake3,
                            data: img_bytes.clone(),
                            staged_path: None,
                        });
                    }
                }
            }
        } else {
            doc.metadata.push(("ocr_deferred".into(), "true".into()));
        }
        return;
    }

    // Run OCR on every valid embedded image without arbitrary per-doc count or 18s truncation
    for (label, img_bytes) in images {
        let segs = ctx
            .ocr
            .process_image(label, img_bytes, options.ocr_min_image_dim, &mut doc.warnings);
        doc.segments.extend(segs);
    }
}

fn absorb_office_result(
    ctx: &ParserContext,
    options: &ParseOptions,
    res: OfficeParseResult,
    virtual_path: &str,
    depth: u32,
    doc: &mut ExtractedDocument,
    acc: &mut ParseAccumulator<'_>,
) {
    doc.segments.extend(res.segments);
    doc.warnings.extend(res.warnings);
    process_embedded_images(ctx, options, &res.embedded_images, doc, acc.deferred_images);

    if depth < options.max_extract_depth {
        for (fname, data) in res.embedded_files {
            if acc
                .budget
                .check_claim((data.len() as u64).max(1), data.len() as u64, &fname)
                .is_err()
            {
                doc.warnings
                    .push(format!("内嵌附件 `{fname}` 超出体积预算，已跳过"));
                continue;
            }
            let child_vp = format!("{virtual_path}!/{fname}");
            if let Ok(c_doc) =
                parse_bytes_internal(ctx, &data, &child_vp, options, depth + 1, acc)
            {
                acc.children.push(c_doc);
            }
        }
    }
}
