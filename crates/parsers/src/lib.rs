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

use crate::adapters::{convert_via_onlyoffice_x2t, parse_pdf_document, try_decrypt_ms_office};
use crate::dwg::parse_dwg_document;
use crate::email_cad::{parse_eml, parse_msg};
use crate::extra_formats::{
    parse_3d_gis, parse_access_db, parse_av_metadata, parse_dbf, parse_dxf_smart, parse_fb2, parse_iwork,
    parse_kmz, parse_mbox, parse_mht, parse_mmap, parse_mobi, parse_sqlite_db, parse_svg,
    parse_tnef, parse_vcf_or_ics, parse_vsdx, parse_xps,
};
use crate::legacy_ole::{parse_legacy_doc_or_wps, parse_legacy_ppt_or_dps};
use crate::ocr::OcrPipeline;
use crate::ofd_uof::{parse_ofd, parse_uof};
use crate::office::{
    parse_docx, parse_epub, parse_odf_xml, parse_pptx, parse_spreadsheet_calamine, parse_xmind,
    OfficeParseResult,
};
use crate::sniffer::{sniff_format, DetectedFormat};
use crate::text::{
    build_head_tail_segment, decode_text_auto, extract_html_text_and_images, extract_rtf_text,
    extract_xml_text, parse_csv_segments,
};
use deepdoc_protocol::{ExtractedDocument, FailureKind, ParseOptions, SegmentScope, TextSegment};
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

pub fn parse_file(
    ctx: &ParserContext,
    disk_path: &Path,
    virtual_path: &str,
    options: &ParseOptions,
) -> Result<(ExtractedDocument, Vec<ExtractedDocument>), ParseFailure> {
    let meta = std::fs::metadata(disk_path).map_err(|e| ParseFailure {
        kind: FailureKind::IoError,
        detail: e.to_string(),
    })?;
    if meta.len() > options.max_single_file_bytes {
        return Err(ParseFailure {
            kind: FailureKind::ZipBombTripped,
            detail: format!("file size {} exceeds max {}", meta.len(), options.max_single_file_bytes),
        });
    }
    let bytes = std::fs::read(disk_path).map_err(|e| ParseFailure {
        kind: FailureKind::IoError,
        detail: e.to_string(),
    })?;
    let mut budget = UnpackBudget::from_options(options);
    parse_bytes_internal(ctx, &bytes, virtual_path, options, 0, &mut budget)
}

pub fn parse_bytes(
    ctx: &ParserContext,
    bytes: &[u8],
    virtual_path: &str,
    options: &ParseOptions,
) -> Result<(ExtractedDocument, Vec<ExtractedDocument>), ParseFailure> {
    let mut budget = UnpackBudget::from_options(options);
    parse_bytes_internal(ctx, bytes, virtual_path, options, 0, &mut budget)
}

fn parse_bytes_internal(
    ctx: &ParserContext,
    bytes: &[u8],
    virtual_path: &str,
    options: &ParseOptions,
    depth: u32,
    budget: &mut UnpackBudget,
) -> Result<(ExtractedDocument, Vec<ExtractedDocument>), ParseFailure> {
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
            if let Ok((mut inner_doc, inner_children)) =
                parse_bytes_internal(ctx, &decrypted, virtual_path, options, depth, budget)
            {
                inner_doc
                    .metadata
                    .push(("offcrypto_decrypted".into(), "true".into()));
                return Ok((inner_doc, inner_children));
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
    let mut children = Vec::new();

    if sniff.encrypted && !matches!(sniff.format, DetectedFormat::Pdf) {
        doc.warnings.push(format!(
            "检测到加密/密码保护头 (`{}`)",
            doc.detected_format
        ));
        return Ok((doc, children));
    }

    match &sniff.format {
        DetectedFormat::Ceb => {
            doc.warnings
                .push("方正 CEB/CEBX 按当前范围约定暂不解析".into());
            return Ok((doc, children));
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
            return Ok((doc, children));
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
            process_embedded_images(ctx, options, &imgs, &mut doc);
        }
        DetectedFormat::Mht => {
            let res = parse_mht(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
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
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Vcf => {
            let res = parse_vcf_or_ics(bytes, "vCard 联系人");
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Ics => {
            let res = parse_vcf_or_ics(bytes, "iCalendar 日历");
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Xlsx | DetectedFormat::Xls | DetectedFormat::Ods => {
            let res = parse_spreadsheet_calamine(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Docx => {
            let res = parse_docx(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Pptx => {
            let res = parse_pptx(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Odt | DetectedFormat::Odp => {
            let res = parse_odf_xml(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Ofd => {
            let res = parse_ofd(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Uof => {
            let res = parse_uof(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Xmind => {
            let res = parse_xmind(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Epub => {
            let res = parse_epub(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Mobi => {
            let res = parse_mobi(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Fb2 => {
            let res = parse_fb2(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Xps => {
            let res = parse_xps(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Vsdx => {
            let res = parse_vsdx(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Mmap => {
            let res = parse_mmap(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::IWorkPages | DetectedFormat::IWorkNumbers | DetectedFormat::IWorkKey => {
            let res = parse_iwork(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Kmz => {
            let res = parse_kmz(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::B3dm | DetectedFormat::Glb | DetectedFormat::Las => {
            let res = parse_3d_gis(bytes, sniff.format.code());
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Dbf => {
            let res = parse_dbf(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Sqlite => {
            let res = parse_sqlite_db(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Access => {
            let (res, is_enc, meta) = parse_access_db(bytes, &options.passwords);
            if is_enc && res.segments.is_empty() {
                doc.encrypted = true;
            }
            doc.metadata.extend(meta);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Doc | DetectedFormat::Ppt | DetectedFormat::Wps | DetectedFormat::Et | DetectedFormat::Dps => {
            // Fast path: pure-Rust native OLE2 / Calamine extraction + embedded image carving (0 subprocess spawn)
            let native_res = match sniff.format {
                DetectedFormat::Ppt | DetectedFormat::Dps => parse_legacy_ppt_or_dps(bytes),
                DetectedFormat::Et => {
                    let cal = parse_spreadsheet_calamine(bytes);
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
                absorb_office_result(ctx, options, native_res, virtual_path, depth, budget, &mut doc, &mut children);
            } else if let Ok((target_fmt, converted_bytes)) = convert_via_onlyoffice_x2t(bytes, &sniff.format) {
                let res = match target_fmt {
                    DetectedFormat::Docx => parse_docx(&converted_bytes),
                    DetectedFormat::Pptx => parse_pptx(&converted_bytes),
                    DetectedFormat::Xlsx => parse_spreadsheet_calamine(&converted_bytes),
                    _ => unreachable!(),
                };
                doc.metadata.push(("converted_by".into(), "onlyoffice-x2t".into()));
                absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
            } else {
                doc.metadata.push(("parsed_by".into(), "native-ole2".into()));
                absorb_office_result(ctx, options, native_res, virtual_path, depth, budget, &mut doc, &mut children);
            }
        }
        DetectedFormat::Pdf => {
            let pdf_out = parse_pdf_document(bytes, &options.passwords);
            if pdf_out.encrypted_locked {
                doc.encrypted = true;
            } else {
                doc.encrypted = false;
            }
            doc.segments.extend(pdf_out.segments);
            doc.warnings.extend(pdf_out.warnings);
            process_embedded_images(ctx, options, &pdf_out.embedded_images, &mut doc);
        }
        DetectedFormat::Dwg => {
            let (res, dwg_meta) = parse_dwg_document(bytes);
            doc.metadata.extend(dwg_meta);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Dxf => {
            let res = parse_dxf_smart(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Eml => {
            let res = parse_eml(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Mbox => {
            let res = parse_mbox(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Msg => {
            let res = parse_msg(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Tnef => {
            let res = parse_tnef(bytes);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::AudioVideo(kind) => {
            let res = parse_av_metadata(bytes, kind);
            absorb_office_result(ctx, options, res, virtual_path, depth, budget, &mut doc, &mut children);
        }
        DetectedFormat::Image(_) => {
            if options.enable_ocr {
                let segs = ctx
                    .ocr
                    .process_image(&file_name, bytes, options.ocr_min_image_dim, &mut doc.warnings);
                doc.segments.extend(segs);
            }
        }
        DetectedFormat::Archive(arch_kind) => {
            if depth >= options.max_extract_depth {
                doc.warnings.push(format!(
                    "压缩包递归深度达到上限 {}，停止展开",
                    options.max_extract_depth
                ));
            } else {
                match unpack_archive(*arch_kind, bytes, &file_name, &options.passwords, budget) {
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
                                budget,
                            ) {
                                Ok((c_doc, grand_children)) => {
                                    children.push(c_doc);
                                    children.extend(grand_children);
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

    Ok((doc, children))
}

fn process_embedded_images(
    ctx: &ParserContext,
    options: &ParseOptions,
    images: &[(String, Vec<u8>)],
    doc: &mut ExtractedDocument,
) {
    if !options.enable_ocr || images.is_empty() {
        return;
    }
    const MAX_IMAGES_PER_DOC: usize = 16;
    let mut processed = 0usize;
    for (label, img_bytes) in images {
        if img_bytes.len() > 16 * 1024 * 1024 {
            continue;
        }
        let segs = ctx
            .ocr
            .process_image(label, img_bytes, options.ocr_min_image_dim, &mut doc.warnings);
        let ran = !segs.is_empty();
        doc.segments.extend(segs);
        if ran {
            processed += 1;
            if processed >= MAX_IMAGES_PER_DOC {
                if images.len() > MAX_IMAGES_PER_DOC {
                    doc.warnings.push(format!(
                        "内嵌图片较多（共 {} 张），已识别前 {} 张 OCR 文本",
                        images.len(),
                        MAX_IMAGES_PER_DOC
                    ));
                }
                break;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn absorb_office_result(
    ctx: &ParserContext,
    options: &ParseOptions,
    res: OfficeParseResult,
    virtual_path: &str,
    depth: u32,
    budget: &mut UnpackBudget,
    doc: &mut ExtractedDocument,
    children: &mut Vec<ExtractedDocument>,
) {
    doc.segments.extend(res.segments);
    doc.warnings.extend(res.warnings);
    process_embedded_images(ctx, options, &res.embedded_images, doc);

    if depth < options.max_extract_depth {
        for (fname, data) in res.embedded_files {
            if budget
                .check_claim((data.len() as u64).max(1), data.len() as u64, &fname)
                .is_err()
            {
                doc.warnings
                    .push(format!("内嵌附件 `{fname}` 超出体积预算，已跳过"));
                continue;
            }
            let child_vp = format!("{virtual_path}!/{fname}");
            if let Ok((c_doc, gc)) =
                parse_bytes_internal(ctx, &data, &child_vp, options, depth + 1, budget)
            {
                children.push(c_doc);
                children.extend(gc);
            }
        }
    }
}
