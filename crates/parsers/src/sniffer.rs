use deepdoc_unpacker::{detect_archive_kind, ArchiveKind};
use std::io::Cursor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectedFormat {
    PlainText,
    Csv,
    Json,
    Xml,
    Html,
    Mht,
    Markdown,
    Rtf,
    Svg,
    Vcf,
    Ics,
    Docx,
    Xlsx,
    Xls,
    Pptx,
    Odt,
    Ods,
    Odp,
    Ofd,
    Uof,
    Xmind,
    Epub,
    Mobi,
    Fb2,
    Xps,
    Vsdx,
    Mmap,
    IWorkPages,
    IWorkNumbers,
    IWorkKey,
    Doc,
    Ppt,
    Wps,
    Et,
    Dps,
    Pdf,
    Ceb,
    Chm,
    Djvu,
    Dxf,
    Dwg,
    Dbf,
    Shp,
    Kml,
    Kmz,
    Gpx,
    GeoJson,
    B3dm,
    Glb,
    Gltf,
    Las,
    Sqlite,
    Access,
    Eml,
    Mbox,
    Msg,
    Pst,
    Tnef,
    Image(&'static str),
    AudioVideo(&'static str),
    Archive(ArchiveKind),
    DiskImage(&'static str),
    UnknownBinary,
}

impl DetectedFormat {
    pub fn code(&self) -> &'static str {
        match self {
            Self::PlainText => "txt",
            Self::Csv => "csv",
            Self::Json => "json",
            Self::Xml => "xml",
            Self::Html => "html",
            Self::Mht => "mht",
            Self::Markdown => "md",
            Self::Rtf => "rtf",
            Self::Svg => "svg",
            Self::Vcf => "vcf",
            Self::Ics => "ics",
            Self::Docx => "docx",
            Self::Xlsx => "xlsx",
            Self::Xls => "xls",
            Self::Pptx => "pptx",
            Self::Odt => "odt",
            Self::Ods => "ods",
            Self::Odp => "odp",
            Self::Ofd => "ofd",
            Self::Uof => "uof",
            Self::Xmind => "xmind",
            Self::Epub => "epub",
            Self::Mobi => "mobi",
            Self::Fb2 => "fb2",
            Self::Xps => "xps",
            Self::Vsdx => "vsdx",
            Self::Mmap => "mmap",
            Self::IWorkPages => "pages",
            Self::IWorkNumbers => "numbers",
            Self::IWorkKey => "key",
            Self::Doc => "doc",
            Self::Ppt => "ppt",
            Self::Wps => "wps",
            Self::Et => "et",
            Self::Dps => "dps",
            Self::Pdf => "pdf",
            Self::Ceb => "ceb",
            Self::Chm => "chm",
            Self::Djvu => "djvu",
            Self::Dxf => "dxf",
            Self::Dwg => "dwg",
            Self::Dbf => "dbf",
            Self::Shp => "shp",
            Self::Kml => "kml",
            Self::Kmz => "kmz",
            Self::Gpx => "gpx",
            Self::GeoJson => "geojson",
            Self::B3dm => "b3dm",
            Self::Glb => "glb",
            Self::Gltf => "gltf",
            Self::Las => "las",
            Self::Sqlite => "sqlite",
            Self::Access => "access",
            Self::Eml => "eml",
            Self::Mbox => "mbox",
            Self::Msg => "msg",
            Self::Pst => "pst",
            Self::Tnef => "tnef",
            Self::Image(s) => s,
            Self::AudioVideo(s) => s,
            Self::Archive(k) => match k {
                ArchiveKind::Zip => "zip",
                ArchiveKind::SevenZ => "7z",
                ArchiveKind::Rar => "rar",
                ArchiveKind::Tar => "tar",
                ArchiveKind::TarGz => "tar.gz",
                ArchiveKind::TarBz2 => "tar.bz2",
                ArchiveKind::TarXz => "tar.xz",
                ArchiveKind::TarZst => "tar.zst",
                ArchiveKind::Gzip => "gz",
                ArchiveKind::Bzip2 => "bz2",
                ArchiveKind::Xz => "xz",
                ArchiveKind::Zst => "zst",
                ArchiveKind::Cab => "cab",
                ArchiveKind::Iso => "iso",
            },
            Self::DiskImage(s) => s,
            Self::UnknownBinary => "bin",
        }
    }

    pub fn is_office_encrypted_container(&self) -> bool {
        matches!(
            self,
            Self::Docx | Self::Xlsx | Self::Pptx | Self::Doc | Self::Xls | Self::Ppt | Self::Wps | Self::Et | Self::Dps
        )
    }
}

#[derive(Debug, Clone)]
pub struct SniffResult {
    pub format: DetectedFormat,
    pub encrypted: bool,
}

pub fn sniff_format(bytes: &[u8], file_name: &str) -> SniffResult {
    let ext = file_name
        .rsplit('.')
        .next()
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    // 1. Fixed binary signatures
    if bytes.starts_with(b"%PDF-") {
        let encrypted = contains_subslice(&bytes[..bytes.len().min(128 * 1024)], b"/Encrypt");
        return SniffResult {
            format: DetectedFormat::Pdf,
            encrypted,
        };
    }
    if bytes.starts_with(b"{\\rtf") {
        return SniffResult { format: DetectedFormat::Rtf, encrypted: false };
    }
    if bytes.starts_with(b"SQLite format 3\0") {
        return SniffResult { format: DetectedFormat::Sqlite, encrypted: false };
    }
    if bytes.starts_with(b"\x00\x01\x00\x00Standard Jet DB")
        || bytes.starts_with(b"\x00\x01\x00\x00Standard ACE DB")
        || matches!(ext.as_str(), "mdb" | "accdb")
    {
        return SniffResult { format: DetectedFormat::Access, encrypted: false };
    }
    if bytes.starts_with(b"CEB") || bytes.starts_with(b"CEBX") {
        return SniffResult { format: DetectedFormat::Ceb, encrypted: false };
    }
    if bytes.starts_with(b"ITSF") {
        return SniffResult { format: DetectedFormat::Chm, encrypted: false };
    }
    if bytes.starts_with(b"AT&TFORM") {
        return SniffResult { format: DetectedFormat::Djvu, encrypted: false };
    }
    if bytes.starts_with(b"!BDN") {
        return SniffResult { format: DetectedFormat::Pst, encrypted: false };
    }
    if bytes.len() >= 4 && u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == 0x223E_9F78 {
        return SniffResult { format: DetectedFormat::Tnef, encrypted: false };
    }
    if bytes.len() >= 6 && bytes.starts_with(b"AC10") {
        return SniffResult { format: DetectedFormat::Dwg, encrypted: false };
    }
    if bytes.starts_with(b"b3dm") {
        return SniffResult { format: DetectedFormat::B3dm, encrypted: false };
    }
    if bytes.starts_with(b"glTF") {
        return SniffResult { format: DetectedFormat::Glb, encrypted: false };
    }
    if bytes.starts_with(b"LASF") {
        return SniffResult { format: DetectedFormat::Las, encrypted: false };
    }
    if bytes.len() >= 68 && &bytes[60..68] == b"BOOKMOBI" {
        return SniffResult { format: DetectedFormat::Mobi, encrypted: false };
    }
    if bytes.len() >= 100 && bytes[0..4] == [0x00, 0x00, 0x27, 0x0A] {
        return SniffResult { format: DetectedFormat::Shp, encrypted: false };
    }

    // Virtual Disk & Forensic Image signatures
    if bytes.starts_with(b"vhdxfile") {
        return SniffResult { format: DetectedFormat::DiskImage("vhdx"), encrypted: false };
    }
    if bytes.starts_with(b"QFI\xFB") {
        return SniffResult { format: DetectedFormat::DiskImage("qcow2"), encrypted: false };
    }
    if bytes.starts_with(b"KDMV")
        || (ext == "vmdk" && bytes.starts_with(b"# Disk DescriptorFile"))
    {
        return SniffResult { format: DetectedFormat::DiskImage("vmdk"), encrypted: false };
    }
    if bytes.starts_with(b"EVF\x09\x0D\x0A\xFF\x00")
        || bytes.starts_with(b"EVF2\x0D\x0A\x81")
        || bytes.starts_with(b"LVF\x09\x0D\x0A\xFF\x00")
    {
        return SniffResult { format: DetectedFormat::DiskImage("e01"), encrypted: false };
    }
    if bytes.starts_with(b"<<< Oracle VM VirtualBox Disk Image >>>") {
        return SniffResult { format: DetectedFormat::DiskImage("vdi"), encrypted: false };
    }
    if bytes.len() >= 512 && &bytes[bytes.len() - 512..bytes.len() - 504] == b"conectix" {
        return SniffResult { format: DetectedFormat::DiskImage("vhd"), encrypted: false };
    }
    if bytes.len() >= 1082 && bytes[1080] == 0x53 && bytes[1081] == 0xEF {
        return SniffResult { format: DetectedFormat::DiskImage("ext4"), encrypted: false };
    }
    if bytes.len() >= 512 && bytes[510] == 0x55 && bytes[511] == 0xAA {
        let is_exfat = &bytes[3..11] == b"EXFAT   ";
        let is_fat16 = &bytes[54..59] == b"FAT12" || &bytes[54..59] == b"FAT16" || &bytes[54..57] == b"FAT";
        let is_fat32 = &bytes[82..87] == b"FAT32";
        if is_exfat {
            return SniffResult { format: DetectedFormat::DiskImage("exfat"), encrypted: false };
        }
        if is_fat16 || is_fat32 {
            return SniffResult { format: DetectedFormat::DiskImage("fat"), encrypted: false };
        }
        if matches!(ext.as_str(), "img" | "dd" | "raw" | "fat" | "vfat" | "exfat" | "ext2" | "ext3" | "ext4") {
            return SniffResult { format: DetectedFormat::DiskImage("img"), encrypted: false };
        }
    }
    if matches!(ext.as_str(), "ext2" | "ext3" | "ext4" | "fat" | "vfat" | "exfat" | "e01" | "ex01" | "l01" | "dmg") {
        let tag: &'static str = match ext.as_str() {
            "ext2" | "ext3" | "ext4" => "ext4",
            "fat" | "vfat" => "fat",
            "exfat" => "exfat",
            "e01" | "ex01" | "l01" => "e01",
            "dmg" => "dmg",
            _ => "img",
        };
        return SniffResult { format: DetectedFormat::DiskImage(tag), encrypted: false };
    }

    // Image formats
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return SniffResult { format: DetectedFormat::Image("png"), encrypted: false };
    }
    if bytes.starts_with(b"\xFF\xD8\xFF") {
        return SniffResult { format: DetectedFormat::Image("jpg"), encrypted: false };
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return SniffResult { format: DetectedFormat::Image("gif"), encrypted: false };
    }
    if bytes.starts_with(b"BM") && bytes.len() > 14 {
        return SniffResult { format: DetectedFormat::Image("bmp"), encrypted: false };
    }
    if bytes.starts_with(b"II*\x00") || bytes.starts_with(b"MM\x00*") {
        return SniffResult { format: DetectedFormat::Image("tif"), encrypted: false };
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return SniffResult { format: DetectedFormat::Image("webp"), encrypted: false };
    }
    if bytes.starts_with(&[0x00, 0x00, 0x01, 0x00]) && ext == "ico" {
        return SniffResult { format: DetectedFormat::Image("ico"), encrypted: false };
    }
    if bytes.starts_with(b"qoif") {
        return SniffResult { format: DetectedFormat::Image("qoi"), encrypted: false };
    }
    if bytes.starts_with(&[0x76, 0x2F, 0x31, 0x01]) {
        return SniffResult { format: DetectedFormat::Image("exr"), encrypted: false };
    }

    // Audio / Video containers
    if bytes.starts_with(b"ID3") {
        return SniffResult { format: DetectedFormat::AudioVideo("mp3"), encrypted: false };
    }
    if bytes.starts_with(b"fLaC") {
        return SniffResult { format: DetectedFormat::AudioVideo("flac"), encrypted: false };
    }
    if bytes.starts_with(b"OggS") {
        return SniffResult { format: DetectedFormat::AudioVideo("ogg"), encrypted: false };
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WAVE" {
        return SniffResult { format: DetectedFormat::AudioVideo("wav"), encrypted: false };
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"AVI " {
        return SniffResult { format: DetectedFormat::AudioVideo("avi"), encrypted: false };
    }
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        let fmt = if ext == "mov" { "mov" } else if ext == "m4a" { "m4a" } else { "mp4" };
        return SniffResult { format: DetectedFormat::AudioVideo(fmt), encrypted: false };
    }
    if bytes.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return SniffResult { format: DetectedFormat::AudioVideo("mkv"), encrypted: false };
    }

    // 2. OLE2 Compound File Binary
    if bytes.starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        return sniff_ole2(bytes, &ext);
    }

    // 3. ZIP-based formats vs Archive
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return sniff_zip_container(bytes, &ext);
    }

    if let Some(arch) = detect_archive_kind(bytes, file_name) {
        return SniffResult {
            format: DetectedFormat::Archive(arch),
            encrypted: false,
        };
    }

    // DBF heuristic (by extension + valid version byte & header len)
    if ext == "dbf" && bytes.len() >= 32 && matches!(bytes[0], 0x02 | 0x03 | 0x30 | 0x31 | 0x32 | 0x83 | 0x8B | 0xF5) {
        return SniffResult { format: DetectedFormat::Dbf, encrypted: false };
    }

    // 4. Text / Structured Text heuristics
    if looks_mostly_text(&bytes[..bytes.len().min(8192)]) {
        let head = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
        let trimmed = head.trim_start();
        if ext == "dxf" || (trimmed.starts_with("0\nSECTION") || trimmed.starts_with("0\r\nSECTION")) {
            return SniffResult { format: DetectedFormat::Dxf, encrypted: false };
        }
        if ext == "mbox" || trimmed.starts_with("From ") && trimmed.contains("\nFrom:") {
            return SniffResult { format: DetectedFormat::Mbox, encrypted: false };
        }
        if ext == "mht" || ext == "mhtml" || (head.contains("MIME-Version:") && head.contains("multipart/related")) {
            return SniffResult { format: DetectedFormat::Mht, encrypted: false };
        }
        if ext == "eml" || looks_like_eml(&head) {
            return SniffResult { format: DetectedFormat::Eml, encrypted: false };
        }
        if ext == "vcf" || trimmed.starts_with("BEGIN:VCARD") {
            return SniffResult { format: DetectedFormat::Vcf, encrypted: false };
        }
        if ext == "ics" || trimmed.starts_with("BEGIN:VCALENDAR") {
            return SniffResult { format: DetectedFormat::Ics, encrypted: false };
        }
        if ext == "svg" || (trimmed.starts_with("<svg") || head.contains("<svg ")) {
            return SniffResult { format: DetectedFormat::Svg, encrypted: false };
        }
        if ext == "fb2" || head.contains("<FictionBook") {
            return SniffResult { format: DetectedFormat::Fb2, encrypted: false };
        }
        if ext == "kml" || head.contains("<kml") {
            return SniffResult { format: DetectedFormat::Kml, encrypted: false };
        }
        if ext == "gpx" || head.contains("<gpx") {
            return SniffResult { format: DetectedFormat::Gpx, encrypted: false };
        }
        if ext == "html" || ext == "htm" || trimmed.to_ascii_lowercase().starts_with("<!doctype html") || trimmed.to_ascii_lowercase().starts_with("<html") {
            return SniffResult { format: DetectedFormat::Html, encrypted: false };
        }
        if ext == "uof" || ext == "uot" {
            return SniffResult { format: DetectedFormat::Uof, encrypted: false };
        }
        if ext == "xml" || trimmed.starts_with("<?xml") {
            if head.contains("<uof:UOF") || head.contains("http://schemas.uof.org") {
                return SniffResult { format: DetectedFormat::Uof, encrypted: false };
            }
            return SniffResult { format: DetectedFormat::Xml, encrypted: false };
        }
        if ext == "geojson" {
            return SniffResult { format: DetectedFormat::GeoJson, encrypted: false };
        }
        if ext == "gltf" {
            return SniffResult { format: DetectedFormat::Gltf, encrypted: false };
        }
        if ext == "json" || (trimmed.starts_with('{') && trimmed.contains(':')) || trimmed.starts_with('[') {
            return SniffResult { format: DetectedFormat::Json, encrypted: false };
        }
        if ext == "csv" {
            return SniffResult { format: DetectedFormat::Csv, encrypted: false };
        }
        if ext == "md" || ext == "markdown" {
            return SniffResult { format: DetectedFormat::Markdown, encrypted: false };
        }
        return SniffResult { format: DetectedFormat::PlainText, encrypted: false };
    }

    SniffResult {
        format: DetectedFormat::UnknownBinary,
        encrypted: false,
    }
}

fn sniff_ole2(bytes: &[u8], ext: &str) -> SniffResult {
    let Ok(mut comp) = cfb::CompoundFile::open(Cursor::new(bytes)) else {
        return SniffResult { format: DetectedFormat::UnknownBinary, encrypted: false };
    };
    let mut has_encrypted_pkg = false;
    let mut has_word = false;
    let mut has_excel = false;
    let mut has_ppt = false;
    let mut has_msg = false;
    let mut has_wps_marker = false;

    for entry in comp.walk() {
        let name = entry.name();
        match name {
            "EncryptedPackage" | "EncryptionInfo" | "DataSpaces" => has_encrypted_pkg = true,
            "WordDocument" => has_word = true,
            "Workbook" | "Book" => has_excel = true,
            "PowerPoint Document" => has_ppt = true,
            _ if name.starts_with("__substg1.0_") => has_msg = true,
            _ if name.contains("WPS") || name.contains("Kingsoft") => has_wps_marker = true,
            _ => {}
        }
    }

    if has_msg {
        return SniffResult { format: DetectedFormat::Msg, encrypted: false };
    }
    if has_encrypted_pkg {
        let fmt = match ext {
            "xlsx" | "xlsm" => DetectedFormat::Xlsx,
            "pptx" => DetectedFormat::Pptx,
            "wps" => DetectedFormat::Wps,
            "et" => DetectedFormat::Et,
            "dps" => DetectedFormat::Dps,
            _ => DetectedFormat::Docx,
        };
        return SniffResult { format: fmt, encrypted: true };
    }

    if has_word {
        let mut encrypted = false;
        if let Ok(mut s) = comp.open_stream("WordDocument") {
            let mut hdr = [0u8; 16];
            if std::io::Read::read_exact(&mut s, &mut hdr).is_ok() {
                let w_ident = u16::from_le_bytes([hdr[0], hdr[1]]);
                if matches!(w_ident, 0xA5EC | 0xA5DC) {
                    encrypted = (hdr[11] & 0x01) != 0;
                }
            }
        }
        let fmt = if ext == "wps" || has_wps_marker {
            DetectedFormat::Wps
        } else {
            DetectedFormat::Doc
        };
        return SniffResult { format: fmt, encrypted };
    }

    if has_excel {
        let fmt = if ext == "et" { DetectedFormat::Et } else { DetectedFormat::Xls };
        return SniffResult { format: fmt, encrypted: false };
    }
    if has_ppt {
        let fmt = if ext == "dps" { DetectedFormat::Dps } else { DetectedFormat::Ppt };
        return SniffResult { format: fmt, encrypted: false };
    }

    match ext {
        "wps" => SniffResult { format: DetectedFormat::Wps, encrypted: false },
        "et" => SniffResult { format: DetectedFormat::Et, encrypted: false },
        "dps" => SniffResult { format: DetectedFormat::Dps, encrypted: false },
        "doc" => SniffResult { format: DetectedFormat::Doc, encrypted: false },
        "xls" => SniffResult { format: DetectedFormat::Xls, encrypted: false },
        "ppt" => SniffResult { format: DetectedFormat::Ppt, encrypted: false },
        _ => SniffResult { format: DetectedFormat::UnknownBinary, encrypted: false },
    }
}

fn sniff_zip_container(bytes: &[u8], ext: &str) -> SniffResult {
    let Ok(archive) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        return SniffResult {
            format: DetectedFormat::Archive(ArchiveKind::Zip),
            encrypted: false,
        };
    };

    let mut has_ofd = false;
    let mut has_word = false;
    let mut has_xl = false;
    let mut has_ppt = false;
    let mut has_xmind = false;
    let mut has_epub = false;
    let mut has_xps = false;
    let mut has_vsdx = false;
    let mut has_mmap = false;
    let mut has_iwa = false;
    let mut has_kmz = false;
    let mut has_odf_content = false;

    for i in 0..archive.len() {
        if let Some(name) = archive.name_for_index(i) {
            let nl = name.to_ascii_lowercase();
            if name == "OFD.xml" || name.ends_with("/OFD.xml") {
                has_ofd = true;
            } else if name == "word/document.xml" {
                has_word = true;
            } else if name == "xl/workbook.xml" || name == "xl/workbook.bin" {
                has_xl = true;
            } else if name == "ppt/presentation.xml" {
                has_ppt = true;
            } else if nl.starts_with("visio/pages/") {
                has_vsdx = true;
            } else if nl.ends_with(".fpage") || nl == "fixeddocumentsequence.fdseq" {
                has_xps = true;
            } else if name == "Document.xml" && ext == "mmap" {
                has_mmap = true;
            } else if nl.ends_with(".iwa") || nl == "index.zip" {
                has_iwa = true;
            } else if nl == "doc.kml" || (ext == "kmz" && nl.ends_with(".kml")) {
                has_kmz = true;
            } else if name == "content.json" || name == "workbook.xml" {
                has_xmind = true;
            } else if name == "META-INF/container.xml" {
                has_epub = true;
            } else if name == "content.xml" {
                has_odf_content = true;
            }
        }
    }

    if has_ofd { return SniffResult { format: DetectedFormat::Ofd, encrypted: false }; }
    if has_word { return SniffResult { format: DetectedFormat::Docx, encrypted: false }; }
    if has_xl { return SniffResult { format: DetectedFormat::Xlsx, encrypted: false }; }
    if has_ppt { return SniffResult { format: DetectedFormat::Pptx, encrypted: false }; }
    if has_vsdx { return SniffResult { format: DetectedFormat::Vsdx, encrypted: false }; }
    if has_xps { return SniffResult { format: DetectedFormat::Xps, encrypted: false }; }
    if has_mmap { return SniffResult { format: DetectedFormat::Mmap, encrypted: false }; }
    if has_kmz { return SniffResult { format: DetectedFormat::Kmz, encrypted: false }; }
    if has_iwa {
        let fmt = match ext {
            "numbers" => DetectedFormat::IWorkNumbers,
            "key" => DetectedFormat::IWorkKey,
            _ => DetectedFormat::IWorkPages,
        };
        return SniffResult { format: fmt, encrypted: false };
    }
    if has_xmind || ext == "xmind" {
        return SniffResult { format: DetectedFormat::Xmind, encrypted: false };
    }
    if has_epub && ext == "epub" {
        return SniffResult { format: DetectedFormat::Epub, encrypted: false };
    }
    if has_odf_content && matches!(ext, "odt" | "ods" | "odp" | "uof" | "uot") {
        let fmt = match ext {
            "ods" => DetectedFormat::Ods,
            "odp" => DetectedFormat::Odp,
            "uof" | "uot" => DetectedFormat::Uof,
            _ => DetectedFormat::Odt,
        };
        return SniffResult { format: fmt, encrypted: false };
    }

    SniffResult {
        format: DetectedFormat::Archive(ArchiveKind::Zip),
        encrypted: false,
    }
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn looks_like_eml(head: &str) -> bool {
    let mut header_hits = 0;
    for line in head.lines().take(20) {
        let l = line.to_ascii_lowercase();
        if l.starts_with("from:") || l.starts_with("to:") || l.starts_with("subject:") || l.starts_with("mime-version:") {
            header_hits += 1;
        }
    }
    header_hits >= 2
}

fn looks_mostly_text(sample: &[u8]) -> bool {
    if sample.is_empty() {
        return true;
    }
    if sample.starts_with(&[0xFF, 0xFE]) || sample.starts_with(&[0xFE, 0xFF]) {
        return true;
    }
    let nul_count = sample.iter().filter(|&&b| b == 0).count();
    if nul_count * 10 > sample.len() {
        return false;
    }
    let bad_ctrl = sample
        .iter()
        .filter(|&&b| b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t'))
        .count();
    bad_ctrl * 20 <= sample.len()
}
