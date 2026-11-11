/// Recover page map and section map by scanning the file directly,
/// completely bypassing the LZ77 page map decompressor.
///
/// Strategy:
/// 1. Scan the file at 32-byte boundaries for XOR-unmasked data page
///    headers (type 0x4163043B) to build page_records.
/// 2. Scan for section map type (0x4163003B) and read section descriptors.
/// 3. This approach works for files where the LZ77 page map is corrupt.
fn recover_section_map_ac18(
    &mut self,
    info: &mut DwgFileHeaderInfo,
) -> Result<(), DxfError> {
    let file_size = self.stream.seek(SeekFrom::End(0))?;

    // Step 1: Scan file for data pages by checking XOR-unmasked headers
    const DATA_PAGE_TYPE: i32 = 0x4163043B;
    const SM_TYPE: i32 = 0x4163003B;
    const PM_TYPE: i32 = 0x41630E3B;

    info.page_records.clear();
    let mut page_num: i32 = 1;
    let mut offset: u64 = 0x100;

    while offset + 32 <= file_size {
        self.stream.seek(SeekFrom::Start(offset))?;
        let mut buf = [0u8; 4];
        if self.stream.read_exact(&mut buf).is_ok() {
            let raw_type = i32::from_le_bytes(buf);
            // XOR-unmask to get the actual type
            let mask = 0x4164536Bu32 ^ (offset as u32);
            let unmasked_type = raw_type as u32 ^ mask;

            if unmasked_type == DATA_PAGE_TYPE as u32 {
                // Data page: read compressed_size from header at +8
                let mut cs_buf = [0u8; 4];
                self.stream.seek(SeekFrom::Start(offset + 8))?;
                if self.stream.read_exact(&mut cs_buf).is_ok() {
                    let cs_unmasked = i32::from_le_bytes(cs_buf) as u32 ^ mask;
                    if cs_unmasked > 0 && cs_unmasked <= 10_000_000 {
                        let total_sz = 32 + cs_unmasked as i64;
                        info.page_records.insert(page_num, (offset as i64, total_sz));
                        page_num += 1;
                        offset += total_sz as u64;
                        continue;
                    }
                }
            }
        }
        offset += 0x20;
    }

    if info.page_records.is_empty() {
        return Err(DxfError::InvalidFormat(
            "Recovery: no data pages found in file scan".into(),
        ));
    }

    // Step 2: Find section map by scanning each page in page_records
    let sm_off = info.page_records.iter().find_map(|(_, &(page_off, _))| {
        if page_off as u64 + 4 > file_size { return None; }
        let mut buf = [0u8; 4];
        self.stream.seek(SeekFrom::Start(page_off as u64)).ok()?;
        self.stream.read_exact(&mut buf).ok()?;
        let raw_type = i32::from_le_bytes(buf);
        if raw_type == SM_TYPE { Some(page_off as u64) } else { None }
    });

    let sm_off = match sm_off {
        Some(off) => off,
        None => {
            // Fallback: scan file at 32-byte boundaries
            let mut o: u64 = 0x100;
            let mut found = None;
            while o + 24 <= file_size {
                let mut buf = [0u8; 4];
                if self.stream.seek(SeekFrom::Start(o)).is_ok()
                    && self.stream.read_exact(&mut buf).is_ok()
                    && i32::from_le_bytes(buf) == SM_TYPE
                {
                    // Verify decomp_size > 200
                    let mut dbuf = [0u8; 4];
                    if self.stream.seek(SeekFrom::Start(o + 4)).is_ok()
                        && self.stream.read_exact(&mut dbuf).is_ok()
                    {
                        let ds = i32::from_le_bytes(dbuf);
                        if ds >= 500 && ds <= 100_000 {
                            found = Some(o);
                        }
                    }
                }
                o += 0x20;
            }
            found
        }
    }.ok_or_else(|| DxfError::InvalidFormat("Recovery: no section map found".into()))?;

    // Step 3: Read section map
    info.section_descriptors.clear();
    self.stream.seek(SeekFrom::Start(sm_off))?;
    let _ = self.stream.read_i32::<LittleEndian>()?;
    let ds = self.stream.read_i32::<LittleEndian>()?;
    let cs = self.stream.read_i32::<LittleEndian>()?;
    let cmp = self.stream.read_i32::<LittleEndian>()?;
    let _ = self.stream.read_u32::<LittleEndian>()?;

    if cs <= 0 || cs > 10_000_000 {
        return Err(DxfError::InvalidFormat(format!("Recovery: bad comp_size {}", cs)));
    }
    let mut comp = vec![0u8; cs as usize];
    self.stream.read_exact(&mut comp)?;
    let dec = if cmp == 2 { decompress_ac18(&comp, ds as usize) } else { comp };
    let mut c = Cursor::new(&dec);
    let nd = c.read_i32::<LittleEndian>().unwrap_or(0);
    let _ = c.read_i32::<LittleEndian>(); // marker 0x02
    let _ = c.read_i32::<LittleEndian>(); // max_decomp 0x7400
    let _ = c.read_i32::<LittleEndian>(); // 0x00
    let _ = c.read_i32::<LittleEndian>(); // num_desc repeated

    for _ in 0..nd {
        let data_sz = c.read_u64::<LittleEndian>().unwrap_or(0);
        let pc = c.read_i32::<LittleEndian>().unwrap_or(0);
        let mx = c.read_i32::<LittleEndian>().unwrap_or(0);
        let _ = c.read_i32::<LittleEndian>();
        let cc = c.read_i32::<LittleEndian>().unwrap_or(0);
        let _ = c.read_i32::<LittleEndian>();
        let enc = c.read_i32::<LittleEndian>().unwrap_or(0);

        let mut nb = [0u8; 64];
        if c.read_exact(&mut nb).is_err() { break; }

        // Try UTF-16LE decode first (AC24/R2013+ files)
        let name = if nb.len() >= 2 && nb[0] != 0 && nb[1] == 0 && nb[2] != 0 {
            let words: Vec<u16> = nb.chunks_exact(2)
                .map(|w| u16::from_le_bytes([w[0], w[1]]))
                .take_while(|&c| c != 0)
                .collect();
            String::from_utf16_lossy(&words)
        } else {
            String::from_utf8_lossy(&nb).trim_end_matches('\0').to_string()
        };

        if !name.starts_with("AcDb:") { continue; }

        let mut pages = Vec::new();
        let mut ok = true;
        for _ in 0..pc {
            match (c.read_i32::<LittleEndian>(), c.read_i32::<LittleEndian>(), c.read_u64::<LittleEndian>()) {
                (Ok(pn), Ok(pcs), Ok(po)) => pages.push(DwgPageCrcInfo {
                    page_number: pn as i64, offset: po, size: 0,
                    decompressed_size: mx as u64, compressed_size: pcs as u64,
                    checksum: 0, crc: 0,
                }),
                _ => { ok = false; break; }
            }
        }
        if !ok { break; }

        info.section_descriptors.push(DwgSectionInfo {
            section_id: 0,
            name, compressed_size: data_sz, decompressed_size: mx as u64,
            encrypted: enc as u64, hash_code: 0, encoding: cc as u64,
            page_count: pc as u64, pages,
        });
    }

    if info.section_descriptors.is_empty() {
        return Err(DxfError::InvalidFormat("Recovery: 0 valid descriptors".into()));
    }

    self.notifications.notify(NotificationType::Warning,
        format!("Recovery: {} sections, {} pages (file-scan method)",
            info.section_descriptors.len(), info.page_records.len()));
    Ok(())
}
