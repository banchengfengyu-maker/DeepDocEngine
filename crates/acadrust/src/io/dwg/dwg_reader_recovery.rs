    /// Recover page map and section map by finding system pages through
    /// page_records lookups. Strategy:
    /// 1. Scan file for PAGE MAP type (0x41630E3B) - rare, 1-2 per file
    /// 2. Re-read page map from correct offset -> populate page_records
    /// 3. Scan each page in page_records for SECTION MAP type (0x4163003B)
    /// 4. Read section map from correct page -> populate section_descriptors
    fn recover_section_map_ac18(
        &mut self,
        info: &mut DwgFileHeaderInfo,
    ) -> Result<(), DxfError> {
        let file_size = self.stream.seek(SeekFrom::End(0))?;

        // Step 1: Scan for page map (type 0x41630E3B)
        const PM_TYPE: i32 = 0x41630E3B;
        const SM_TYPE: i32 = 0x4163003B;
        let mut pm_offsets: Vec<u64> = Vec::new();
        let mut offset: u64 = 0x100;

        while offset + 24 <= file_size {
            self.stream.seek(SeekFrom::Start(offset))?;
            let mut buf = [0u8; 4];
            if self.stream.read_exact(&mut buf).is_ok() {
                let t = i32::from_le_bytes(buf);
                if t == PM_TYPE {
                    pm_offsets.push(offset);
                }
            }
            offset += 0x20;
        }

        // Step 2: Re-read page map from first found location
        if let Some(&pm_offset) = pm_offsets.first() {
            info.page_records.clear();
            self.stream.seek(SeekFrom::Start(pm_offset))?;
            let _ = self.stream.read_i32::<LittleEndian>()?;
            let pm_ds = self.stream.read_i32::<LittleEndian>()?;
            let pm_cs = self.stream.read_i32::<LittleEndian>()?;
            let pm_cmp = self.stream.read_i32::<LittleEndian>()?;
            let _ = self.stream.read_u32::<LittleEndian>()?;

            if pm_cs > 0 && pm_cs <= 10_000_000 {
                let mut pm_comp = vec![0u8; pm_cs as usize];
                if self.stream.read_exact(&mut pm_comp).is_ok() {
                    let pm_dec = if pm_cmp == 2 {
                        decompress_ac18(&pm_comp, pm_ds as usize)
                    } else {
                        pm_comp
                    };
                    let mut c = Cursor::new(&pm_dec);
                    let mut foff: i64 = 0x100;
                    while (c.position() as usize) + 8 <= pm_dec.len() {
                        let pn = c.read_i32::<LittleEndian>().unwrap_or(0);
                        let ps = c.read_i32::<LittleEndian>().unwrap_or(0);
                        if pn > 0 && ps > 0 {
                            info.page_records.insert(pn, (foff, ps as i64));
                        }
                        foff += ps as i64;
                    }
                }
            }
        }

        if info.page_records.is_empty() {
            return Err(DxfError::InvalidFormat(
                "AC18 recovery: no page records after page map re-read".into(),
            ));
        }

        // Step 3: Scan each page in page_records for section map type
        let mut sm_offset: Option<u64> = None;
        for (&_pn, &(page_off, _page_sz)) in &info.page_records {
            if page_off as u64 + 4 > file_size { continue; }
            self.stream.seek(SeekFrom::Start(page_off as u64))?;
            let mut buf = [0u8; 4];
            if self.stream.read_exact(&mut buf).is_ok() {
                if i32::from_le_bytes(buf) == SM_TYPE {
                    sm_offset = Some(page_off as u64);
                    break;
                }
            }
        }

        let sm_off = sm_offset.ok_or_else(|| DxfError::InvalidFormat(format!(
            "AC18 recovery: no section map found in {} page records",
            info.page_records.len()
        )))?;

        // Step 4: Read section map from found page
        info.section_descriptors.clear();
        self.stream.seek(SeekFrom::Start(sm_off))?;
        let _ = self.stream.read_i32::<LittleEndian>()?;
        let decomp_size = self.stream.read_i32::<LittleEndian>()?;
        let comp_size = self.stream.read_i32::<LittleEndian>()?;
        let compression = self.stream.read_i32::<LittleEndian>()?;
        let _ = self.stream.read_u32::<LittleEndian>()?;

        if comp_size <= 0 || comp_size > 10_000_000 {
            return Err(DxfError::InvalidFormat(format!(
                "AC18 recovered section map invalid compressed size: {}", comp_size
            )));
        }
        let mut compressed = vec![0u8; comp_size as usize];
        self.stream.read_exact(&mut compressed)?;

        let decompressed = if compression == 2 {
            decompress_ac18(&compressed, decomp_size as usize)
        } else {
            compressed
        };

        // Parse section descriptors (AC18 format: 64-byte ASCII names)
        let mut c = Cursor::new(&decompressed);
        let num_desc = c.read_i32::<LittleEndian>()?;
        let _ = c.read_i32::<LittleEndian>()?;
        let _ = c.read_i32::<LittleEndian>()?;
        let _ = c.read_i32::<LittleEndian>()?;
        let _ = c.read_i32::<LittleEndian>()?;

        for _ in 0..num_desc {
            let data_size = c.read_u64::<LittleEndian>()?;
            let page_count = c.read_i32::<LittleEndian>()?;
            let max_decomp = c.read_i32::<LittleEndian>()?;
            let _ = c.read_i32::<LittleEndian>()?;
            let comp_code = c.read_i32::<LittleEndian>()?;
            let _ = c.read_i32::<LittleEndian>()?;
            let encrypted = c.read_i32::<LittleEndian>()?;

            let mut name_buf = [0u8; 64];
            if c.read_exact(&mut name_buf).is_err() { break; }
            let name = String::from_utf8_lossy(&name_buf)
                .trim_end_matches('\0')
                .to_string();

            let mut pages = Vec::new();
            let mut page_ok = true;
            for _ in 0..page_count {
                let pn = match c.read_i32::<LittleEndian>() {
                    Ok(v) => v,
                    Err(_) => { page_ok = false; break; }
                };
                let pcs = match c.read_i32::<LittleEndian>() {
                    Ok(v) => v,
                    Err(_) => { page_ok = false; break; }
                };
                let poff = match c.read_u64::<LittleEndian>() {
                    Ok(v) => v,
                    Err(_) => { page_ok = false; break; }
                };
                pages.push(DwgPageCrcInfo {
                    page_number: pn as i64,
                    offset: poff,
                    size: 0,
                    decompressed_size: max_decomp as u64,
                    compressed_size: pcs as u64,
                    checksum: 0,
                    crc: 0,
                });
            }
            if !page_ok { break; }

            // Only accept valid section names
            if !name.is_empty() && name.starts_with("AcDb:") {
                info.section_descriptors.push(DwgSectionInfo {
                    section_id: 0,
                    name,
                    compressed_size: data_size,
                    decompressed_size: max_decomp as u64,
                    encrypted: encrypted as u64,
                    hash_code: 0,
                    encoding: comp_code as u64,
                    page_count: page_count as u64,
                    pages,
                });
            }
        }

        if info.section_descriptors.is_empty() {
            return Err(DxfError::InvalidFormat(
                "AC18 recovered section map has 0 valid descriptors".into(),
            ));
        }

        self.notifications.notify(
            NotificationType::Warning,
            format!(
                "AC18 recovery: {} sections from {} page records (pm={:#X}, sm={:#X})",
                info.section_descriptors.len(),
                info.page_records.len(),
                pm_offsets.first().unwrap_or(&0),
                sm_off,
            ),
        );

        Ok(())
    }
