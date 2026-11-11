use deepdoc_protocol::{
    DocumentPreview, ExtractedDocument, HitLocationSnippet, HitRecord, IndexStats, PreviewSegment,
    SearchHitItem, SearchQuery, SegmentScope, TextSegment,
};
use deepdoc_rule_engine::CompiledRuleSet;
use jieba_rs::Jieba;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tantivy::collector::{Count, TopDocs};
use tantivy::query::{
    BooleanQuery, BoostQuery, Occur, PhraseQuery, Query, QueryParser, RegexQuery, TermQuery,
    TermSetQuery,
};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, TextFieldIndexing, TextOptions, Value, FAST, INDEXED, STORED,
    STRING,
};
use tantivy::tokenizer::{LowerCaser, NgramTokenizer, TextAnalyzer, Token, TokenStream, Tokenizer};
use tantivy::{doc, Index, IndexReader, IndexWriter, ReloadPolicy, Term};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IndexerError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Tantivy error: {0}")]
    Tantivy(#[from] tantivy::TantivyError),
    #[error("Tantivy query parse error: {0}")]
    QueryParse(#[from] tantivy::query::QueryParserError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Codec(String),
    #[error("Document {0} not found")]
    NotFound(u64),
}

#[inline]
fn is_cjk_char(ch: char) -> bool {
    matches!(
        ch as u32,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x20000..=0x2A6DF
    )
}

#[derive(Clone)]
struct JiebaTokenizer {
    jieba: Arc<Jieba>,
}

struct VecTokenStream {
    tokens: Vec<Token>,
    index: usize,
}

impl TokenStream for VecTokenStream {
    fn advance(&mut self) -> bool {
        if self.index < self.tokens.len() {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn token(&self) -> &Token {
        &self.tokens[self.index - 1]
    }

    fn token_mut(&mut self) -> &mut Token {
        &mut self.tokens[self.index - 1]
    }
}

impl Tokenizer for JiebaTokenizer {
    type TokenStream<'a> = VecTokenStream;

    fn token_stream<'a>(&'a mut self, text: &'a str) -> Self::TokenStream<'a> {
        let mut tokens = Vec::new();
        let mut pos = 0usize;
        // Use non-overlapping Default mode + split internal punctuation (`_`, `-`, `.`)
        // so consecutive words retain exact position adjacency without overlapping sub-tokens.
        for tok in self.jieba.tokenize(text, jieba_rs::TokenizeMode::Default, true) {
            let mut sub_start = None;
            for (rel_idx, ch) in tok.word.char_indices() {
                if ch.is_alphanumeric() {
                    sub_start.get_or_insert(rel_idx);
                } else if let Some(s) = sub_start.take() {
                    let piece = &tok.word[s..rel_idx];
                    tokens.push(Token {
                        offset_from: tok.byte_start + s,
                        offset_to: tok.byte_start + rel_idx,
                        position: pos,
                        text: piece.to_string(),
                        position_length: 1,
                    });
                    pos += 1;
                }
            }
            if let Some(s) = sub_start {
                let piece = &tok.word[s..];
                tokens.push(Token {
                    offset_from: tok.byte_start + s,
                    offset_to: tok.byte_end,
                    position: pos,
                    text: piece.to_string(),
                    position_length: 1,
                });
                pos += 1;
            }
        }
        VecTokenStream { tokens, index: 0 }
    }
}

/// Emits contiguous overlapping CJK 2-grams (`ab`, `bc`, `cd`) with position gaps at non-CJK boundaries,
/// guaranteeing exact phrase recall regardless of Jieba word segmentation boundaries.
#[derive(Clone, Default)]
struct CjkBigramTokenizer;

impl Tokenizer for CjkBigramTokenizer {
    type TokenStream<'a> = VecTokenStream;

    fn token_stream<'a>(&'a mut self, text: &'a str) -> Self::TokenStream<'a> {
        let mut tokens = Vec::new();
        let mut pos = 0usize;
        let mut run: Vec<(usize, usize, char)> = Vec::new();

        let flush_run = |run: &mut Vec<(usize, usize, char)>, tokens: &mut Vec<Token>, pos: &mut usize| {
            if run.len() >= 2 {
                for w in run.windows(2) {
                    let mut bigram = String::with_capacity(6);
                    bigram.push(w[0].2);
                    bigram.push(w[1].2);
                    tokens.push(Token {
                        offset_from: w[0].0,
                        offset_to: w[1].1,
                        position: *pos,
                        text: bigram,
                        position_length: 1,
                    });
                    *pos += 1;
                }
                *pos += 1;
            }
            run.clear();
        };

        for (idx, ch) in text.char_indices() {
            if is_cjk_char(ch) {
                run.push((idx, idx + ch.len_utf8(), ch));
            } else {
                flush_run(&mut run, &mut tokens, &mut pos);
            }
        }
        flush_run(&mut run, &mut tokens, &mut pos);

        VecTokenStream { tokens, index: 0 }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredBlobPayload {
    segments: Vec<TextSegment>,
    metadata: Vec<(String, String)>,
}

struct SchemaFields {
    doc_id: Field,
    blake3: Field,
    file_ext: Field,
    virtual_path: Field,
    file_name: Field,
    file_name_ng: Field,
    fn_cjk_bi: Field,
    head_tail: Field,
    body: Field,
    ocr_text: Field,
    table_data: Field,
    metadata: Field,
    txt_cjk_bi: Field,
}

pub struct IndexStore {
    data_dir: PathBuf,
    tantivy_dir: PathBuf,
    db_path: PathBuf,
    conn: Mutex<Connection>,
    index: Index,
    reader: IndexReader,
    writer: Mutex<Option<IndexWriter>>,
    fields: SchemaFields,
}

impl IndexStore {
    pub fn open(data_dir: &Path) -> Result<Self, IndexerError> {
        std::fs::create_dir_all(data_dir)?;
        let tantivy_dir = data_dir.join("tantivy");
        std::fs::create_dir_all(&tantivy_dir)?;
        let db_path = data_dir.join("metadata.sqlite");

        let conn = Connection::open(&db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "cache_size", -16384)?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        init_sqlite_schema(&conn)?;

        let (schema, fields) = build_schema();
        let index = if tantivy_dir.join("meta.json").exists() {
            let opened = Index::open_in_dir(&tantivy_dir)?;
            if opened.schema() != schema {
                drop(opened);
                let _ = std::fs::remove_dir_all(&tantivy_dir);
                std::fs::create_dir_all(&tantivy_dir)?;
                let _ = conn.execute_batch(
                    "DELETE FROM rule_hit_cache; DELETE FROM documents; DELETE FROM usn_checkpoints;",
                );
                Index::create_in_dir(&tantivy_dir, schema)?
            } else {
                opened
            }
        } else {
            Index::create_in_dir(&tantivy_dir, schema)?
        };

        let jieba = Arc::new(Jieba::new());
        let jieba_analyzer = TextAnalyzer::builder(JiebaTokenizer { jieba })
            .filter(LowerCaser)
            .build();
        index.tokenizers().register("jieba", jieba_analyzer);

        if let Ok(ng) = NgramTokenizer::new(2, 3, false) {
            let ng_analyzer = TextAnalyzer::builder(ng).filter(LowerCaser).build();
            index.tokenizers().register("ngram3", ng_analyzer);
        }

        let cjk_bi_analyzer = TextAnalyzer::builder(CjkBigramTokenizer)
            .filter(LowerCaser)
            .build();
        index.tokenizers().register("cjk_bi", cjk_bi_analyzer);

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()?;

        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            tantivy_dir,
            db_path,
            conn: Mutex::new(conn),
            index,
            reader,
            writer: Mutex::new(None),
            fields,
        })
    }

    fn ensure_writer<'a>(
        &self,
        guard: &'a mut Option<IndexWriter>,
    ) -> Result<&'a mut IndexWriter, IndexerError> {
        if guard.is_none() {
            *guard = Some(self.index.writer(96 * 1024 * 1024)?);
        }
        Ok(guard.as_mut().expect("writer initialized"))
    }

    pub fn is_file_unchanged(
        &self,
        virtual_path: &str,
        byte_size: u64,
        mtime_ns: i64,
    ) -> Result<Option<(u64, String)>, IndexerError> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(i64, String, i64, i64, String)> = conn
            .query_row(
                "SELECT doc_id, blake3, byte_size, mtime_ns, status FROM documents WHERE virtual_path = ?1",
                params![virtual_path],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        if let Some((doc_id, blake3, old_sz, old_mt, status)) = row {
            if status == "ok" && old_sz as u64 == byte_size && old_mt == mtime_ns {
                return Ok(Some((doc_id as u64, blake3)));
            }
        }
        Ok(None)
    }

    pub fn has_blob(&self, blake3: &str) -> Result<bool, IndexerError> {
        let conn = self.conn.lock().unwrap();
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM content_blobs WHERE blake3 = ?1",
                params![blake3],
                |r| r.get(0),
            )
            .optional()?;
        Ok(exists.is_some())
    }

    pub fn load_incremental_snapshot(
        &self,
    ) -> Result<std::collections::HashMap<String, (u64, u64, i64, String)>, IndexerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT virtual_path, doc_id, byte_size, mtime_ns, status FROM documents",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                (
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ),
            ))
        })?;
        let mut map = std::collections::HashMap::new();
        for row in rows {
            let (vp, val) = row?;
            map.insert(vp, val);
        }
        Ok(map)
    }

    pub fn upsert_document(
        &self,
        source_root: &str,
        doc: &ExtractedDocument,
        mtime_ns: i64,
        status: &str,
    ) -> Result<u64, IndexerError> {
        let mut ids = self.upsert_documents_batch(&[(source_root, doc, mtime_ns, status)])?;
        Ok(ids.pop().unwrap_or(0))
    }

    /// Batch-upsert documents using a single SQLite WAL transaction, skipping duplicate blob compression.
    pub fn upsert_documents_batch(
        &self,
        items: &[(&str, &ExtractedDocument, i64, &str)],
    ) -> Result<Vec<u64>, IndexerError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Pre-check which content hashes are already persisted so duplicate files skip rmp/zstd encoding.
        let mut known_blobs: std::collections::HashSet<String> = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare_cached("SELECT 1 FROM content_blobs WHERE blake3 = ?1")?;
            let mut set = std::collections::HashSet::new();
            for &(_, doc, _, _) in items {
                if !set.contains(&doc.blake3_hex)
                    && stmt.query_row(params![&doc.blake3_hex], |_| Ok(())).optional()?.is_some()
                {
                    set.insert(doc.blake3_hex.clone());
                }
            }
            set
        };

        struct PreparedDoc<'a> {
            source_root: &'a str,
            doc: &'a ExtractedDocument,
            mtime_ns: i64,
            status: &'a str,
            file_ext: String,
            warnings_json: String,
            total_chars: usize,
            compressed_blob: Option<Vec<u8>>,
            head_tail: String,
            body: String,
            ocr_text: String,
            table_data: String,
            metadata_txt: String,
        }

        let mut prepared = Vec::with_capacity(items.len());
        for &(source_root, doc, mtime_ns, status) in items {
            let file_ext = Path::new(&doc.file_name)
                .extension()
                .map(|s| s.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_else(|| doc.detected_format.clone());
            let warnings_json =
                serde_json::to_string(&doc.warnings).unwrap_or_else(|_| "[]".into());
            let total_chars: usize = doc.segments.iter().map(|s| s.text.chars().count()).sum();
            let compressed_blob = if known_blobs.insert(doc.blake3_hex.clone()) {
                let capped_segments = cap_segments_for_storage(&doc.segments, MAX_STORED_SEGMENT_BYTES);
                let payload = StoredBlobPayload {
                    segments: capped_segments,
                    metadata: doc.metadata.clone(),
                };
                let raw_mp =
                    rmp_serde::to_vec(&payload).map_err(|e| IndexerError::Codec(e.to_string()))?;
                Some(zstd::bulk::compress(&raw_mp, 4)?)
            } else {
                None
            };

            let mut head_tail = String::new();
            let mut body = String::new();
            let mut ocr_text = String::new();
            let mut table_data = String::new();
            let mut metadata_txt = String::new();

            for seg in &doc.segments {
                let target = match seg.scope {
                    SegmentScope::HeadTail => &mut head_tail,
                    SegmentScope::Ocr => &mut ocr_text,
                    SegmentScope::Table => &mut table_data,
                    SegmentScope::Metadata => &mut metadata_txt,
                    SegmentScope::FileName | SegmentScope::Body | SegmentScope::Comment => &mut body,
                };
                if !target.is_empty() {
                    target.push('\n');
                }
                target.push_str(&seg.text);
            }
            for (k, v) in &doc.metadata {
                if !metadata_txt.is_empty() {
                    metadata_txt.push('\n');
                }
                metadata_txt.push_str(k);
                metadata_txt.push_str(": ");
                metadata_txt.push_str(v);
            }

            prepared.push(PreparedDoc {
                source_root,
                doc,
                mtime_ns,
                status,
                file_ext,
                warnings_json,
                total_chars,
                compressed_blob,
                head_tail,
                body,
                ocr_text,
                table_data,
                metadata_txt,
            });
        }

        let mut doc_ids = Vec::with_capacity(prepared.len());
        {
            let conn = self.conn.lock().unwrap();
            let tx = conn.unchecked_transaction()?;
            {
                let mut blob_stmt = tx.prepare_cached(
                    "INSERT OR IGNORE INTO content_blobs (blake3, total_chars, segment_count, zstd_segments) VALUES (?1, ?2, ?3, ?4)",
                )?;
                let mut doc_stmt = tx.prepare_cached(
                    "INSERT INTO documents (virtual_path, source_root, file_name, file_ext, detected_format, blake3, byte_size, mtime_ns, encrypted, status, warnings_json, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                     ON CONFLICT(virtual_path) DO UPDATE SET
                        source_root=excluded.source_root,
                        file_name=excluded.file_name,
                        file_ext=excluded.file_ext,
                        detected_format=excluded.detected_format,
                        blake3=excluded.blake3,
                        byte_size=excluded.byte_size,
                        mtime_ns=excluded.mtime_ns,
                        encrypted=excluded.encrypted,
                        status=excluded.status,
                        warnings_json=excluded.warnings_json,
                        updated_at=excluded.updated_at
                     RETURNING doc_id",
                )?;

                for p in &prepared {
                    if let Some(ref zblob) = p.compressed_blob {
                        blob_stmt.execute(params![
                            &p.doc.blake3_hex,
                            p.total_chars as i64,
                            p.doc.segments.len() as i64,
                            zblob
                        ])?;
                    }
                    let id: i64 = doc_stmt.query_row(
                        params![
                            &p.doc.virtual_path,
                            p.source_root,
                            &p.doc.file_name,
                            &p.file_ext,
                            &p.doc.detected_format,
                            &p.doc.blake3_hex,
                            p.doc.byte_size as i64,
                            p.mtime_ns,
                            if p.doc.encrypted { 1i64 } else { 0i64 },
                            p.status,
                            &p.warnings_json,
                            now
                        ],
                        |r| r.get(0),
                    )?;
                    doc_ids.push(id as u64);
                }
            }
            tx.commit()?;
        }

        {
            let mut writer_guard = self.writer.lock().unwrap();
            let writer = self.ensure_writer(&mut writer_guard)?;
            for (p, &doc_id) in prepared.iter().zip(doc_ids.iter()) {
                let fn_bi = format!("{}\n{}", p.doc.file_name, p.doc.virtual_path);
                let txt_bi = format!(
                    "{}\n{}\n{}\n{}\n{}",
                    p.head_tail, p.body, p.ocr_text, p.table_data, p.metadata_txt
                );
                writer.delete_term(Term::from_field_u64(self.fields.doc_id, doc_id));
                writer.add_document(doc!(
                    self.fields.doc_id => doc_id,
                    self.fields.blake3 => p.doc.blake3_hex.as_str(),
                    self.fields.file_ext => p.file_ext.as_str(),
                    self.fields.virtual_path => p.doc.virtual_path.as_str(),
                    self.fields.file_name => p.doc.file_name.as_str(),
                    self.fields.file_name_ng => p.doc.file_name.as_str(),
                    self.fields.fn_cjk_bi => fn_bi.as_str(),
                    self.fields.head_tail => p.head_tail.as_str(),
                    self.fields.body => p.body.as_str(),
                    self.fields.ocr_text => p.ocr_text.as_str(),
                    self.fields.table_data => p.table_data.as_str(),
                    self.fields.metadata => p.metadata_txt.as_str(),
                    self.fields.txt_cjk_bi => txt_bi.as_str(),
                ))?;
            }
        }

        Ok(doc_ids)
    }

    pub fn commit(&self) -> Result<(), IndexerError> {
        let mut writer_guard = self.writer.lock().unwrap();
        if let Some(writer) = writer_guard.as_mut() {
            writer.commit()?;
        }
        self.reader.reload()?;
        Ok(())
    }

    /// Commit pending writes, wait for background segment merges, reload the search reader,
    /// and drop the `IndexWriter` so indexing arena memory (~96 MiB) is released back to the OS.
    pub fn commit_and_release(&self) -> Result<(), IndexerError> {
        let writer_opt = self.writer.lock().unwrap().take();
        if let Some(mut writer) = writer_opt {
            writer.commit()?;
            let _ = writer.wait_merging_threads();
        }
        self.reader.reload()?;
        Ok(())
    }

    pub fn load_ocr_cache(&self, limit: usize) -> Result<Vec<(String, String)>, IndexerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT img_blake3, ocr_text FROM ocr_image_cache ORDER BY updated_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit.max(1) as i64], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn upsert_ocr_cache_batch(
        &self,
        entries: &[(String, u32, u32, String)],
    ) -> Result<(), IndexerError> {
        if entries.is_empty() {
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO ocr_image_cache (img_blake3, width, height, ocr_text, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for (img_blake3, w, h, txt) in entries {
                stmt.execute(params![img_blake3, *w as i64, *h as i64, txt, now])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_usn_checkpoint(&self, drive_root: &str) -> Result<Option<(u64, i64)>, IndexerError> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(i64, i64)> = conn
            .query_row(
                "SELECT journal_id, next_usn FROM usn_checkpoints WHERE drive_root = ?1",
                params![drive_root],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.map(|(jid, usn)| (jid as u64, usn)))
    }

    pub fn set_usn_checkpoint(
        &self,
        drive_root: &str,
        journal_id: u64,
        next_usn: i64,
    ) -> Result<(), IndexerError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO usn_checkpoints (drive_root, journal_id, next_usn, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![drive_root, journal_id as i64, next_usn, now],
        )?;
        Ok(())
    }

    /// Remove documents (and any nested archive child docs `path!...`) from both SQLite and Tantivy.
    pub fn remove_documents_by_paths(&self, paths: &[String]) -> Result<usize, IndexerError> {
        if paths.is_empty() {
            return Ok(0);
        }
        let mut doc_ids = Vec::new();
        {
            let conn = self.conn.lock().unwrap();
            let tx = conn.unchecked_transaction()?;
            {
                let mut sel = tx.prepare_cached(
                    "SELECT doc_id FROM documents
                     WHERE virtual_path = ?1
                        OR (LENGTH(virtual_path) > LENGTH(?1)
                            AND SUBSTR(virtual_path, 1, LENGTH(?1) + 1) = (?1 || '!'))",
                )?;
                let mut del = tx.prepare_cached(
                    "DELETE FROM documents
                     WHERE virtual_path = ?1
                        OR (LENGTH(virtual_path) > LENGTH(?1)
                            AND SUBSTR(virtual_path, 1, LENGTH(?1) + 1) = (?1 || '!'))",
                )?;
                for p in paths {
                    let rows = sel.query_map(params![p], |r| r.get::<_, i64>(0))?;
                    for r in rows {
                        doc_ids.push(r? as u64);
                    }
                    del.execute(params![p])?;
                }
            }
            tx.commit()?;
        }
        if !doc_ids.is_empty() {
            let mut writer_guard = self.writer.lock().unwrap();
            let writer = self.ensure_writer(&mut writer_guard)?;
            for doc_id in &doc_ids {
                writer.delete_term(Term::from_field_u64(self.fields.doc_id, *doc_id));
            }
        }
        Ok(doc_ids.len())
    }

    /// Reclaim unreferenced `content_blobs` and stale `rule_hit_cache` rows after incremental updates.
    pub fn prune_orphaned_blobs(&self) -> Result<usize, IndexerError> {
        let conn = self.conn.lock().unwrap();
        let d1 = conn.execute(
            "DELETE FROM content_blobs WHERE blake3 NOT IN (SELECT DISTINCT blake3 FROM documents)",
            [],
        )?;
        let d2 = conn.execute(
            "DELETE FROM rule_hit_cache WHERE doc_blake3 NOT IN (SELECT DISTINCT blake3 FROM documents)",
            [],
        )?;
        Ok(d1 + d2)
    }

    pub fn load_extracted_document(&self, doc_id: u64) -> Result<ExtractedDocument, IndexerError> {
        let (virtual_path, file_name, detected_format, blake3, byte_size, encrypted, warnings_json, zstd_blob): (
            String,
            String,
            String,
            String,
            i64,
            i64,
            String,
            Vec<u8>,
        ) = {
            let conn = self.conn.lock().unwrap();
            conn.query_row(
                "SELECT d.virtual_path, d.file_name, d.detected_format, d.blake3, d.byte_size, d.encrypted, d.warnings_json, b.zstd_segments
                 FROM documents d
                 JOIN content_blobs b ON d.blake3 = b.blake3
                 WHERE d.doc_id = ?1",
                params![doc_id as i64],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )
            .optional()?
            .ok_or(IndexerError::NotFound(doc_id))?
        };

        let raw_mp = zstd::bulk::decompress(&zstd_blob, 128 * 1024 * 1024)?;
        let payload: StoredBlobPayload =
            rmp_serde::from_slice(&raw_mp).map_err(|e| IndexerError::Codec(e.to_string()))?;
        let warnings: Vec<String> = serde_json::from_str(&warnings_json).unwrap_or_default();

        Ok(ExtractedDocument {
            virtual_path,
            file_name,
            detected_format,
            blake3_hex: blake3,
            byte_size: byte_size as u64,
            encrypted: encrypted != 0,
            segments: payload.segments,
            metadata: payload.metadata,
            warnings,
        })
    }

    pub fn search(&self, query: &SearchQuery) -> Result<(usize, Vec<SearchHitItem>), IndexerError> {
        self.reader.reload()?;
        let searcher = self.reader.searcher();

        let text_fields: Vec<Field> = match query.scope_filter {
            Some(SegmentScope::FileName) => vec![self.fields.file_name, self.fields.file_name_ng],
            Some(SegmentScope::HeadTail) => vec![self.fields.head_tail],
            Some(SegmentScope::Body) | Some(SegmentScope::Comment) => {
                vec![self.fields.body]
            }
            Some(SegmentScope::Ocr) => vec![self.fields.ocr_text],
            Some(SegmentScope::Table) => vec![self.fields.table_data],
            Some(SegmentScope::Metadata) => vec![self.fields.metadata],
            None => vec![
                self.fields.file_name,
                self.fields.head_tail,
                self.fields.body,
                self.fields.ocr_text,
                self.fields.table_data,
                self.fields.metadata,
                self.fields.virtual_path,
            ],
        };

        let main_query: Box<dyn Query> = if query.text.trim().is_empty() {
            Box::new(tantivy::query::AllQuery)
        } else if query.use_regex {
            let mut sub: Vec<(Occur, Box<dyn Query>)> = Vec::new();
            for &f in &[self.fields.file_name, self.fields.body, self.fields.ocr_text, self.fields.table_data, self.fields.head_tail] {
                if let Ok(rq) = RegexQuery::from_pattern(query.text.trim(), f) {
                    sub.push((Occur::Should, Box::new(rq)));
                }
            }
            Box::new(BooleanQuery::new(sub))
        } else {
            let q_trimmed = query.text.trim();
            let mut qp = QueryParser::for_index(&self.index, text_fields.clone());
            if query.match_all_terms {
                qp.set_conjunction_by_default();
            }
            let base_q = qp.parse_query(q_trimmed)?;
            if let Some(hybrid) = build_cjk_hybrid_query(
                &self.fields,
                &text_fields,
                query.scope_filter,
                q_trimmed,
                query.match_all_terms,
            ) {
                Box::new(BooleanQuery::new(vec![
                    (Occur::Should, Box::new(BoostQuery::new(base_q, 2.0))),
                    (Occur::Should, hybrid),
                ]))
            } else {
                base_q
            }
        };

        let mut filter_clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
        let exts = parse_ext_list(query.file_ext_filter.as_deref());
        if exts.len() == 1 {
            filter_clauses.push((
                Occur::Must,
                Box::new(TermQuery::new(
                    Term::from_field_text(self.fields.file_ext, &exts[0]),
                    IndexRecordOption::Basic,
                )),
            ));
        } else if exts.len() > 1 {
            let ext_or: Vec<(Occur, Box<dyn Query>)> = exts
                .into_iter()
                .map(|ext| {
                    let tq = TermQuery::new(
                        Term::from_field_text(self.fields.file_ext, &ext),
                        IndexRecordOption::Basic,
                    );
                    (Occur::Should, Box::new(tq) as Box<dyn Query>)
                })
                .collect();
            filter_clauses.push((Occur::Must, Box::new(BooleanQuery::new(ext_or))));
        }

        if let Some(allowed_ids) = self.find_doc_ids_filtered(query.path_prefix.as_deref(), None)? {
            if allowed_ids.is_empty() {
                return Ok((0, Vec::new()));
            }
            let terms: Vec<Term> = allowed_ids
                .into_iter()
                .map(|id| Term::from_field_u64(self.fields.doc_id, id))
                .collect();
            filter_clauses.push((Occur::Must, Box::new(TermSetQuery::new(terms))));
        }

        let final_query: Box<dyn Query> = if filter_clauses.is_empty() {
            main_query
        } else {
            filter_clauses.insert(0, (Occur::Must, main_query));
            Box::new(BooleanQuery::new(filter_clauses))
        };

        let limit = query.limit.clamp(1, 2000);
        let (total_hits, top_docs) = searcher.search(
            &*final_query,
            &(
                Count,
                TopDocs::with_limit(limit)
                    .and_offset(query.offset)
                    .order_by_score(),
            ),
        )?;

        let terms: Vec<String> = query
            .text
            .split_whitespace()
            .map(|s| s.trim_matches('"').to_string())
            .filter(|s| !s.is_empty() && !matches!(s.to_ascii_uppercase().as_str(), "AND" | "OR" | "NOT"))
            .collect();

        let compiled_snippet_re = compile_search_regex(&terms, query.use_regex);
        let mut items = Vec::with_capacity(top_docs.len());
        for (score, addr) in top_docs {
            let retrieved: tantivy::TantivyDocument = searcher.doc(addr)?;
            let Some(doc_id) = retrieved
                .get_first(self.fields.doc_id)
                .and_then(|v| v.as_u64())
            else {
                continue;
            };
            if let Ok(ed) = self.load_extracted_document(doc_id) {
                let snippets = extract_query_snippets_fast(&ed, &terms, compiled_snippet_re.as_ref(), 3);
                items.push(SearchHitItem {
                    doc_id,
                    score,
                    virtual_path: ed.virtual_path,
                    file_name: ed.file_name,
                    detected_format: ed.detected_format,
                    blake3_hex: ed.blake3_hex,
                    byte_size: ed.byte_size,
                    snippets,
                });
            }
        }

        Ok((total_hits, items))
    }

    pub fn get_preview(
        &self,
        doc_id: u64,
        highlight_terms: &[String],
        max_chars: usize,
    ) -> Result<DocumentPreview, IndexerError> {
        let doc = self.load_extracted_document(doc_id)?;
        Ok(build_document_preview(doc_id, doc, highlight_terms, max_chars))
    }

    /// Evaluate a compiled `RuleSet` across all indexed documents (or selected `doc_ids`),
    /// reusing `rule_hit_cache` keyed by `(doc_blake3, ruleset_fingerprint)`.
    pub fn evaluate_rules_over_store(
        &self,
        compiled: &CompiledRuleSet,
        target_doc_ids: Option<&[u64]>,
    ) -> Result<Vec<HitRecord>, IndexerError> {
        struct DocRow {
            doc_id: u64,
            blake3: String,
            virtual_path: String,
            file_name: String,
            detected_format: String,
            byte_size: u64,
            encrypted: bool,
            warnings_json: String,
        }

        let ext_filter = if target_doc_ids.is_none() {
            compiled.prefilter_file_extensions()
        } else {
            None
        };
        let has_fname_scope = compiled.has_filename_scope();

        let (doc_rows, cache_map, unique_blobs): (
            Vec<DocRow>,
            std::collections::HashMap<String, (i64, Vec<u8>)>,
            std::collections::HashMap<String, Vec<u8>>,
        ) = {
            let conn = self.conn.lock().unwrap();
            let mut rows_out = Vec::new();
            if let Some(ids) = target_doc_ids {
                let mut stmt = conn.prepare_cached(
                    "SELECT blake3, virtual_path, file_name, detected_format, byte_size, encrypted, warnings_json FROM documents WHERE doc_id = ?1",
                )?;
                for &id in ids {
                    if let Some(row) = stmt
                        .query_row(params![id as i64], |r| {
                            Ok(DocRow {
                                doc_id: id,
                                blake3: r.get(0)?,
                                virtual_path: r.get(1)?,
                                file_name: r.get(2)?,
                                detected_format: r.get(3)?,
                                byte_size: r.get::<_, i64>(4)? as u64,
                                encrypted: r.get::<_, i64>(5)? != 0,
                                warnings_json: r.get(6)?,
                            })
                        })
                        .optional()?
                    {
                        rows_out.push(row);
                    }
                }
            } else {
                let mut stmt = conn.prepare(
                    "SELECT doc_id, blake3, virtual_path, file_name, file_ext, detected_format, byte_size, encrypted, warnings_json FROM documents WHERE status = 'ok'",
                )?;
                let mut qrows = stmt.query([])?;
                while let Some(r) = qrows.next()? {
                    let ext: String = r.get(4)?;
                    if let Some(ref allowed) = ext_filter {
                        if !allowed.iter().any(|e| e == &ext) {
                            continue;
                        }
                    }
                    rows_out.push(DocRow {
                        doc_id: r.get::<_, i64>(0)? as u64,
                        blake3: r.get(1)?,
                        virtual_path: r.get(2)?,
                        file_name: r.get(3)?,
                        detected_format: r.get(5)?,
                        byte_size: r.get::<_, i64>(6)? as u64,
                        encrypted: r.get::<_, i64>(7)? != 0,
                        warnings_json: r.get(8)?,
                    });
                }
            }

            let mut cache = std::collections::HashMap::new();
            if !has_fname_scope && !rows_out.is_empty() {
                let mut cstmt = conn.prepare(
                    "SELECT doc_blake3, matched, hits_msgpack FROM rule_hit_cache WHERE ruleset_hash = ?1",
                )?;
                let mut crows = cstmt.query(params![&compiled.fingerprint])?;
                while let Some(r) = crows.next()? {
                    cache.insert(r.get::<_, String>(0)?, (r.get::<_, i64>(1)?, r.get::<_, Vec<u8>>(2)?));
                }
            }

            let mut blobs = std::collections::HashMap::new();
            if !rows_out.is_empty() {
                let mut bstmt = conn.prepare_cached(
                    "SELECT zstd_segments FROM content_blobs WHERE blake3 = ?1",
                )?;
                for row in &rows_out {
                    if !has_fname_scope && cache.contains_key(&row.blake3) {
                        continue;
                    }
                    if !blobs.contains_key(&row.blake3) {
                        if let Some(z) = bstmt
                            .query_row(params![&row.blake3], |r| r.get::<_, Vec<u8>>(0))
                            .optional()?
                        {
                            blobs.insert(row.blake3.clone(), z);
                        }
                    }
                }
            }

            (rows_out, cache, blobs)
        };

        let mut all_hits = Vec::new();
        let mut to_eval: Vec<&DocRow> = Vec::new();
        let mut seen_uncached_b3: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut dup_rows_by_b3: std::collections::HashMap<&str, Vec<&DocRow>> =
            std::collections::HashMap::new();

        for row in &doc_rows {
            if !has_fname_scope {
                if let Some((matched, blob)) = cache_map.get(&row.blake3) {
                    if *matched != 0 {
                        if let Ok(mut hits) = rmp_serde::from_slice::<Vec<HitRecord>>(blob) {
                            for h in &mut hits {
                                h.doc_id = row.doc_id;
                                h.virtual_path = row.virtual_path.clone();
                                h.file_name = row.file_name.clone();
                            }
                            all_hits.extend(hits);
                        }
                    }
                    continue;
                }
                if seen_uncached_b3.insert(&row.blake3) {
                    to_eval.push(row);
                } else {
                    dup_rows_by_b3.entry(&row.blake3).or_default().push(row);
                }
            } else {
                to_eval.push(row);
            }
        }

        if !to_eval.is_empty() {
            let workers = std::thread::available_parallelism()
                .map(|n| n.get().clamp(1, 6))
                .unwrap_or(2)
                .min(to_eval.len());
            let chunk_size = to_eval.len().div_ceil(workers);

            let eval_outputs: Vec<Vec<(&DocRow, Vec<HitRecord>)>> = std::thread::scope(|s| {
                let unique_blobs_ref = &unique_blobs;
                let mut handles = Vec::with_capacity(workers);
                for chunk in to_eval.chunks(chunk_size) {
                    handles.push(s.spawn(move || {
                        let mut out = Vec::with_capacity(chunk.len());
                        for &row in chunk {
                            let Some(zblob) = unique_blobs_ref.get(&row.blake3) else {
                                continue;
                            };
                            let Ok(raw_mp) = zstd::bulk::decompress(zblob, 128 * 1024 * 1024) else {
                                continue;
                            };
                            let Ok(payload) = rmp_serde::from_slice::<StoredBlobPayload>(&raw_mp) else {
                                continue;
                            };
                            let warnings: Vec<String> =
                                serde_json::from_str(&row.warnings_json).unwrap_or_default();
                            let ed = ExtractedDocument {
                                virtual_path: row.virtual_path.clone(),
                                file_name: row.file_name.clone(),
                                detected_format: row.detected_format.clone(),
                                blake3_hex: row.blake3.clone(),
                                byte_size: row.byte_size,
                                encrypted: row.encrypted,
                                segments: payload.segments,
                                metadata: payload.metadata,
                                warnings,
                            };
                            let (hits, _) = compiled.evaluate_document(row.doc_id, &ed, 5);
                            out.push((row, hits));
                        }
                        out
                    }));
                }
                handles.into_iter().filter_map(|h| h.join().ok()).collect()
            });

            let mut cache_updates: Vec<(&str, i64, Vec<u8>)> = Vec::new();
            for chunk_res in eval_outputs {
                for (row, hits) in chunk_res {
                    if !has_fname_scope {
                        let matched = if hits.is_empty() { 0i64 } else { 1i64 };
                        let encoded = rmp_serde::to_vec(&hits).unwrap_or_default();
                        cache_updates.push((row.blake3.as_str(), matched, encoded));
                        if !hits.is_empty() {
                            if let Some(dups) = dup_rows_by_b3.get(row.blake3.as_str()) {
                                for dup in dups {
                                    let mut cloned = hits.clone();
                                    for h in &mut cloned {
                                        h.doc_id = dup.doc_id;
                                        h.virtual_path = dup.virtual_path.clone();
                                        h.file_name = dup.file_name.clone();
                                    }
                                    all_hits.extend(cloned);
                                }
                            }
                        }
                    }
                    all_hits.extend(hits);
                }
            }

            if !cache_updates.is_empty() {
                let conn = self.conn.lock().unwrap();
                let tx = conn.unchecked_transaction()?;
                {
                    let mut cstmt = tx.prepare_cached(
                        "INSERT OR REPLACE INTO rule_hit_cache (doc_blake3, ruleset_hash, matched, hits_msgpack) VALUES (?1, ?2, ?3, ?4)",
                    )?;
                    for (b3, matched, encoded) in cache_updates {
                        let _ = cstmt.execute(params![b3, &compiled.fingerprint, matched, encoded]);
                    }
                }
                tx.commit()?;
            }
        }

        Ok(all_hits)
    }

    pub fn stats(&self) -> Result<IndexStats, IndexerError> {
        let conn = self.conn.lock().unwrap();
        let total_documents: i64 = conn.query_row("SELECT COUNT(*) FROM documents", [], |r| r.get(0))?;
        let unique_content_blobs: i64 =
            conn.query_row("SELECT COUNT(*) FROM content_blobs", [], |r| r.get(0))?;
        let ocr_cached_images: i64 =
            conn.query_row("SELECT COUNT(*) FROM ocr_image_cache", [], |r| r.get(0))?;
        let encrypted_documents: i64 =
            conn.query_row("SELECT COUNT(*) FROM documents WHERE encrypted = 1", [], |r| r.get(0))?;
        let failed_documents: i64 =
            conn.query_row("SELECT COUNT(*) FROM documents WHERE status != 'ok'", [], |r| r.get(0))?;
        let total_raw_chars: i64 = conn
            .query_row("SELECT COALESCE(SUM(total_chars), 0) FROM content_blobs", [], |r| r.get(0))?;

        let db_size_bytes = std::fs::metadata(&self.db_path).map(|m| m.len()).unwrap_or(0);
        let tantivy_size_bytes = dir_size(&self.tantivy_dir);

        Ok(IndexStats {
            total_documents: total_documents as u64,
            unique_content_blobs: unique_content_blobs as u64,
            ocr_cached_images: ocr_cached_images as u64,
            encrypted_documents: encrypted_documents as u64,
            failed_documents: failed_documents as u64,
            total_raw_chars: total_raw_chars as u64,
            db_size_bytes,
            tantivy_size_bytes,
        })
    }

    /// Resolve matching `doc_id`s for directory prefix and/or extension list filters.
    /// Returns `Ok(None)` when neither filter is active.
    pub fn find_doc_ids_filtered(
        &self,
        path_prefix: Option<&str>,
        file_ext_filter: Option<&str>,
    ) -> Result<Option<Vec<u64>>, IndexerError> {
        let prefix_norm = path_prefix
            .map(normalize_win_path)
            .filter(|s| !s.is_empty());
        let exts = parse_ext_list(file_ext_filter);
        if prefix_norm.is_none() && exts.is_empty() {
            return Ok(None);
        }

        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT doc_id, virtual_path, file_ext FROM documents")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;

        let mut matched = Vec::new();
        for row in rows {
            let (doc_id, vp, fext) = row?;
            if !exts.is_empty() && !exts.iter().any(|e| e.eq_ignore_ascii_case(&fext)) {
                continue;
            }
            if let Some(ref p) = prefix_norm {
                if !path_matches_dir_prefix(&vp, p) {
                    continue;
                }
            }
            matched.push(doc_id);
        }
        Ok(Some(matched))
    }

    /// Physically purge deleted document traces from both SQLite (`secure_delete + VACUUM + WAL truncate`)
    /// and Tantivy (merge segments to strip deleted terms + reload reader + garbage collect old segment files).
    pub fn secure_compact_after_delete(&self) -> Result<(), IndexerError> {
        let _ = self.prune_orphaned_blobs()?;
        {
            let mut writer_guard = self.writer.lock().unwrap();
            let mut writer = match writer_guard.take() {
                Some(w) => w,
                None => self.index.writer(32 * 1024 * 1024)?,
            };
            writer.commit()?;
            let seg_ids = self.index.searchable_segment_ids()?;
            if !seg_ids.is_empty() {
                let _ = writer.merge(&seg_ids).wait();
            }
            writer.commit()?;
            self.reader.reload()?;
            let _ = writer.garbage_collect_files().wait();
            let _ = writer.wait_merging_threads();
        }
        {
            let conn = self.conn.lock().unwrap();
            conn.pragma_update(None, "secure_delete", "ON")?;
            conn.execute_batch(
                "PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);",
            )?;
        }
        Ok(())
    }

    pub fn clear_all(&self) -> Result<(), IndexerError> {
        self.reset_index_tables(true)
    }

    /// Clear indexed documents, content blobs, rule cache, and USN checkpoints while preserving
    /// persistent `ocr_image_cache` so manual rebuild avoids re-running expensive image OCR.
    pub fn reset_keep_ocr_cache(&self) -> Result<(), IndexerError> {
        self.reset_index_tables(false)
    }

    fn reset_index_tables(&self, clear_ocr_cache: bool) -> Result<(), IndexerError> {
        {
            let conn = self.conn.lock().unwrap();
            let sql = if clear_ocr_cache {
                "DELETE FROM rule_hit_cache; DELETE FROM documents; DELETE FROM content_blobs; DELETE FROM ocr_image_cache; DELETE FROM usn_checkpoints;"
            } else {
                "DELETE FROM rule_hit_cache; DELETE FROM documents; DELETE FROM content_blobs; DELETE FROM usn_checkpoints;"
            };
            conn.execute_batch(sql)?;
        }
        {
            let mut writer_guard = self.writer.lock().unwrap();
            let writer = self.ensure_writer(&mut writer_guard)?;
            writer.delete_all_documents()?;
        }
        self.commit_and_release()?;
        Ok(())
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

const MAX_STORED_SEGMENT_BYTES: usize = 4 * 1024 * 1024;

/// Cap persisted preview segments in `content_blobs` so outlier multi-megabyte documents do not bloat SQLite
/// while keeping full text indexed in Tantivy.
fn cap_segments_for_storage(segments: &[TextSegment], max_bytes: usize) -> Vec<TextSegment> {
    let mut out = Vec::with_capacity(segments.len());
    let mut used = 0usize;
    for seg in segments {
        if used >= max_bytes {
            break;
        }
        let avail = max_bytes - used;
        if seg.text.len() <= avail {
            used += seg.text.len();
            out.push(seg.clone());
        } else {
            let cut = seg.text.floor_char_boundary(avail);
            let mut clipped = seg.text[..cut].to_string();
            clipped.push_str("\n[...SQLite 预览快照已裁剪至 4 MiB，全文仍保留在倒排索引中...]");
            out.push(TextSegment {
                scope: seg.scope,
                location_label: seg.location_label.clone(),
                text: clipped,
            });
            break;
        }
    }
    out
}

pub fn build_document_preview(
    doc_id: u64,
    doc: ExtractedDocument,
    highlight_terms: &[String],
    max_chars: usize,
) -> DocumentPreview {
    let cap = if max_chars == 0 { 200_000 } else { max_chars };
    let mut used = 0usize;
    let mut truncated = false;
    let mut preview_segs = Vec::new();

    for seg in doc.segments {
        if used >= cap {
            truncated = true;
            break;
        }
        let remaining = cap - used;
        let char_count = seg.text.chars().count();
        let text_slice = if char_count > remaining {
            truncated = true;
            seg.text.chars().take(remaining).collect::<String>()
        } else {
            seg.text
        };
        used += text_slice.chars().count();
        let ranges = find_highlight_char_ranges(&text_slice, highlight_terms);
        preview_segs.push(PreviewSegment {
            scope: seg.scope,
            location_label: seg.location_label,
            text: text_slice,
            highlight_ranges: ranges,
        });
    }

    DocumentPreview {
        doc_id,
        virtual_path: doc.virtual_path,
        file_name: doc.file_name,
        detected_format: doc.detected_format,
        blake3_hex: doc.blake3_hex,
        byte_size: doc.byte_size,
        encrypted: doc.encrypted,
        metadata: doc.metadata,
        segments: preview_segs,
        truncated,
    }
}

fn dir_size(p: &Path) -> u64 {
    std::fs::read_dir(p)
        .map(|it| {
            it.flatten()
                .map(|e| {
                    if e.path().is_dir() {
                        dir_size(&e.path())
                    } else {
                        e.metadata().map(|m| m.len()).unwrap_or(0)
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}

fn init_sqlite_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS documents (
            doc_id INTEGER PRIMARY KEY AUTOINCREMENT,
            virtual_path TEXT UNIQUE NOT NULL,
            source_root TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_ext TEXT NOT NULL,
            detected_format TEXT NOT NULL,
            blake3 TEXT NOT NULL,
            byte_size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            encrypted INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            warnings_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_docs_blake3 ON documents(blake3);
        CREATE INDEX IF NOT EXISTS idx_docs_ext ON documents(file_ext);

        CREATE TABLE IF NOT EXISTS content_blobs (
            blake3 TEXT PRIMARY KEY,
            total_chars INTEGER NOT NULL,
            segment_count INTEGER NOT NULL,
            zstd_segments BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ocr_image_cache (
            img_blake3 TEXT PRIMARY KEY,
            width INTEGER NOT NULL,
            height INTEGER NOT NULL,
            ocr_text TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rule_hit_cache (
            doc_blake3 TEXT NOT NULL,
            ruleset_hash TEXT NOT NULL,
            matched INTEGER NOT NULL,
            hits_msgpack BLOB NOT NULL,
            PRIMARY KEY (doc_blake3, ruleset_hash)
        );

        CREATE TABLE IF NOT EXISTS usn_checkpoints (
            drive_root TEXT PRIMARY KEY,
            journal_id INTEGER NOT NULL,
            next_usn INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );",
    )
}

fn build_schema() -> (Schema, SchemaFields) {
    let mut b = Schema::builder();
    let jieba_pos_opts = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer("jieba")
            .set_index_option(IndexRecordOption::WithFreqsAndPositions),
    );
    let ng_pos_opts = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer("ngram3")
            .set_index_option(IndexRecordOption::WithFreqsAndPositions),
    );
    let cjk_bi_pos_opts = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer("cjk_bi")
            .set_index_option(IndexRecordOption::WithFreqsAndPositions),
    );

    let doc_id = b.add_u64_field("doc_id", INDEXED | STORED | FAST);
    let blake3 = b.add_text_field("blake3", STRING);
    let file_ext = b.add_text_field("file_ext", STRING | FAST);
    let virtual_path = b.add_text_field("virtual_path", jieba_pos_opts.clone());
    let file_name = b.add_text_field("file_name", jieba_pos_opts.clone());
    let file_name_ng = b.add_text_field("file_name_ng", ng_pos_opts);
    let fn_cjk_bi = b.add_text_field("fn_cjk_bi", cjk_bi_pos_opts.clone());
    let head_tail = b.add_text_field("head_tail", jieba_pos_opts.clone());
    let body = b.add_text_field("body", jieba_pos_opts.clone());
    let ocr_text = b.add_text_field("ocr_text", jieba_pos_opts.clone());
    let table_data = b.add_text_field("table_data", jieba_pos_opts.clone());
    let metadata = b.add_text_field("metadata", jieba_pos_opts);
    let txt_cjk_bi = b.add_text_field("txt_cjk_bi", cjk_bi_pos_opts);

    let schema = b.build();
    let fields = SchemaFields {
        doc_id,
        blake3,
        file_ext,
        virtual_path,
        file_name,
        file_name_ng,
        fn_cjk_bi,
        head_tail,
        body,
        ocr_text,
        table_data,
        metadata,
        txt_cjk_bi,
    };
    (schema, fields)
}

fn parse_ext_list(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or("")
        .split([',', ';', ' ', '|'])
        .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn normalize_win_path(p: &str) -> String {
    let mut s = p.trim().replace('/', "\\").to_ascii_lowercase();
    while s.len() > 1 && s.ends_with('\\') {
        s.pop();
    }
    s
}

fn path_matches_dir_prefix(virtual_path: &str, prefix_norm: &str) -> bool {
    let vp = virtual_path.replace('/', "\\").to_ascii_lowercase();
    if vp == prefix_norm {
        return true;
    }
    if let Some(rest) = vp.strip_prefix(prefix_norm) {
        rest.starts_with('\\') || rest.starts_with("!/") || rest.starts_with("!\\")
    } else {
        false
    }
}

/// Build a boundary-free CJK bigram + alphanumeric rescue query for plain keyword searches
/// so compound Chinese phrases match regardless of word segmentation boundaries.
fn build_cjk_hybrid_query(
    fields: &SchemaFields,
    jieba_fields: &[Field],
    scope_filter: Option<SegmentScope>,
    raw_query: &str,
    match_all_terms: bool,
) -> Option<Box<dyn Query>> {
    // Only apply rescue when query uses plain whitespace/keyword syntax and contains CJK chars.
    if !raw_query.chars().any(is_cjk_char)
        || raw_query.contains(['"', ':', '(', ')', '+', '*'])
        || raw_query.split_whitespace().any(|w| {
            w.starts_with('-') || matches!(w, "AND" | "OR" | "NOT")
        })
    {
        return None;
    }

    let cjk_bi_fields: Vec<Field> = match scope_filter {
        None => vec![fields.fn_cjk_bi, fields.txt_cjk_bi],
        Some(SegmentScope::FileName) => vec![fields.fn_cjk_bi],
        // Individual sub-scopes (Ocr/Table/HeadTail/Body/Metadata) do not share `txt_cjk_bi`.
        Some(_) => return None,
    };

    let mut top_clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
    let mut used_cjk_bigram = false;
    let term_occur = if match_all_terms {
        Occur::Must
    } else {
        Occur::Should
    };

    for word in raw_query.split_whitespace() {
        let mut word_clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
        let mut cjk_run = Vec::new();
        let mut ascii_buf = String::new();

        let flush_ascii = |buf: &mut String, out: &mut Vec<(Occur, Box<dyn Query>)>| {
            if buf.is_empty() {
                return;
            }
            let lower = buf.to_ascii_lowercase();
            buf.clear();
            let subs: Vec<(Occur, Box<dyn Query>)> = jieba_fields
                .iter()
                .map(|&f| {
                    let tq = TermQuery::new(Term::from_field_text(f, &lower), IndexRecordOption::Basic);
                    (Occur::Should, Box::new(tq) as Box<dyn Query>)
                })
                .collect();
            if !subs.is_empty() {
                out.push((Occur::Must, Box::new(BooleanQuery::new(subs))));
            }
        };

        let flush_cjk = |run: &mut Vec<char>,
                         out: &mut Vec<(Occur, Box<dyn Query>)>,
                         used_bigram: &mut bool| {
            if run.is_empty() {
                return;
            }
            if run.len() == 1 {
                let s: String = run.iter().collect();
                let subs: Vec<(Occur, Box<dyn Query>)> = jieba_fields
                    .iter()
                    .map(|&f| {
                        let tq = TermQuery::new(Term::from_field_text(f, &s), IndexRecordOption::Basic);
                        (Occur::Should, Box::new(tq) as Box<dyn Query>)
                    })
                    .collect();
                if !subs.is_empty() {
                    out.push((Occur::Must, Box::new(BooleanQuery::new(subs))));
                }
            } else {
                *used_bigram = true;
                let bigrams: Vec<String> = run
                    .windows(2)
                    .map(|w| {
                        let mut b = String::with_capacity(6);
                        b.push(w[0]);
                        b.push(w[1]);
                        b
                    })
                    .collect();
                let subs: Vec<(Occur, Box<dyn Query>)> = cjk_bi_fields
                    .iter()
                    .map(|&f| {
                        if bigrams.len() == 1 {
                            let tq = TermQuery::new(
                                Term::from_field_text(f, &bigrams[0]),
                                IndexRecordOption::Basic,
                            );
                            (Occur::Should, Box::new(tq) as Box<dyn Query>)
                        } else {
                            let terms: Vec<Term> =
                                bigrams.iter().map(|b| Term::from_field_text(f, b)).collect();
                            (Occur::Should, Box::new(PhraseQuery::new(terms)) as Box<dyn Query>)
                        }
                    })
                    .collect();
                if !subs.is_empty() {
                    out.push((Occur::Must, Box::new(BooleanQuery::new(subs))));
                }
            }
            run.clear();
        };

        for ch in word.chars() {
            if is_cjk_char(ch) {
                flush_ascii(&mut ascii_buf, &mut word_clauses);
                cjk_run.push(ch);
            } else if ch.is_alphanumeric() {
                flush_cjk(&mut cjk_run, &mut word_clauses, &mut used_cjk_bigram);
                ascii_buf.push(ch);
            } else {
                flush_ascii(&mut ascii_buf, &mut word_clauses);
                flush_cjk(&mut cjk_run, &mut word_clauses, &mut used_cjk_bigram);
            }
        }
        flush_ascii(&mut ascii_buf, &mut word_clauses);
        flush_cjk(&mut cjk_run, &mut word_clauses, &mut used_cjk_bigram);

        if word_clauses.len() == 1 {
            top_clauses.push((term_occur, word_clauses.pop().unwrap().1));
        } else if !word_clauses.is_empty() {
            top_clauses.push((term_occur, Box::new(BooleanQuery::new(word_clauses))));
        }
    }

    if !used_cjk_bigram || top_clauses.is_empty() {
        return None;
    }
    Some(Box::new(BooleanQuery::new(top_clauses)))
}

fn compile_search_regex(terms: &[String], use_regex: bool) -> Option<regex::Regex> {
    if terms.is_empty() {
        return None;
    }
    if use_regex {
        return regex::Regex::new(&terms.join(" ")).ok();
    }
    let parts: Vec<String> = terms
        .iter()
        .filter(|t| !t.is_empty())
        .map(|t| regex::escape(t))
        .collect();
    if parts.is_empty() {
        return None;
    }
    regex::RegexBuilder::new(&parts.join("|"))
        .case_insensitive(true)
        .build()
        .ok()
}

fn extract_query_snippets_fast(
    doc: &ExtractedDocument,
    terms: &[String],
    compiled_re: Option<&regex::Regex>,
    max_snips: usize,
) -> Vec<HitLocationSnippet> {
    let mut out = Vec::new();
    if terms.is_empty() {
        if let Some(first) = doc.segments.first() {
            let preview: String = first.text.chars().take(100).collect();
            out.push(HitLocationSnippet {
                scope: first.scope,
                location_label: first.location_label.clone(),
                matched_term: String::new(),
                snippet: preview.replace(['\r', '\n'], " "),
                match_start_char: 0,
                match_len_char: 0,
            });
        }
        return out;
    }

    if let Some(rx) = compiled_re {
        for seg in &doc.segments {
            if out.len() >= max_snips {
                break;
            }
            if let Some(m) = rx.find(&seg.text) {
                out.push(slice_snippet(seg, m.as_str(), m.start(), m.end()));
            }
        }
    }
    out
}

fn slice_snippet(seg: &TextSegment, term: &str, bs: usize, be: usize) -> HitLocationSnippet {
    let match_ci_len = seg.text[bs..be].chars().count();
    let mut bws = 0usize;
    let mut ws_chars = 0usize;
    for (count, (idx, _)) in seg.text[..bs].char_indices().rev().enumerate() {
        bws = idx;
        ws_chars = count + 1;
        if count >= 29 {
            break;
        }
    }
    let has_lead = bws > 0;

    let mut bwe = seg.text.len();
    let mut has_tail = false;
    for (count, (rel_idx, ch)) in seg.text[be..].char_indices().enumerate() {
        if count >= 50 {
            bwe = be + rel_idx;
            has_tail = true;
            break;
        }
        bwe = be + rel_idx + ch.len_utf8();
    }

    let mut snippet = String::new();
    let mut lead = 0;
    if has_lead {
        snippet.push_str("...");
        lead = 3;
    }
    snippet.push_str(&seg.text[bws..bwe].replace(['\r', '\n'], " "));
    if has_tail {
        snippet.push_str("...");
    }
    HitLocationSnippet {
        scope: seg.scope,
        location_label: seg.location_label.clone(),
        matched_term: term.to_string(),
        snippet,
        match_start_char: lead + ws_chars,
        match_len_char: match_ci_len,
    }
}

fn find_highlight_char_ranges(text: &str, terms: &[String]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let Some(rx) = compile_search_regex(terms, false) else {
        return ranges;
    };
    let mut last_byte = 0usize;
    let mut last_char = 0usize;
    for m in rx.find_iter(text).take(500) {
        let bs = m.start();
        let be = m.end();
        last_char += text[last_byte..bs].chars().count();
        let ci_start = last_char;
        let ci_len = text[bs..be].chars().count();
        last_char += ci_len;
        last_byte = be;
        ranges.push((ci_start, ci_len));
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ocr_cache_usn_checkpoint_prune_and_segment_cap_work() {
        let dir = std::env::temp_dir().join(format!("deepdoc_idx_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = IndexStore::open(&dir).expect("open store");

        // 1. OCR cache roundtrip
        store
            .upsert_ocr_cache_batch(&[
                ("hash-a".into(), 640, 480, "图章识别文本".into()),
                ("hash-b".into(), 120, 80, "".into()),
            ])
            .unwrap();
        let warm = store.load_ocr_cache(100).unwrap();
        assert_eq!(warm.len(), 2);

        // 2. USN checkpoint roundtrip
        assert_eq!(store.get_usn_checkpoint("D:\\").unwrap(), None);
        store.set_usn_checkpoint("D:\\", 987654321, 4096).unwrap();
        assert_eq!(store.get_usn_checkpoint("D:\\").unwrap(), Some((987654321, 4096)));

        // 3. Oversized segment snapshot cap (full Tantivy index still receives full text)
        let huge = "ABCD ".repeat(1_200_000) + "UNIQUE_END_TOKEN";
        let doc = ExtractedDocument {
            virtual_path: "D:\\big.txt".into(),
            file_name: "big.txt".into(),
            detected_format: "txt".into(),
            blake3_hex: "b3-big".into(),
            byte_size: huge.len() as u64,
            encrypted: false,
            segments: vec![TextSegment {
                scope: SegmentScope::Body,
                location_label: "正文".into(),
                text: huge,
            }],
            metadata: vec![],
            warnings: vec![],
        };
        let doc_id = store.upsert_document("D:\\", &doc, 100, "ok").unwrap();
        store.commit_and_release().unwrap();

        let (hits, _) = store
            .search(&SearchQuery {
                text: "UNIQUE_END_TOKEN".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(hits, 1);

        let loaded = store.load_extracted_document(doc_id).unwrap();
        assert!(loaded.segments[0].text.len() <= MAX_STORED_SEGMENT_BYTES + 256);

        // 4. Remove by path (and nested child) + prune
        let child = ExtractedDocument {
            virtual_path: "D:\\big.txt!/inner.txt".into(),
            file_name: "inner.txt".into(),
            detected_format: "txt".into(),
            blake3_hex: "b3-inner".into(),
            byte_size: 5,
            encrypted: false,
            segments: vec![],
            metadata: vec![],
            warnings: vec![],
        };
        store.upsert_document("D:\\", &child, 100, "ok").unwrap();
        let removed = store.remove_documents_by_paths(&["D:\\big.txt".into()]).unwrap();
        assert_eq!(removed, 2);
        store.commit_and_release().unwrap();
        assert!(store.prune_orphaned_blobs().unwrap() >= 1);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
