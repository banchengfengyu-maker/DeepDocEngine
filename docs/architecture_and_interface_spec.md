# 深度文档内容解析与关键词/布尔/正则检索系统《架构与接口设计规格书》

> **工程代号**：`DeepDocEngine`  
> **核心路线**：C# WPF (.NET 8) 外壳 + Rust 核心守护进程 + 双层沙箱 Worker 池（成熟 C/C++ 库隔离）  
> **设计原则**：以稳为主、零从零造轮子、64 位全链路、权限与崩溃隔离、分发便捷、可溯源检索  

---

## 1. 总体进程拓扑与合规/稳定性边界

系统采用**四进程角色、三层隔离**拓扑，确保“GUI 永不闪退、主索引服务不断线、高危/GPL C++ 组件可独立分发与回收”。

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ 进程 1: App.UI.exe (C# WPF / .NET 8, 普通用户权限)                        │
│  - 拖拽文件/目录 (无 UIPI 阻塞)   - 布尔/正则规则编辑器                    │
│  - 虚拟化百万级结果列表           - 命中位置溯源与原文/OCR 高亮预览         │
└───────────────────────────────▲──────────────────────────────────────────┘
                                │ Windows Named Pipe (4B LE Len + MessagePack)
                                │ \\.\pipe\DeepDocEngine.<tag>  (仅本机 DACL)
┌───────────────────────────────▼──────────────────────────────────────────┐
│ 进程 2: engine-daemon.exe (Rust, 全 MIT/Apache-2.0 依赖, 可按需提权)      │
│  - 任务调度与 Job Object Worker 池监管 (超时强杀 / 内存上限 / 自动重启)     │
│  - Win32 NTFS USN Journal / $MFT$ 文件枚举与增量监控                       │
│  - Tantivy 全文倒排索引 (jieba + N-gram 双字段)                            │
│  - SQLite + Zstd 非截断原文分块缓存 + BLAKE3 内容去重 + 规则命中缓存        │
│  - 两阶段规则引擎 (AST 编译器 -> Aho-Corasick 粗筛 -> RegexSet 单趟精算)    │
└───────────────┬──────────────────────────────────────────┬───────────────┘
                │ stdin/stdout Binary Frame (Job Object)   │ stdin/stdout Binary Frame (Job Object)
┌───────────────▼──────────────────────────┐ ┌─────────────▼───────────────┐
│ 进程 3: parser-worker.exe (标准沙箱池)     │ │ 进程 4: ext-worker.exe      │
│  [Permissive / Apache / MIT / BSD]       │ │  [可选 GPL/重型取证沙箱]     │
│  - 魔数嗅探 + 递归解包 (Zip Bomb 熔断)     │ │  - LibreDWG (.dwg)          │
│  - 纯 Rust 解析: TXT/CSV/HTML/RTF/OOXML/  │ │  - libpst/libpff (.pst/.ost)│
│    ODF/OFD/UOF/XMind/EPUB/EML/MSG/DXF    │ │  - libtsk + libyal          │
│  - PDFium 文本抽取 & 扫描页渲染            │ │    (VMDK/VHDX/QCOW2/未分配) │
│  - ONNX Runtime + PP-OCRv4 (BLAKE3 去重) │ │  - GDAL/OGR (GIS 属性层)     │
│  - ONLYOFFICE Core (x2t.exe) 转换适配器   │ │  - chmlib / djvulibre       │
│    (.doc/.ppt/.wps/.et/.dps -> OOXML)    │ │                             │
│  - 可选 FFmpeg + sherpa-onnx 音视频槽位   │ │  (独立进程/按需分发与审计)    │
└──────────────────────────────────────────┘ └─────────────────────────────┘
```

### 1.1 关键架构决策说明

1. **老二进制 Office / WPS 转换引擎：选定 ONLYOFFICE Core (`x2t`)**
   - 在 `parser-worker` 中通过独立临时沙箱目录调用 `x2t`（将 `.doc / .ppt / .wps / .et / .dps` 转为临时 `.docx / .pptx / .xlsx` 后，直接复用主 Rust OOXML 解析器抽取正文、批注、页眉页脚与 `media/` 内嵌图片）。
   - 相比 LibreOffice，分发体积显著更小，无常驻 UNO 服务锁死问题，且每个文档使用独立临时工作目录，转换完毕即清理。
   - **重要补充**：同步内置 `[MS-OFFCRYPTO]` 加密头侦测（识别 RC4 / XOR / Agile AES / PDF 密码 / 压缩包加密），支持无口令限制编辑自动解密 + 用户密码本自动尝试；无法解密的文件显式标为 `Encrypted`，杜绝安静漏检。

2. **GPL 与重型 C/C++ 组件边界（以方便分发与运行稳定为标准）**
   - **主程序零污染**：`App.UI.exe`、`engine-daemon.exe` 以及标准 `parser-worker.exe` **不链接任何 GPL/AGPL 库**，整体安装包结构清晰、商业/内网分发与许可证审计边界极干净。
   - **双 Worker 统一协议**：将 `LibreDWG`、`libpst`、`The Sleuth Kit (libtsk)` + `libyal`、`GDAL/OGR`、`chmlib`/`djvulibre` 收敛到独立的 `ext-worker.exe`（与 `parser-worker.exe` 共用同一套 `WorkerRequest / WorkerResponse` 二进制帧协议，均受 Windows Job Object 监管）。
   - **分发与运维优势**：核心包即可独立交付常规与现代办公/PDF/OCR/压缩包/邮件解析能力；按需附带 `ext-worker.exe` + `libs/` 即可激活 DWG/PST/GIS/虚拟磁盘取证，且任意扩展格式崩溃只触发单 Worker 重启，主索引服务与 UI 零影响。

3. **方正 CEB / CEBX 边界**：暂不实现（保留 `FormatKind::Ceb` 识别标记，命中时明确上报 `UnsupportedFormat("CEB/CEBX excluded by design")`）。

---

## 2. 跨进程 IPC 通信协议定义

### 2.1 帧封装格式（Named Pipe 与 Worker stdin/stdout 共用）

所有跨进程消息采用**定长帧头 + MessagePack 载荷**：

```text
+-----------------------+-----------------------------------------------+
| Length (4 bytes, u32) | Payload (Length bytes, MessagePack encoded)   |
| Little-Endian         | Max Frame Size: 64 MiB (0x0400_0000)          |
+-----------------------+-----------------------------------------------+
```

### 2.2 UI ↔ Daemon Named Pipe 协议 (`crates/protocol/src/ipc.rs`)

管道名：`\\.\pipe\DeepDocEngine.v1`（支持多实例后缀），使用双工异步流（UI 发 `ClientRequest`，Daemon 推 `DaemonMessage`，包括响应与异步流式事件）：

* **请求类型 `ClientRequest`**：
  * `Ping` -> `Pong { daemon_version, worker_ready, ext_worker_ready, indexed_docs }`
  * `StartScan { job_id, roots: Vec<String>, ruleset: Option<RuleSet>, options: ScanOptions }`
  * `CancelScan { job_id }`
  * `Search { query: SearchQuery }`（支持交互式 Tantivy 查询：`keywords`、布尔式、`file_ext` 过滤、分页与高亮片段）
  * `EvaluateRules { ruleset: RuleSet, target_doc_ids: Option<Vec<u64>> }`（对已索引文档或当前库执行批量敏感策略匹配）
  * `GetDocumentPreview { doc_id: u64, highlight_terms: Vec<String>, max_chars: usize }`（返回分段正文、OCR 文本、位置标签与命中偏移）
  * `GetStats` / `ClearIndex` / `Shutdown`
* **响应与流式事件 `DaemonMessage`**：
  * `Ack { req_id, ok, message }`
  * `ScanProgress { job_id, scanned_files, parsed_ok, skipped_cached, encrypted_files, failed_files, current_path, elapsed_ms }`
  * `ScanHit { job_id, hit: HitRecord }`（命中即实时流式推送给 WPF 列表）
  * `ScanCompleted { job_id, summary: ScanSummary }`
  * `SearchResult { req_id, total_hits, took_ms, items: Vec<SearchHitItem> }`
  * `PreviewResult { req_id, doc: DocumentPreview }`
  * `StatsResult { req_id, stats: IndexStats }`
  * `Error { req_id, code, message }`

### 2.3 Daemon ↔ Worker 协议 (`crates/protocol/src/worker.rs`)

* `WorkerRequest`：
  * `HealthCheck` -> 返回可用引擎能力（如 `pdfium`, `onnx_ocr`, `x2t`, `libarchive`, `libredwg`, `libtsk`）
  * `ParseFile { task_id, path, virtual_path, max_extract_depth, max_uncompressed_bytes, enable_ocr, passwords }`
  * `ParseBytes { task_id, data: ByteBuf, virtual_path, hint_ext, ... }`（用于嵌套归档内层流式对象，避免落盘暴露明文）
* `WorkerResponse`：
  * `Parsed { task_id, doc: ExtractedDocument }`
  * `Failed { task_id, kind: FailureKind, detail }`（区分 `Encrypted`, `Corrupted`, `ZipBombTripped`, `Timeout`, `Unsupported`）

### 2.4 核心统一文档中间模型 `ExtractedDocument`

所有解析器最终产出统一的溯源结构，保留“命中的究竟是正文第几页、Excel 哪张表、还是压缩包里第几层图片 OCR”：

```rust
pub struct ExtractedDocument {
    pub virtual_path: String,        // 例: D:\archive.zip!/预算.xlsx
    pub file_name: String,
    pub detected_format: String,     // 魔数嗅探后的真实格式 (非扩展名)
    pub blake3_hex: String,          // 原始内容哈希 (用于去重与缓存)
    pub byte_size: u64,
    pub encrypted: bool,
    pub segments: Vec<TextSegment>,  // 保留位置标签的分段文本
    pub metadata: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

pub struct TextSegment {
    pub scope: SegmentScope,         // FileName | HeadTail | Body | Ocr | Table | Metadata | Comment
    pub location_label: String,      // 例: "第 4 页 (扫描件 OCR)", "Sheet[预算表] 行18", "word/media/image2.png (OCR)"
    pub text: String,
}
```

---

## 3. 存储与索引模型 (`crates/indexer`)

### 3.1 Tantivy 全文倒排 Schema

| 字段名 | 类型 / Tokenizer | 存储 / 索引用途 |
| :--- | :--- | :--- |
| `doc_id` | `u64` (`INDEXED \| STORED \| FAST`) | SQLite 主键关联与精确过滤 |
| `blake3` | `STRING` (`INDEXED \| STORED`) | 内容去重查询 |
| `virtual_path` | `TEXT` (`jieba` + `STORED`) | 路径检索与嵌套归档展示 |
| `file_name` | `TEXT` (`jieba` + `ngram` + `STORED`) | 文件名关键词与子串命中 |
| `file_ext` | `STRING` (`INDEXED \| STORED \| FAST`) | `file_ext:dwg` 快速过滤 |
| `head_tail` | `TEXT` (`jieba` + `ngram`) | 公文首尾 N 行（红头/密级标志）专用字段 |
| `body` | `TEXT` (`jieba` + `ngram`) | 文档主体文本（兼顾语义分词与精确子串零漏检） |
| `ocr_text` | `TEXT` (`jieba` + `ngram`) | 图片与内嵌图 OCR 识别文本 |
| `table_data` | `TEXT` (`jieba` + `ngram`) | Excel/表格行列文本（保留同行分隔，支持同行约束） |
| `metadata` | `TEXT` (`jieba`) | 作者、标题、GIS 图层/属性元数据、邮件头 |

### 3.2 SQLite + Zstd 原文与缓存表设计

启用 `WAL` 模式 + `zstd` 压缩，彻底解决原版 `VARCHAR(100000)` 截断问题：
1. `documents(doc_id INTEGER PRIMARY KEY, virtual_path TEXT UNIQUE, source_root TEXT, file_name TEXT, file_ext TEXT, detected_format TEXT, blake3 TEXT, byte_size INTEGER, mtime_ns INTEGER, status TEXT, updated_at INTEGER)`
2. `content_blobs(blake3 TEXT PRIMARY KEY, total_chars INTEGER, segment_count INTEGER, zstd_segments BLOB)` —— 序列化全部 `TextSegment` 后 Zstd 压缩存储，任意大文件不截断。
3. `ocr_image_cache(img_blake3 TEXT PRIMARY KEY, width INTEGER, height INTEGER, ocr_text TEXT, updated_at INTEGER)` —— 全文库图片级去重缓存（跳过重复页眉 Logo/印章底图，节省 50%~80% OCR 算力）。
4. `rule_hit_cache(doc_blake3 TEXT, ruleset_hash TEXT, matched INTEGER, hits_json BLOB, PRIMARY KEY(doc_blake3, ruleset_hash))` —— 增量复检命中缓存。

---

## 4. 两阶段布尔 / 正则规则引擎 (`crates/rule-engine`)

### 4.1 支持的规则语法 AST

* **基础项**：字面关键词（`机密`）、精确短语（`"内部采购方案"`）、正则（`re:/绝密\s*★/`）
* **逻辑组合**：`AND` (`&`), `OR` (`|`), `NOT` (`!`), 括号优先级 `(...)`, **至少命中 N 词**（`ATLEAST(2, 词A, 词B, 词C)`）
* **位置限定**：`scope:filename(...)`, `scope:head_tail(...)`, `scope:ocr(...)`, `scope:table(...)`, `same_line(A, B)`（同行共现）
* **匹配模式**：`FirstHit`（命中即停，极速敏感检查）与 `FullHits`（全文统计次数 + 全量位置高亮摘要）

### 4.2 两阶段求值管线

1. **阶段 1（粗筛剪枝）**：
   - 从 AST 自动推导**必要字面锚点集合**（Required Literal Anchors）与候选索引查询；
   - 对内存/批量扫描场景，将全部字面关键词合并编译为单个 **`Aho-Corasick`** 自动机，单趟扫描文档生成词项命中 BitSet；未满足必要字面条件的文件直接在阶段 1 淘汰（>90% 剪枝）。
2. **阶段 2（单趟精算）**：
   - 将规则集内全部正则表达式编译为一个 **`regex::RegexSet`**（组合自动机），对通过阶段 1 的候选文档做单趟正则扫描，再沿规则 AST 树完成布尔逻辑与位置约束求值，产出带 `location_label` 与上下文截取的高亮片段。

---

## 5. 全格式成熟库选型与集成状态矩阵

| 类别 | 格式 | 选型库 / 引擎 | 所在进程 | 状态与兜底 |
| :--- | :--- | :--- | :--- | :--- |
| 文本 / 网页 / PIM / 矢量图 | TXT/LOG/CSV/JSON/XML/HTML/MHT/MD/RTF/SVG/VCF/ICS | `encoding_rs`, `chardetng`, `quick-xml`, `scraper`, `pulldown-cmark`, `csv`, `mail-parser` | `parser-worker` (纯 Rust) | **内置直通**（自动检测编码 + MHT 内嵌图片 OCR） |
| 现代 Office / 版式 / 导图 / 电子书 | DOCX/XLSX/XLSM/XLSB/XLS/PPTX/ODS/ODT/ODP/XPS/VSDX/OFD/UOF/XMind/MMAP/iWork(Pages/Numbers/Key)/EPUB/MOBI/FB2 | `calamine`, `zip`, `quick-xml`, `mobi`, `msoffice-crypto` | `parser-worker` (纯 Rust) | **内置直通**（含 `[MS-OFFCRYPTO]` 解密、内嵌 `media/*` 图片提取，CEB/CEBX 按约定排除） |
| PDF | PDF | **PDFium** (`pdfium.dll` FFI 全字体渲染/密码/元数据/扫描页 2x 光栅化) + **`lopdf`** | `parser-worker` | **PDFium + `lopdf` 双引擎在线**，扫描页自动转离线 OCR |
| 老 Office / WPS | DOC / PPT / WPS / ET / DPS | **ONLYOFFICE Core v10 (`x2t.exe`)** + 纯 Rust **OLE2 原生回退** (`cfb` 计件表/PPT 记录流/图片雕刻) | `parser-worker` | **`x2t.exe` 高保真转换在线** + OLE2 回退 + `[MS-OFFCRYPTO]` 解密 |
| 离线 OCR / 多帧图像 / 音视频 | PNG/JPG/BMP/多页TIFF/动图GIF/WEBP & MP3/MP4/WAV/FLAC/MKV | **`ort` 动态加载 `onnxruntime.dll` + PP-OCRv4**（`det/cls/rec` + `ppocr_keys_v1.txt`）+ **WinRT `Windows::Media::Ocr` 内置兜底** + `exif`/`png`/`tiff`/`gif` | `parser-worker` | **双引擎离线中英 OCR 在线** + BLAKE3 缓存去重 + `<24px`/纯色过滤 |
| 归档 / 邮件 / 轻量数据库 | ZIP/7Z/TAR/GZ/BZ2/XZ/ZST/CAB/ISO(Joliet)/RAR(RAR3-5) + EML/MBOX/MSG/TNEF + DBF/SQLite | `zip`, `sevenz-rust2`, **`unrar` (C++ UnRAR)**, `tar`, `flate2`, `zstd`, `cab`, `mail-parser`, `cfb`, `dbase`, `rusqlite` | `parser-worker` | **RAR5 与全递归解包原生内置** + 密码探测 + Zip Bomb 熔断 |
| GIS / 3D 点云与模型 | DXF(含 GBK)/KML/KMZ/GPX/GeoJSON/B3DM/GLB/GLTF/LAS | `dxf`, `encoding_rs`, `zip`, 二进制头/Chunk 解析 | `parser-worker` | **内置直通**（显式处理 `$DWGCODEPAGE=ANSI_936` 中文 DXF） |
| CAD / 邮件库 / 取证 / 虚拟磁盘 | DWG / SHP(+DBF) / CHM / PST / OST / DjVu / VHD / VHDX / VMDK / QCOW2 / VDI / IMG / DD / E01 | **`LibreDWG(dwg2dxf.exe)`**, **`outlook-pst-ost` + LZFu RTF 解压**, `ntfs`, `dbase`, `7z.exe` / `readpst.exe` / `libtsk` | `ext-worker` (GPL/重 C++ 与取证隔离) | **DWG 实体解析、PST/OST 原生遍历+附件递归、只读 NTFS 磁盘扫描全部上线** |

---

## 6. 分阶段实施路线图

* **M1（核心骨架与全链路闭环 — 已完成）**：
  - 完成 `DeepDocEngine` Rust Workspace（8 个 Crate）+ `DocSentinel.UI` C# WPF (.NET 8) 工程，跑通 Named Pipe、`Job Object` 双沙箱与 `Tantivy + SQLite` 两阶段规则检索。
* **M2（全格式深度扩展 — 已完成）**：
  - 扩展至 55+ 格式、MS-OFFCRYPTO 透明解密、OLE2 原生回退、CAB/ISO/Zstd、3D GIS/数据库与虚拟磁盘 NTFS/扇区雕刻。
* **M3（重型深度引擎正式接入与发布打包 — 已完成）**：
  - 实装 ONNX Runtime PP-OCRv4 + WinRT 离线中英 OCR、PDFium 全字体渲染与扫描页 2x 光栅化 OCR、ONLYOFFICE `x2t.exe` 高保真转换、原生 UnRAR (RAR3/4/5) 解包、`outlook-pst-ost` 原生 PST/OST 邮箱与 LZFu RTF 解析、以及隔离 `ext-worker` 内的 LibreDWG `dwg2dxf.exe` 全实体转译；并提供 `scripts/fetch_native_deps.ps1` + `scripts/stage_dist.ps1` 一体化离线下发打包。
* **M4（压测、USN 长期增量监听与安装包调优）**：
  - 百万文件压力测试、内存水位调优、MSI/NSIS 单目录安装包制作。
