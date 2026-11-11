# DeepDocEngine

Windows 本地全格式文档深度解析、关键词/正则/邻近规则检索与安全擦除桌面工具（`C# WPF` 桌面端 + `Rust` 多进程守护引擎 + 沙箱解析 Worker 池）。

## 核心特性

- **55+ 格式原生深度解析（免装外部 Office / AutoCAD）**：
  - 办公文档与国标版式：`DOCX / XLSX / XLSM / XLS / PPTX / ODT / ODS / ODP / PDF / OFD / UOF / XMind / MindManager(.mmap) / Apple iWork / EPUB / MOBI / FB2`，支持 `[MS-OFFCRYPTO]` 解密（`DOC / PPT / WPS / ET / DPS` 含 OLE2 纯 Rust 回退解析）。
  - CAD / GIS / 数据库：`DWG`（内嵌纯 Rust `acadrust` 原生抽取图层、块名与 `TEXT/MTEXT` 实体文字）、`DXF`（含 GBK 自动转码）、`SHP + DBF`、`KML / KMZ / GPX / GLB / B3DM / LAS / SQLite / Access`。
  - 邮件与多级压缩包：`EML / MBOX / MSG / TNEF / PST / OST`（含 LZFu 压缩 RTF）；`ZIP / 7Z / RAR(RAR3/4/5) / TAR / GZ / BZ2 / XZ / ZST / CAB / ISO`，自动将非 UTF-8 老旧 Windows 压缩包中文文件名按 `GB18030 / chardetng` 解码还原，带 Zip Bomb 与递归深度熔断。
- **图片与内嵌图片离线 OCR**：
  - 内置 `ONNX Runtime + PP-OCRv4`（`det / cls / rec`）纯文字检测与识别（Windows 内建 WinRT OCR 自动兜底），自动抽取 PDF 扫描页与 Office / 邮件内嵌图文字。
  - **老旧台式机独立显卡支持**：打包轻量化 `DirectML.dll`（免装数 GB CUDA），自动检测 `>= 1 GiB` 显存独显并按显存大小通过命名信号量限流 GPU 并发槽位（`< 3 GiB` 限 1 并发、`>= 3 GiB` 限 2 并发），核显及无独显机器自动走 CPU 批量优化路径；跨进程/跨重启持久化 `ocr_image_cache` 避免相同图片重复推理。
- **中文优化检索与高性能索引库**：
  - `Tantivy` 倒排索引采用 **Jieba 精确非重叠分词 + CJK 双字接缝（`cjk_bi`）召回 + 位置索引**：兼顾专有名词排序与任意连续汉字词组的高召回、零错序。
  - `SQLite WAL + 内容去重 + 4 MiB 快照上限 + Zstd 4 级压缩`：保留 Tantivy 完整全文检索的同时防止超大文件撑爆本地库。
  - 盘符根目录优先尝试 **NTFS USN Journal** 增量变更读取（无权限或普通目录自动平滑回退快照比对）；后台 Worker 采用低 CPU/IO 优先级运行并在空闲后自动收缩回收内存。
- **灵活检索与不落库临时直搜**：
  - 支持 **多文件类型预设与逗号分隔多后缀过滤**、**指定目录搜索**、**多关键词 `AND / OR` 切换**、正则、字段限定与高级表达式（`NEAR / ONEAR / SAMELINE / scope:ocr(...)`）。
  - 支持 **`临时直搜(不落库)`**：对 U 盘或临时目录直接在内存中并发搜索并支持高亮预览，不向本地数据库写入任何文档记录。
  - 支持 **手动增量索引 / 手动重建索引（保留 OCR 缓存）/ 闲时 3 分钟自动增量索引**、**打开文件与打开所在目录**。
- **防杀软温和深度擦除（`DeepDelete`）**：
  - 对选中或指定的待清理文件采用 **低熵值 3 遍原位覆写（`0xAA → 0x55 → 0x00`）+ 分块稳速刷新 + 中性改名移除**（避免高熵突发写盘触发安全软件误杀），并同步执行 `PRAGMA secure_delete=ON` + `WAL 截断` + `VACUUM` + Tantivy 合段垃圾回收，清理引擎本地库中的痕迹。

## 目录结构

- `crates/protocol`: 4B LE Length + MessagePack IPC 协议与中间文档模型
- `crates/rule-engine`: 规则 AST 编译器 + Stage1 `Aho-Corasick` + Stage2 `RegexSet`
- `crates/source-fs`: 统一数据源（Win32 NTFS MFT/USN Journal 增量 + `WalkDir` 回退 + BLAKE3）
- `crates/unpacker`: 多格式归档解包、老旧 ZIP 中文编码修复与 Zip Bomb 熔断
- `crates/parsers`: 55+ 格式魔数嗅探、原生 `acadrust` DWG 解析、PDFium 与 PP-OCRv4 离线流水线
- `crates/indexer`: `Tantivy`（Jieba + CJK Bigram + Pos）与 `SQLite`（WAL + Zstd + OCR 缓存 + USN 位点 + 安全擦除压缩）
- `crates/engine-daemon`, `crates/parser-worker`, `crates/ext-worker`: Windows Named Pipe 守护进程与 Job Object 沙箱 Worker
- `crates/acadrust`: 适配后的本地 `acadrust`（MPL-2.0）纯 Rust DWG/DXF 解析库
- `ui/DocSentinel.UI`: `.NET 8` C# WPF 桌面客户端（输出 `App.UI.exe`）
- `installer/DeepDocEngine.iss` & `scripts/`: Inno Setup 6 安装包脚本、依赖拉取与发布脚本

## 构建与打包（Windows x64）

```powershell
# 1. 拉取并缓存原生运行库（PDFium、ONNX Runtime + DirectML、PP-OCRv4 模型、7-Zip）至 native_deps/
.\scripts\fetch_native_deps.ps1

# 2. 运行工作区 Rust 单元测试与集成测试
cargo build --bins --offline
cargo test --workspace

# 3. 编译 Release 并输出绿色免安装目录 dist/
.\scripts\stage_dist.ps1

# 4. 使用 Inno Setup 6 构建单文件安装包（输出到 dist_installer/）
.\scripts\build_installer.ps1
```

## 开源许可

本项目主体代码基于 [Apache License 2.0](LICENSE) 开源；包含的第三方库及模型署名详情请参见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
