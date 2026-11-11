# Third-Party Notices and Licenses

`DeepDocEngine` is licensed under the **Apache License 2.0** (see `LICENSE`), and incorporates or bundles the following third-party components and models:

## 1. Embedded Source Crates

- **acadrust** (`crates/acadrust/`, `v0.3.4`, by Hakan AK)
  - License: **Mozilla Public License 2.0 (MPL-2.0)**
  - Usage: Native pure-Rust DWG / DXF parser. Source code and local adaptations remain openly available in `crates/acadrust/`.

## 2. Rust Dependencies (`Cargo.toml` / `Cargo.lock`)

- Permissive crates (`MIT` / `Apache-2.0` / `BSD-2-Clause` / `BSD-3-Clause` / `ISC` / `MPL-2.0`), including `tantivy`, `rusqlite`, `jieba-rs`, `lopdf`, `calamine`, `quick-xml`, `ort`, `blake3`, `zstd`, `rmp-serde`, `msoffice-crypto`, `encoding_rs`, `chardetng`, `tokio`, `windows-sys`.
- **unrar** crate (`crates/unpacker/`, optional RAR archive read-only extraction)
  - License: UnRAR freeware source license (allows free read-only decompression of `.rar` archives; prohibits using UnRAR source to re-create a RAR compression algorithm). Notice and upstream terms apply when distributing builds with RAR support enabled.

## 3. Native Runtime Libraries (`scripts/fetch_native_deps.ps1` -> `dist/libs/` & `dist/models/`)

- **PDFium** (`pdfium.dll`, `bblanchon/pdfium-binaries` Chromium builds)
  - License: **BSD-3-Clause / Apache-2.0**
- **ONNX Runtime** (`onnxruntime.dll`, `onnxruntime_providers_shared.dll`, `microsoft/onnxruntime`)
  - License: **MIT**
- **Microsoft DirectML** (`DirectML.dll`, `Microsoft.AI.DirectML`)
  - License: Microsoft Software License Terms for DirectML (redistributable Windows DirectX 12 ML runtime)
- **PaddleOCR / RapidOCR PP-OCRv4 ONNX Models & Dictionary** (`det.onnx`, `cls.onnx`, `rec.onnx`, `ppocr_keys_v1.txt`)
  - License: **Apache-2.0**
- **7-Zip CLI / Library** (`7z.exe`, `7z.dll`)
  - License: **LGPL-2.1-or-later** (plus unRAR restriction notices where applicable; executed externally by `ext-worker` / archive helpers)

## 4. Optional Extensions (Disabled in Default Distribution)

- **LibreDWG** (`dwg2dxf.exe` + runtime DLLs, enabled only when `-IncludeLibreDwg` is passed to `fetch_native_deps.ps1` / `stage_dist.ps1`)
  - License: **GPL-3.0-or-later** (isolated strictly behind the separate `ext-worker.exe` IPC process boundary; **not bundled** in default releases)
- **ONLYOFFICE DocumentBuilder / `x2t`** (enabled only when `-IncludeOnlyOffice` / `-IncludeX2t` is passed)
  - License: **AGPL-3.0** (upstream DocumentBuilder terms; **not bundled** in default releases)
