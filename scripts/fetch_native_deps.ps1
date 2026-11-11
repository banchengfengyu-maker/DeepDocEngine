param(
    [switch]$IncludeOnlyOffice,
    [switch]$IncludeLibreDwg,
    [switch]$CpuOnlyOrt
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$NativeRoot = Join-Path $Root "native_deps"
$Cache = Join-Path $NativeRoot "_downloads"
$Libs = Join-Path $NativeRoot "libs"
$Models = Join-Path $NativeRoot "models"
$X2tDir = Join-Path $Libs "x2t"

New-Item -ItemType Directory -Path $Cache, $Libs, $Models, $X2tDir -Force | Out-Null

function Get-FileWithCurl {
    param([string]$Url, [string]$Dest)
    if ((Test-Path $Dest) -and ((Get-Item $Dest).Length -gt 0)) {
        Write-Host "[cached] $Dest" -ForegroundColor DarkGray
        return
    }
    Write-Host "[download] $Url -> $Dest" -ForegroundColor Cyan
    & curl.exe -fL --retry 3 --retry-delay 2 -C - -o "$Dest.part" $Url
    if ($LASTEXITCODE -ne 0) {
        Remove-Item "$Dest.part" -Force -ErrorAction SilentlyContinue
        Write-Host "[retry Invoke-WebRequest] $Url -> $Dest" -ForegroundColor Yellow
        Invoke-WebRequest -Uri $Url -OutFile "$Dest.part" -UseBasicParsing
    }
    if (-not (Test-Path "$Dest.part")) {
        throw "Download failed: $Url"
    }
    Move-Item "$Dest.part" $Dest -Force
}

# 1. PDFium (Win x64)
$PdfiumUrl = "https://github.com/bblanchon/pdfium-binaries/releases/download/chromium/8152/pdfium-win-x64.tgz"
$PdfiumTgz = Join-Path $Cache "pdfium-win-x64.tgz"
Get-FileWithCurl -Url $PdfiumUrl -Dest $PdfiumTgz
if (-not (Test-Path (Join-Path $Libs "pdfium.dll"))) {
    $Tmp = Join-Path $Cache "pdfium_tmp"
    if (Test-Path $Tmp) { Remove-Item $Tmp -Recurse -Force }
    New-Item -ItemType Directory -Path $Tmp | Out-Null
    & tar.exe -xzf $PdfiumTgz -C $Tmp
    if ($LASTEXITCODE -ne 0) { throw "tar extract pdfium failed" }
    Copy-Item (Join-Path $Tmp "bin\pdfium.dll") (Join-Path $Libs "pdfium.dll") -Force
    Remove-Item $Tmp -Recurse -Force
    Write-Host "[staged] libs/pdfium.dll" -ForegroundColor Green
}

# 2. ONNX Runtime (DirectML GPU on Windows DX12 by default, or CPU fallback via -CpuOnlyOrt) + PP-OCRv4 Models + Dictionary
if ($CpuOnlyOrt) {
    $OrtUrl = "https://github.com/microsoft/onnxruntime/releases/download/v1.24.4/onnxruntime-win-x64-1.24.4.zip"
    $OrtZip = Join-Path $Cache "onnxruntime-win-x64-1.24.4.zip"
    Get-FileWithCurl -Url $OrtUrl -Dest $OrtZip
    if (-not (Test-Path (Join-Path $Libs "onnxruntime.dll"))) {
        $Tmp = Join-Path $Cache "ort_tmp"
        if (Test-Path $Tmp) { Remove-Item $Tmp -Recurse -Force }
        Expand-Archive -Path $OrtZip -DestinationPath $Tmp -Force
        Get-ChildItem -Path $Tmp -Recurse -Filter "onnxruntime*.dll" | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $Libs $_.Name) -Force
        }
        Remove-Item $Tmp -Recurse -Force
        Write-Host "[staged] libs/onnxruntime*.dll (CPU)" -ForegroundColor Green
    }
} else {
    $OrtDmlPkg = Join-Path $Cache "microsoft.ml.onnxruntime.directml.1.24.4.nupkg"
    Get-FileWithCurl -Url "https://api.nuget.org/v3-flatcontainer/microsoft.ml.onnxruntime.directml/1.24.4/microsoft.ml.onnxruntime.directml.1.24.4.nupkg" -Dest $OrtDmlPkg
    $AiDmlPkg = Join-Path $Cache "microsoft.ai.directml.1.15.4.nupkg"
    Get-FileWithCurl -Url "https://api.nuget.org/v3-flatcontainer/microsoft.ai.directml/1.15.4/microsoft.ai.directml.1.15.4.nupkg" -Dest $AiDmlPkg
    if ((-not (Test-Path (Join-Path $Libs "DirectML.dll"))) -or (-not (Test-Path (Join-Path $Libs "onnxruntime.dll")))) {
        $TmpOrt = Join-Path $Cache "ort_dml_tmp"
        $TmpAi = Join-Path $Cache "ai_dml_tmp"
        if (Test-Path $TmpOrt) { Remove-Item $TmpOrt -Recurse -Force }
        if (Test-Path $TmpAi) { Remove-Item $TmpAi -Recurse -Force }
        $OrtZipTmp = "$OrtDmlPkg.zip"
        $AiZipTmp = "$AiDmlPkg.zip"
        Copy-Item $OrtDmlPkg $OrtZipTmp -Force
        Copy-Item $AiDmlPkg $AiZipTmp -Force
        Expand-Archive -Path $OrtZipTmp -DestinationPath $TmpOrt -Force
        Expand-Archive -Path $AiZipTmp -DestinationPath $TmpAi -Force
        Get-ChildItem -Path (Join-Path $TmpOrt "runtimes\win-x64\native") -Filter "onnxruntime*.dll" | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $Libs $_.Name) -Force
        }
        $DmlDll = Get-ChildItem -Path $TmpAi -Recurse -Filter "DirectML.dll" | Where-Object { $_.FullName -like "*x64*" } | Select-Object -First 1
        if ($DmlDll) { Copy-Item $DmlDll.FullName (Join-Path $Libs "DirectML.dll") -Force }
        Remove-Item $TmpOrt, $TmpAi, $OrtZipTmp, $AiZipTmp -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[staged] libs/onnxruntime*.dll + DirectML.dll (GPU DirectML)" -ForegroundColor Green
    }
}

Get-FileWithCurl -Url "https://huggingface.co/SWHL/RapidOCR/resolve/main/PP-OCRv4/ch_PP-OCRv4_det_infer.onnx" -Dest (Join-Path $Models "det.onnx")
Get-FileWithCurl -Url "https://huggingface.co/SWHL/RapidOCR/resolve/main/PP-OCRv1/ch_ppocr_mobile_v2.0_cls_infer.onnx" -Dest (Join-Path $Models "cls.onnx")
Get-FileWithCurl -Url "https://huggingface.co/SWHL/RapidOCR/resolve/main/PP-OCRv4/ch_PP-OCRv4_rec_infer.onnx" -Dest (Join-Path $Models "rec.onnx")
Get-FileWithCurl -Url "https://raw.githubusercontent.com/PaddlePaddle/PaddleOCR/main/ppocr/utils/ppocr_keys_v1.txt" -Dest (Join-Path $Models "ppocr_keys_v1.txt")

# 3. LibreDWG 0.14 (optional 32MB fallback; disabled by default since acadrust handles DWG natively)
if ($IncludeLibreDwg) {
    $DwgUrl = "https://github.com/LibreDWG/libredwg/releases/download/0.14/libredwg-0.14-win64.zip"
    $DwgZip = Join-Path $Cache "libredwg-0.14-win64.zip"
    Get-FileWithCurl -Url $DwgUrl -Dest $DwgZip
    if (-not (Test-Path (Join-Path $Libs "dwg2dxf.exe"))) {
        $Tmp = Join-Path $Cache "dwg_tmp"
        if (Test-Path $Tmp) { Remove-Item $Tmp -Recurse -Force }
        Expand-Archive -Path $DwgZip -DestinationPath $Tmp -Force
        Get-ChildItem -Path $Tmp -Recurse -Filter "*.dll" | ForEach-Object { Copy-Item $_.FullName (Join-Path $Libs $_.Name) -Force }
        $Dwg2Dxf = Get-ChildItem -Path $Tmp -Recurse -Filter "dwg2dxf.exe" | Select-Object -First 1
        if ($Dwg2Dxf) { Copy-Item $Dwg2Dxf.FullName (Join-Path $Libs "dwg2dxf.exe") -Force }
        Remove-Item $Tmp -Recurse -Force
        Write-Host "[staged] libs/dwg2dxf.exe + DLLs" -ForegroundColor Green
    }
}

# 4. ONLYOFFICE DocumentBuilder (optional 183MB legacy fallback; disabled by default)
if ($IncludeOnlyOffice) {
    $OoUrl = "https://github.com/ONLYOFFICE/DocumentBuilder/releases/download/v10.0.0/onlyoffice-documentbuilder-windows-x64.zip"
    $OoZip = Join-Path $Cache "onlyoffice-documentbuilder-windows-x64.zip"
    Get-FileWithCurl -Url $OoUrl -Dest $OoZip
    if (-not (Test-Path (Join-Path $X2tDir "x2t.exe"))) {
        $Tmp = Join-Path $Cache "oo_tmp"
        if (Test-Path $Tmp) { Remove-Item $Tmp -Recurse -Force }
        Expand-Archive -Path $OoZip -DestinationPath $Tmp -Force
        $X2t = Get-ChildItem -Path $Tmp -Recurse -Filter "x2t.exe" | Select-Object -First 1
        if ($X2t) {
            $SrcBin = $X2t.Directory.FullName
            Copy-Item "$SrcBin\*" $X2tDir -Recurse -Force
            Write-Host "[staged] libs/x2t/x2t.exe (from $SrcBin)" -ForegroundColor Green
        } else {
            Write-Host "[warn] x2t.exe not found inside onlyoffice-documentbuilder archive; listing exes:" -ForegroundColor Yellow
            Get-ChildItem -Path $Tmp -Recurse -Filter "*.exe" | ForEach-Object { Write-Host "  $($_.FullName)" }
        }
        Remove-Item $Tmp -Recurse -Force
    }
}

# 5. 7-Zip CLI (7z.exe + 7z.dll) for CHM & Container Disk Images (ext-worker)
$SevenZipExe = Join-Path $Libs "7z.exe"
$SevenZipDll = Join-Path $Libs "7z.dll"
if (-not ((Test-Path $SevenZipExe) -and (Test-Path $SevenZipDll))) {
    $Tmp = Join-Path $NativeRoot "_tmp_7z"
    if (Test-Path $Tmp) { Remove-Item $Tmp -Recurse -Force }
    New-Item -ItemType Directory -Path $Tmp -Force | Out-Null
    $SevenZr = Join-Path $Tmp "7zr.exe"
    $SevenInst = Join-Path $Tmp "7z2409-x64.exe"
    Get-FileWithCurl -Url "https://www.7-zip.org/a/7zr.exe" -Dest $SevenZr
    Get-FileWithCurl -Url "https://www.7-zip.org/a/7z2409-x64.exe" -Dest $SevenInst
    & $SevenZr x $SevenInst "-o$Tmp" "7z.exe" "7z.dll" -y | Out-Null
    if (Test-Path (Join-Path $Tmp "7z.exe")) {
        Copy-Item (Join-Path $Tmp "7z.exe") $SevenZipExe -Force
        Copy-Item (Join-Path $Tmp "7z.dll") $SevenZipDll -Force
        Write-Host "[staged] libs/7z.exe + 7z.dll" -ForegroundColor Green
    } else {
        Write-Host "[warn] failed to extract 7z.exe / 7z.dll" -ForegroundColor Yellow
    }
    Remove-Item $Tmp -Recurse -Force
}

Write-Host "`nNative dependencies ready in: $NativeRoot" -ForegroundColor Green
Get-ChildItem $Libs | Select-Object Name, Length
Get-ChildItem $Models | Select-Object Name, Length
