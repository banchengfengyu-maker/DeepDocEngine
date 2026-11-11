param(
    [switch]$IncludeX2t,
    [switch]$IncludeLibreDwg
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    Write-Host "[1/4] Building Rust workspace (Release)..." -ForegroundColor Cyan
    cargo build --release --bin engine-daemon --bin parser-worker --bin ext-worker
    if ($LASTEXITCODE -ne 0) { throw "Rust build failed" }

    Write-Host "[2/4] Publishing C# WPF UI (Release self-contained win-x64)..." -ForegroundColor Cyan
    dotnet publish ui\DocSentinel.UI\DocSentinel.UI.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false
    if ($LASTEXITCODE -ne 0) { throw "WPF publish failed" }

    $Dist = Join-Path $Root "dist"
    if (Test-Path $Dist) { Remove-Item $Dist -Recurse -Force }
    $DistLibs = Join-Path $Dist "libs"
    $DistModels = Join-Path $Dist "models"
    New-Item -ItemType Directory -Path $Dist, $DistLibs, $DistModels | Out-Null

    Write-Host "[3/4] Staging binaries and native engines into dist/..." -ForegroundColor Cyan
    Copy-Item "target\release\engine-daemon.exe" $Dist
    Copy-Item "target\release\parser-worker.exe" $Dist
    Copy-Item "target\release\ext-worker.exe" $Dist
    $PubDir = "ui\DocSentinel.UI\bin\Release\net8.0-windows\win-x64\publish"
    Copy-Item "$PubDir\*" $Dist -Recurse -Force

    $NativeLibs = Join-Path $Root "native_deps\libs"
    $NativeModels = Join-Path $Root "native_deps\models"
    if (Test-Path $NativeLibs) {
        $LibreDwgFiles = @("dwg2dxf.exe", "libredwg-0.dll", "libiconv-2.dll", "libpcre2-8-0.dll", "libpcre2-16-0.dll", "_LibreDWG.dll")
        Get-ChildItem $NativeLibs -File | Where-Object {
            $IncludeLibreDwg -or ($_.Name -notin $LibreDwgFiles)
        } | ForEach-Object {
            Copy-Item $_.FullName $DistLibs -Force
        }
        $X2tSrc = Join-Path $NativeLibs "x2t"
        if ($IncludeX2t -and (Test-Path $X2tSrc)) {
            $X2tDst = Join-Path $DistLibs "x2t"
            Copy-Item $X2tSrc $X2tDst -Recurse -Force
            Remove-Item (Join-Path $X2tDst "include") -Recurse -Force -ErrorAction SilentlyContinue
            Get-ChildItem $X2tDst -File | Where-Object {
                $_.Extension -in @(".lib", ".pdb", ".py", ".jar") -or $_.Name -like "docbuilder.*"
            } | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path $NativeModels) {
        Copy-Item "$NativeModels\*" $DistModels -Recurse -Force
    }

    Write-Host "[4/4] Done! Output staged at: $Dist" -ForegroundColor Green
}
finally {
    Pop-Location
}
