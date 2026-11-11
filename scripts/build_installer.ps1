param(
    [string]$Version = "0.1.0",
    [switch]$SkipStage,
    [string]$IsccPath = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($IsccPath)) {
    $Candidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe")
    )
    $Found = $Candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if ($Found) {
        $IsccPath = $Found
    } else {
        $Cmd = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
        if ($Cmd) { $IsccPath = $Cmd.Source }
    }
}

$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    if (-not $SkipStage) {
        & (Join-Path $PSScriptRoot "stage_dist.ps1")
        if ($LASTEXITCODE -ne 0) { throw "stage_dist.ps1 failed" }
    }

    if (-not (Test-Path $IsccPath)) {
        throw "Inno Setup compiler ISCC.exe not found at: $IsccPath"
    }

    $DistDir = Join-Path $Root "dist"
    $OutDir = Join-Path $Root "dist_installer"
    if (-not (Test-Path $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir | Out-Null
    }
    $IssFile = Join-Path $Root "installer\DeepDocEngine.iss"

    Write-Host "[Inno Setup] Compiling installer from $DistDir ..." -ForegroundColor Cyan
    & $IsccPath "/DAppVersion=$Version" "/DDistDir=$DistDir" "/DOutputSetupDir=$OutDir" $IssFile
    if ($LASTEXITCODE -ne 0) { throw "ISCC.exe failed with exit code $LASTEXITCODE" }

    $SetupExe = Join-Path $OutDir "DeepDocEngine_Setup_v${Version}_win64.exe"
    if (Test-Path $SetupExe) {
        $SizeMb = [math]::Round((Get-Item $SetupExe).Length / 1MB, 2)
        Write-Host "[Inno Setup] Done! Installer created: $SetupExe ($SizeMb MB)" -ForegroundColor Green
    }
}
finally {
    Pop-Location
}
