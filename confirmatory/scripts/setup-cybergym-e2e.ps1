param()

$ErrorActionPreference = "Stop"

$PinnedCommit = "b46456c46838b2b090d7e6ded5bfdf1ff583dba7"
$CalibrationTask = "arrow/arvo_41221"
$RepoUrl = "https://github.com/sunblaze-ucb/cybergym-e2e.git"

function Section($t) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host $t
    Write-Host "============================================================"
}

Write-Host "AAC 2.0 CYBERGYM-E2E BENCHMARK SETUP"
Write-Host ("Timestamp: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"))
Write-Host "NO MODEL CALLS WILL BE MADE."
Write-Host "NO BENCHMARK DATASET WILL BE DOWNLOADED."

$root = git rev-parse --show-toplevel 2>$null
if (-not $root) {
    throw "Run this script from inside the aac2-experiments repository."
}
Set-Location $root

Section "1. CONFIRM RESEARCH BRANCH"
$branch = git branch --show-current
Write-Host ("Branch: {0}" -f $branch)
if ($branch -ne "confirmatory-v2") {
    throw "Expected branch confirmatory-v2, found $branch"
}

Section "2. DOCKER"
$dockerInfo = docker info --format 'Server={{.ServerVersion}} OS={{.OperatingSystem}} CPUs={{.NCPU}} Mem={{.MemTotal}}' 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Docker engine is not reachable. Start Docker Desktop."
}
Write-Host ("[OK] {0}" -f $dockerInfo)

Section "3. HOST FREE SPACE"
$drive = Get-PSDrive -Name ((Get-Location).Drive.Name)
Write-Host ("Free space on {0}: {1:N1} GB" -f $drive.Name, ($drive.Free / 1GB))
if (($drive.Free / 1GB) -lt 40) {
    Write-Host "[WARN] Less than 40 GB free. Do not download benchmark task data yet."
}

Section "4. CLONE / PIN CYBERGYM-E2E"
$externalDir = Join-Path $root "external"
$benchDir = Join-Path $externalDir "cybergym-e2e"
New-Item -ItemType Directory -Force -Path $externalDir | Out-Null

if (-not (Test-Path (Join-Path $benchDir ".git"))) {
    Write-Host "Cloning CyberGym-E2E source repository..."
    git clone $RepoUrl $benchDir
    if ($LASTEXITCODE -ne 0) {
        throw "CyberGym-E2E clone failed."
    }
} else {
    Write-Host "[OK] Existing CyberGym-E2E clone found."
}

Push-Location $benchDir
try {
    git fetch origin
    if ($LASTEXITCODE -ne 0) {
        throw "Could not fetch CyberGym-E2E."
    }

    git checkout --detach $PinnedCommit
    if ($LASTEXITCODE -ne 0) {
        throw "Could not checkout pinned CyberGym-E2E commit."
    }

    $actual = git rev-parse HEAD
    Write-Host ("Pinned commit: {0}" -f $actual)
    if ($actual -ne $PinnedCommit) {
        throw "Pinned commit mismatch."
    }
} finally {
    Pop-Location
}

Section "5. BENCHMARK FILE CHECK"
$required = @(
    "README.md",
    "SUBMISSION.md",
    "scripts\run_agent.py",
    "scripts\tasks.txt",
    "scripts\utils.py",
    "projects\arrow\arvo_41221\config.toml",
    "projects\arrow\arvo_41221\prepare.sh",
    "projects\arrow\arvo_41221\run_poc.sh",
    "projects\arrow\arvo_41221\test.sh"
)

foreach ($rel in $required) {
    $p = Join-Path $benchDir $rel
    if (Test-Path $p) {
        Write-Host ("[OK]   {0}" -f $rel)
    } else {
        throw "Missing benchmark file: $rel"
    }
}

Section "6. CALIBRATION TASK RESERVATION"
$tasksFile = Join-Path $benchDir "scripts\tasks.txt"
$found = Select-String -Path $tasksFile -Pattern ("^" + [regex]::Escape($CalibrationTask) + "$") -Quiet
if (-not $found) {
    throw "Calibration task $CalibrationTask is not in scripts/tasks.txt"
}
Write-Host ("[OK] Reserved calibration-only task: {0}" -f $CalibrationTask)
Write-Host "This task must NOT be included in any confirmatory item bank."

Section "7. CLI AUTH PRESENCE"
$claude = Get-Command claude -ErrorAction SilentlyContinue
$codex = Get-Command codex -ErrorAction SilentlyContinue
if ($claude) {
    Write-Host ("[OK] Claude Code: {0}" -f (& claude --version 2>&1 | Out-String).Trim())
} else {
    Write-Host "[WARN] Claude Code not found."
}
if ($codex) {
    Write-Host ("[OK] Codex: {0}" -f (& codex --version 2>&1 | Out-String).Trim())
} else {
    Write-Host "[WARN] Codex not found."
}

Section "8. RESULT"
Write-Host "[PASS] CyberGym-E2E source is cloned and pinned."
Write-Host ("       Commit: {0}" -f $PinnedCommit)
Write-Host ("       Calibration task: {0}" -f $CalibrationTask)
Write-Host "       No model was called."
Write-Host "       No benchmark dataset was downloaded."
Write-Host ""
Write-Host "NEXT GATE: inspect subscription-authenticated Claude Code/Codex integration"
Write-Host "           and download ONLY the reserved calibration task data."
Write-Host ""
Write-Host "=== END BENCHMARK SETUP ==="
