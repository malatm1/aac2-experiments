param()

$ErrorActionPreference = "Stop"

$Dataset = "sunblaze-ucb/cybergym-e2e"
$DatasetRevision = "3aee406e4e915e32527fea16de7f002630fa8c76"
$Task = "arrow/arvo_41221"
$Files = @(
    "projects/arrow/arvo_41221/crash.log",
    "projects/arrow/arvo_41221/poc.bin",
    "projects/arrow/arvo_41221/src.tgz"
)

function Section($t) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host $t
    Write-Host "============================================================"
}

Write-Host "AAC 2.0 CALIBRATION TASK DATA DOWNLOAD"
Write-Host ("Timestamp: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"))
Write-Host "ONLY THE THREE RESERVED CALIBRATION FILES WILL BE DOWNLOADED."
Write-Host "NO MODEL WILL BE CALLED."

$root = git rev-parse --show-toplevel 2>$null
if (-not $root) {
    throw "Run this script from inside the aac2-experiments repository."
}
Set-Location $root

$benchDir = Join-Path $root "external\cybergym-e2e"
if (-not (Test-Path (Join-Path $benchDir ".git"))) {
    throw "Pinned CyberGym-E2E working copy not found."
}

$benchCommit = (git -C $benchDir rev-parse HEAD).Trim()
if ($benchCommit -ne "b46456c46838b2b090d7e6ded5bfdf1ff583dba7") {
    throw "CyberGym-E2E working copy is not at the pinned commit."
}

Section "1. VERIFY HUGGING FACE LOGIN"

$hf = Get-Command hf -ErrorAction SilentlyContinue
if (-not $hf) {
    $pythonExe = (Get-Command python).Source
    $scriptsDir = Join-Path (Split-Path $pythonExe -Parent) "Scripts"
    $hfCandidate = Join-Path $scriptsDir "hf.exe"
    if (Test-Path $hfCandidate) {
        $hf = Get-Item $hfCandidate
    }
}
if (-not $hf) {
    throw "Hugging Face CLI not found. Re-run the access-check script first."
}

$oldEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $hf.FullName auth whoami
$hfStatus = $LASTEXITCODE
$ErrorActionPreference = $oldEap

if ($hfStatus -ne 0) {
    throw "Hugging Face authentication is not active."
}

Section "2. DOWNLOAD EXACT TASK FILES"

$py = @'
from pathlib import Path
from huggingface_hub import hf_hub_download

repo_id = "sunblaze-ucb/cybergym-e2e"
revision = "3aee406e4e915e32527fea16de7f002630fa8c76"
local_dir = Path(r"__LOCAL_DIR__")

files = [
    "projects/arrow/arvo_41221/crash.log",
    "projects/arrow/arvo_41221/poc.bin",
    "projects/arrow/arvo_41221/src.tgz",
]

for filename in files:
    print(f"Downloading: {filename}")
    p = hf_hub_download(
        repo_id=repo_id,
        repo_type="dataset",
        filename=filename,
        revision=revision,
        local_dir=str(local_dir),
        token=True,
    )
    print(f"  -> {p}")
'@

$escapedBench = $benchDir.Replace("\","\\")
$py = $py.Replace("__LOCAL_DIR__", $escapedBench)
$tmp = Join-Path $env:TEMP "aac2_download_calibration.py"
Set-Content -Path $tmp -Value $py -Encoding UTF8

& python $tmp
$code = $LASTEXITCODE
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

if ($code -ne 0) {
    throw "Calibration task download failed with exit code $code."
}

Section "3. VERIFY PATHS, SIZES AND HASHES"

$total = 0L
$records = @()

foreach ($rel in $Files) {
    $localPath = Join-Path $benchDir ($rel -replace "/","\")
    if (-not (Test-Path $localPath)) {
        throw "Expected downloaded file missing: $localPath"
    }

    $fi = Get-Item $localPath
    $hash = (Get-FileHash -Algorithm SHA256 $localPath).Hash.ToLower()
    $total += $fi.Length

    $records += [pscustomobject]@{
        Path = $rel
        Bytes = $fi.Length
        MiB = [Math]::Round($fi.Length / 1MB, 2)
        SHA256 = $hash
    }

    Write-Host ("[OK] {0}" -f $rel)
    Write-Host ("     Size: {0:N0} bytes ({1:N2} MiB)" -f $fi.Length, ($fi.Length / 1MB))
    Write-Host ("     SHA256: {0}" -f $hash)
}

Write-Host ""
Write-Host ("Total downloaded task data: {0:N2} MiB" -f ($total / 1MB))

Section "4. WRITE LOCAL LOCK RECORD"

$lockDir = Join-Path $root "confirmatory\local"
New-Item -ItemType Directory -Force -Path $lockDir | Out-Null
$lockPath = Join-Path $lockDir "calibration-task-lock.json"

$lock = [ordered]@{
    benchmark = "cybergym-e2e"
    benchmark_commit = $benchCommit
    dataset = $Dataset
    dataset_revision = $DatasetRevision
    task = $Task
    purpose = "calibration_only"
    include_in_confirmatory_dataset = $false
    files = $records
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
}

$lock | ConvertTo-Json -Depth 6 | Set-Content -Path $lockPath -Encoding UTF8
Write-Host ("[OK] Local lock record written: {0}" -f $lockPath)

Section "5. RESULT"

Write-Host "[PASS] Reserved calibration task data is present and hashed."
Write-Host ("       Dataset revision: {0}" -f $DatasetRevision)
Write-Host ("       Task: {0}" -f $Task)
Write-Host "       No model was called."
Write-Host "       No other benchmark tasks were downloaded."
Write-Host ""
Write-Host "NEXT GATE: inspect/pull the single task Docker image and validate the"
Write-Host "           benchmark mechanically before any Claude/GPT calibration call."
Write-Host ""
Write-Host "=== END CALIBRATION DATA DOWNLOAD ==="
