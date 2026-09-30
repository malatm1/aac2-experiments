param()

$ErrorActionPreference = "Stop"

$Dataset = "sunblaze-ucb/cybergym-e2e"
$TaskNeedle = "arvo_41221"

function Section($t) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host $t
    Write-Host "============================================================"
}

Write-Host "AAC 2.0 HUGGING FACE DATASET ACCESS CHECK"
Write-Host ("Timestamp: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"))
Write-Host "THIS SCRIPT DOES NOT DOWNLOAD THE BENCHMARK DATASET."
Write-Host "It only installs the HF client if needed, authenticates, and lists metadata."

Section "1. HUGGING FACE CLIENT"

$savedEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$import = & python -c "import huggingface_hub; print(huggingface_hub.__version__)" 2>$null
$importExit = $LASTEXITCODE
$ErrorActionPreference = $savedEap

if ($importExit -ne 0) {
    Write-Host "huggingface_hub is not installed yet."
    Write-Host "Installing huggingface_hub..."
    $savedEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & python -m pip install --upgrade huggingface_hub
    $pipExit = $LASTEXITCODE
    $ErrorActionPreference = $savedEap
    if ($pipExit -ne 0) {
        throw "Failed to install huggingface_hub."
    }
} else {
    Write-Host ("[OK] Python huggingface_hub: {0}" -f ($import | Out-String).Trim())
}

$hf = Get-Command hf -ErrorAction SilentlyContinue
if (-not $hf) {
    $scripts = Join-Path (Split-Path (Get-Command python).Source -Parent) "Scripts"
    if (Test-Path (Join-Path $scripts "hf.exe")) {
        $env:PATH = "$scripts;$env:PATH"
    }
}
$hf = Get-Command hf -ErrorAction SilentlyContinue
if (-not $hf) {
    throw "The hf CLI was not found after installing huggingface_hub."
}
Write-Host ("[OK] hf CLI: {0}" -f $hf.Source)

Section "2. AUTHENTICATION"

& hf auth whoami
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "No authenticated Hugging Face session found."
    Write-Host "The CLI will now ask for a Hugging Face access token."
    Write-Host "Paste the token ONLY into this PowerShell prompt, never into ChatGPT."
    Write-Host ""
    & hf auth login
    if ($LASTEXITCODE -ne 0) {
        throw "Hugging Face login failed."
    }
}

Write-Host ""
& hf auth whoami
if ($LASTEXITCODE -ne 0) {
    throw "Hugging Face authentication could not be verified."
}

Section "3. GATED DATASET METADATA ACCESS"

$py = @'
from huggingface_hub import HfApi
from huggingface_hub.utils import GatedRepoError, HfHubHTTPError

repo_id = "sunblaze-ucb/cybergym-e2e"
needle = "arvo_41221"

api = HfApi()

try:
    info = api.dataset_info(repo_id, token=True)
    print(f"[OK] Dataset metadata accessible: {repo_id}")
    print(f"     Revision: {info.sha}")
    print(f"     Gated: {getattr(info, 'gated', None)}")

    files = api.list_repo_files(repo_id=repo_id, repo_type="dataset", token=True)
    print(f"     Repository files indexed: {len(files)}")

    matches = [p for p in files if needle.lower() in p.lower()]
    print(f"     Files matching {needle}: {len(matches)}")
    for p in matches:
        print(f"       {p}")

    if not matches:
        print("[WARN] No exact calibration-task paths were found.")
        print("       Do NOT download the full dataset. We will inspect the dataset tree first.")
        raise SystemExit(4)

except GatedRepoError as e:
    print("[ACTION REQUIRED] Your account is authenticated but does not yet have access to the gated dataset.")
    print("Open the dataset page in your browser, accept its access/contact-sharing conditions, then rerun this script.")
    raise SystemExit(3)
except HfHubHTTPError as e:
    print(f"[ERROR] Hugging Face returned: {e}")
    raise SystemExit(2)
'@

$tmp = Join-Path $env:TEMP "aac2_hf_access_check.py"
Set-Content -Path $tmp -Value $py -Encoding UTF8
& python $tmp
$code = $LASTEXITCODE
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

if ($code -eq 3) {
    Write-Host ""
    Write-Host "=== ACCESS CONDITIONS MUST BE ACCEPTED; NO DATA DOWNLOADED ==="
    exit 3
}
if ($code -ne 0) {
    throw "Dataset metadata check did not pass (exit $code)."
}

Section "4. RESULT"

Write-Host "[PASS] Hugging Face authentication and gated dataset access are working."
Write-Host ("       Dataset: {0}" -f $Dataset)
Write-Host ("       Calibration task searched: {0}" -f $TaskNeedle)
Write-Host "       No benchmark file was downloaded."
Write-Host ""
Write-Host "NEXT GATE: download only the files required for the reserved calibration task."
Write-Host ""
Write-Host "=== END HF ACCESS CHECK ==="
