param()

$ErrorActionPreference = "Stop"

$PinnedBenchCommit = "b46456c46838b2b090d7e6ded5bfdf1ff583dba7"
$Image = "n132/arvo:41221-fix"

$ExpectedHashes = @{
    "crash.log" = "db3dd53d0f38de49be2d3c02a5f292e89632fbaee0ec04cd696d0dcdc089dea0"
    "poc.bin"   = "091666864704562ced0b066681436406ed451540fa653bd522fbe99bf2824034"
    "src.tgz"   = "db2162139e74b46d9e96e4f4d7947dd716639c455fe9525ba1b34878463a448d"
}

function Section($t) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host $t
    Write-Host "============================================================"
}

Write-Host "AAC 2.0 CYBERGYM-E2E MECHANICAL CALIBRATION"
Write-Host ("Timestamp: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"))
Write-Host "NO CLAUDE OR GPT MODEL WILL BE CALLED."
Write-Host "This gate validates the benchmark using its published ground-truth patch."

$root = git rev-parse --show-toplevel 2>$null
if (-not $root) {
    throw "Run this script from inside the aac2-experiments repository."
}
Set-Location $root

$benchDir = Join-Path $root "external\cybergym-e2e"
$taskDir = Join-Path $benchDir "projects\arrow\arvo_41221"

if (-not (Test-Path (Join-Path $benchDir ".git"))) {
    throw "CyberGym-E2E working copy is missing."
}

$benchCommit = (git -C $benchDir rev-parse HEAD).Trim()
if ($benchCommit -ne $PinnedBenchCommit) {
    throw "Benchmark commit mismatch: expected $PinnedBenchCommit, got $benchCommit"
}

Section "1. NORMALISE PINNED BENCHMARK CHECKOUT FOR LINUX"

# Windows Git may rewrite LF shell scripts as CRLF when checking out the
# external benchmark. Docker executes these scripts under Linux, where CRLF
# causes errors such as "
    $p = Join-Path $taskDir $name
    if (-not (Test-Path $p)) {
        throw "Missing calibration file: $p"
    }
    $actual = (Get-FileHash -Algorithm SHA256 $p).Hash.ToLower()
    if ($actual -ne $ExpectedHashes[$name]) {
        throw "SHA256 mismatch for $name"
    }
    Write-Host ("[OK] {0}: {1}" -f $name, $actual)
}

$patchPath = Join-Path $taskDir "patch.diff"
if (-not (Test-Path $patchPath)) {
    throw "Ground-truth patch missing from pinned benchmark source."
}
$patchHash = (Get-FileHash -Algorithm SHA256 $patchPath).Hash.ToLower()
Write-Host ("[OK] patch.diff SHA256: {0}" -f $patchHash)

Section "3. DOCKER IMAGE"

$dockerInfo = docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Docker engine is not reachable."
}

Write-Host ("Pulling only: {0}" -f $Image)
docker pull $Image
if ($LASTEXITCODE -ne 0) {
    throw "Docker image pull failed."
}

$inspectJson = docker image inspect $Image 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Could not inspect Docker image after pull."
}
$inspect = $inspectJson | ConvertFrom-Json
if (-not $inspect -or $inspect.Count -lt 1) {
    throw "Docker image inspect returned no object."
}

$imageObj = $inspect[0]
$imageId = [string]$imageObj.Id
$repoDigests = if ($imageObj.RepoDigests) { ($imageObj.RepoDigests -join ",") } else { "<none>" }
$imageSize = [int64]$imageObj.Size

Write-Host ("[OK] Image ID: {0}" -f $imageId)
Write-Host ("[OK] Repo digest(s): {0}" -f $repoDigests)
Write-Host ("[OK] Local image size: {0:N2} GiB" -f ($imageSize / 1GB))

Section "4. PYTHON VALIDATOR DEPENDENCIES"

$probe = 'import tomli, tomli_w, boto3, httpx, docker; print("OK")'
$oldEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$probeOut = & python -c $probe 2>$null
$probeExit = $LASTEXITCODE
$ErrorActionPreference = $oldEap

if ($probeExit -ne 0) {
    Write-Host "Installing validator-only Python dependencies..."
    & python -m pip install --upgrade tomli tomli_w boto3 httpx docker
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install validator dependencies."
    }
} else {
    Write-Host "[OK] Validator dependencies already present."
}

Section "5. GROUND-TRUTH PATCH VALIDATION"

Write-Host "CyberGym-E2E will now validate stages 3 and 4 in fresh containers:"
Write-Host "  Stage 3: project tests pass with the published patch"
Write-Host "  Stage 4: ground-truth PoC no longer crashes with the published patch"
Write-Host ""
Write-Host "This can take substantial time because Arrow may be compiled more than once."
Write-Host ""

$py = @'
import json
import sys
from pathlib import Path

bench = Path(r"__BENCH__")
task = bench / "projects" / "arrow" / "arvo_41221"
scripts = bench / "scripts"
sys.path.insert(0, str(scripts))

from run_agent import run_final_validation

results = run_final_validation(
    poc_path=None,
    patch_path=task / "patch.diff",
    data_path=task,
    script_path=task,
    build_image="n132/arvo:41221-fix",
    mode="patch-only",
)

print("\n=== MECHANICAL VALIDATION RESULT ===")
print(json.dumps(results, indent=2))

out = bench / "calibration_mechanical_result.json"
out.write_text(json.dumps(results, indent=2), encoding="utf-8")

if results.get("stage3") != "passed" or results.get("stage4") != "passed":
    raise SystemExit(5)
'@

$escapedBench = $benchDir.Replace("\","\\")
$py = $py.Replace("__BENCH__", $escapedBench)
$tmp = Join-Path $env:TEMP "aac2_mechanical_validation.py"
Set-Content -Path $tmp -Value $py -Encoding UTF8

$oldEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& python $tmp
$validationExit = $LASTEXITCODE
$ErrorActionPreference = $oldEap
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

if ($validationExit -ne 0) {
    throw "Mechanical benchmark validation failed (exit $validationExit). Do not run model calibration."
}

Section "6. RECORD LOCAL CALIBRATION METADATA"

$recordPath = Join-Path $benchDir "calibration_environment.json"
$record = [ordered]@{
    benchmark = "cybergym-e2e"
    benchmark_commit = $benchCommit
    task = "arrow/arvo_41221"
    purpose = "mechanical_calibration_only"
    model_called = $false
    build_image_tag = $Image
    build_image_id = $imageId
    build_image_repo_digests = $repoDigests
    ground_truth_patch_sha256 = $patchHash
    stage3 = "passed"
    stage4 = "passed"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
}
$record | ConvertTo-Json -Depth 5 | Set-Content -Path $recordPath -Encoding UTF8
Write-Host ("[OK] Environment record: {0}" -f $recordPath)

Section "7. RESULT"

Write-Host "[PASS] CyberGym-E2E mechanical calibration passed."
Write-Host "       Stage 3: PASS"
Write-Host "       Stage 4: PASS"
Write-Host "       No AI model was called."
Write-Host ""
Write-Host "NEXT GATE: construct the host-authenticated Claude Code/Codex adapter and"
Write-Host "           run ONE reserved patch-only calibration trajectory per model."
Write-Host ""
Write-Host "=== END MECHANICAL CALIBRATION ==="
\\r': command not found".  Re-materialise every
# tracked benchmark file directly from the pinned Git index with autocrlf off.
# Untracked downloaded task data (crash.log, poc.bin, src.tgz) is preserved.
git -C $benchDir config core.autocrlf false
git -C $benchDir config core.eol lf
git -C $benchDir checkout-index -f -a
if ($LASTEXITCODE -ne 0) {
    throw "Could not rematerialise the pinned CyberGym-E2E checkout with LF endings."
}

$benchCommitAfter = (git -C $benchDir rev-parse HEAD).Trim()
if ($benchCommitAfter -ne $PinnedBenchCommit) {
    throw "Benchmark commit changed during line-ending normalisation."
}

# Verify the helper that failed previously contains no carriage returns.
$installDeps = Join-Path $benchDir "scripts\install_validate_deps.sh"
$bytes = [System.IO.File]::ReadAllBytes($installDeps)
$crCount = ($bytes | Where-Object { $_ -eq 13 }).Count
if ($crCount -ne 0) {
    throw "CRLF normalisation failed: install_validate_deps.sh still contains $crCount CR bytes."
}
Write-Host "[OK] Pinned benchmark rematerialised with LF line endings."
Write-Host "[OK] install_validate_deps.sh contains no CR bytes."
Write-Host ("[OK] Benchmark commit remains: {0}" -f $benchCommitAfter)

Section "2. VERIFY CALIBRATION DATA"

foreach ($name in @("crash.log","poc.bin","src.tgz")) {
    $p = Join-Path $taskDir $name
    if (-not (Test-Path $p)) {
        throw "Missing calibration file: $p"
    }
    $actual = (Get-FileHash -Algorithm SHA256 $p).Hash.ToLower()
    if ($actual -ne $ExpectedHashes[$name]) {
        throw "SHA256 mismatch for $name"
    }
    Write-Host ("[OK] {0}: {1}" -f $name, $actual)
}

$patchPath = Join-Path $taskDir "patch.diff"
if (-not (Test-Path $patchPath)) {
    throw "Ground-truth patch missing from pinned benchmark source."
}
$patchHash = (Get-FileHash -Algorithm SHA256 $patchPath).Hash.ToLower()
Write-Host ("[OK] patch.diff SHA256: {0}" -f $patchHash)

Section "2. DOCKER IMAGE"

$dockerInfo = docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Docker engine is not reachable."
}

Write-Host ("Pulling only: {0}" -f $Image)
docker pull $Image
if ($LASTEXITCODE -ne 0) {
    throw "Docker image pull failed."
}

$inspectJson = docker image inspect $Image 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Could not inspect Docker image after pull."
}
$inspect = $inspectJson | ConvertFrom-Json
if (-not $inspect -or $inspect.Count -lt 1) {
    throw "Docker image inspect returned no object."
}

$imageObj = $inspect[0]
$imageId = [string]$imageObj.Id
$repoDigests = if ($imageObj.RepoDigests) { ($imageObj.RepoDigests -join ",") } else { "<none>" }
$imageSize = [int64]$imageObj.Size

Write-Host ("[OK] Image ID: {0}" -f $imageId)
Write-Host ("[OK] Repo digest(s): {0}" -f $repoDigests)
Write-Host ("[OK] Local image size: {0:N2} GiB" -f ($imageSize / 1GB))

Section "3. PYTHON VALIDATOR DEPENDENCIES"

$probe = 'import tomli, tomli_w, boto3, httpx, docker; print("OK")'
$oldEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$probeOut = & python -c $probe 2>$null
$probeExit = $LASTEXITCODE
$ErrorActionPreference = $oldEap

if ($probeExit -ne 0) {
    Write-Host "Installing validator-only Python dependencies..."
    & python -m pip install --upgrade tomli tomli_w boto3 httpx docker
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install validator dependencies."
    }
} else {
    Write-Host "[OK] Validator dependencies already present."
}

Section "4. GROUND-TRUTH PATCH VALIDATION"

Write-Host "CyberGym-E2E will now validate stages 3 and 4 in fresh containers:"
Write-Host "  Stage 3: project tests pass with the published patch"
Write-Host "  Stage 4: ground-truth PoC no longer crashes with the published patch"
Write-Host ""
Write-Host "This can take substantial time because Arrow may be compiled more than once."
Write-Host ""

$py = @'
import json
import sys
from pathlib import Path

bench = Path(r"__BENCH__")
task = bench / "projects" / "arrow" / "arvo_41221"
scripts = bench / "scripts"
sys.path.insert(0, str(scripts))

from run_agent import run_final_validation

results = run_final_validation(
    poc_path=None,
    patch_path=task / "patch.diff",
    data_path=task,
    script_path=task,
    build_image="n132/arvo:41221-fix",
    mode="patch-only",
)

print("\n=== MECHANICAL VALIDATION RESULT ===")
print(json.dumps(results, indent=2))

out = bench / "calibration_mechanical_result.json"
out.write_text(json.dumps(results, indent=2), encoding="utf-8")

if results.get("stage3") != "passed" or results.get("stage4") != "passed":
    raise SystemExit(5)
'@

$escapedBench = $benchDir.Replace("\","\\")
$py = $py.Replace("__BENCH__", $escapedBench)
$tmp = Join-Path $env:TEMP "aac2_mechanical_validation.py"
Set-Content -Path $tmp -Value $py -Encoding UTF8

$oldEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& python $tmp
$validationExit = $LASTEXITCODE
$ErrorActionPreference = $oldEap
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

if ($validationExit -ne 0) {
    throw "Mechanical benchmark validation failed (exit $validationExit). Do not run model calibration."
}

Section "5. RECORD LOCAL CALIBRATION METADATA"

$recordPath = Join-Path $benchDir "calibration_environment.json"
$record = [ordered]@{
    benchmark = "cybergym-e2e"
    benchmark_commit = $benchCommit
    task = "arrow/arvo_41221"
    purpose = "mechanical_calibration_only"
    model_called = $false
    build_image_tag = $Image
    build_image_id = $imageId
    build_image_repo_digests = $repoDigests
    ground_truth_patch_sha256 = $patchHash
    stage3 = "passed"
    stage4 = "passed"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
}
$record | ConvertTo-Json -Depth 5 | Set-Content -Path $recordPath -Encoding UTF8
Write-Host ("[OK] Environment record: {0}" -f $recordPath)

Section "6. RESULT"

Write-Host "[PASS] CyberGym-E2E mechanical calibration passed."
Write-Host "       Stage 3: PASS"
Write-Host "       Stage 4: PASS"
Write-Host "       No AI model was called."
Write-Host ""
Write-Host "NEXT GATE: construct the host-authenticated Claude Code/Codex adapter and"
Write-Host "           run ONE reserved patch-only calibration trajectory per model."
Write-Host ""
Write-Host "=== END MECHANICAL CALIBRATION ==="
