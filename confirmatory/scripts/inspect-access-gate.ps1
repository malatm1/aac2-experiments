param()

$ErrorActionPreference = "SilentlyContinue"

function Section($t) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host $t
    Write-Host "============================================================"
}

function FlagCheck($text, $flag) {
    if ($text -match [regex]::Escape($flag)) {
        Write-Host ("[OK]   supports {0}" -f $flag)
        return $true
    } else {
        Write-Host ("[INFO] {0} not found in help output" -f $flag)
        return $false
    }
}

Write-Host "AAC 2.0 SUBSCRIPTION/CLI ACCESS INSPECTION"
Write-Host ("Timestamp: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"))
Write-Host "NO MODEL PROMPTS WILL BE SENT."
Write-Host "CREDENTIAL CONTENTS WILL NOT BE PRINTED."

Section "1. CLAUDE CODE"

if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
    Write-Host "[MISS] Claude Code not found."
} else {
    $cv = (& claude --version 2>&1 | Out-String).Trim()
    Write-Host ("Version: {0}" -f $cv)

    try {
        $raw = (& claude auth status 2>$null | Out-String).Trim()
        if ($raw) {
            $obj = $raw | ConvertFrom-Json
            Write-Host ("Logged in: {0}" -f $obj.loggedIn)
            Write-Host ("Auth method: {0}" -f $obj.authMethod)
            Write-Host ("API provider: {0}" -f $obj.apiProvider)
            Write-Host ("Subscription type: {0}" -f $obj.subscriptionType)
        } else {
            Write-Host "[INFO] No machine-readable auth-status response."
        }
    } catch {
        Write-Host "[INFO] Could not parse Claude auth status."
    }

    $help = (& claude --help 2>&1 | Out-String)
    FlagCheck $help "--model" | Out-Null
    FlagCheck $help "--output-format" | Out-Null
    FlagCheck $help "--max-turns" | Out-Null
    FlagCheck $help "--allowedTools" | Out-Null
    FlagCheck $help "--disallowedTools" | Out-Null
    FlagCheck $help "--permission-mode" | Out-Null
    FlagCheck $help "--dangerously-skip-permissions" | Out-Null

    $claudeHome = Join-Path $HOME ".claude"
    if (Test-Path $claudeHome) {
        Write-Host ""
        Write-Host "Credential/config storage indicators (names only):"
        Get-ChildItem -Force $claudeHome -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'auth|credential|config|setting|token' } |
            ForEach-Object {
                Write-Host ("       {0} ({1} bytes)" -f $_.Name, $_.Length)
            }
    }
}

Section "2. CODEX"

if (-not (Get-Command codex -ErrorAction SilentlyContinue)) {
    Write-Host "[MISS] Codex not found."
} else {
    $xv = (& codex --version 2>&1 | Out-String).Trim()
    Write-Host ("Version: {0}" -f $xv)

    $help = (& codex --help 2>&1 | Out-String)
    FlagCheck $help "exec" | Out-Null
    FlagCheck $help "--model" | Out-Null
    FlagCheck $help "--sandbox" | Out-Null
    FlagCheck $help "--ask-for-approval" | Out-Null

    $execHelp = (& codex exec --help 2>&1 | Out-String)
    Write-Host ""
    Write-Host "Codex exec capabilities:"
    FlagCheck $execHelp "--model" | Out-Null
    FlagCheck $execHelp "--json" | Out-Null
    FlagCheck $execHelp "--sandbox" | Out-Null
    FlagCheck $execHelp "--skip-git-repo-check" | Out-Null

    Write-Host ""
    Write-Host "Login status:"
    try {
        $status = (& codex login status 2>&1 | Out-String).Trim()
        if ($status) {
            # Avoid echoing anything that resembles a token/key.
            $safe = $status -replace '(?i)(sk-[A-Za-z0-9_-]+)', '<REDACTED>'
            $safe = $safe -replace '(?i)(token[^\s:=]*\s*[:=]\s*)\S+', '$1<REDACTED>'
            Write-Host $safe
        } else {
            Write-Host "[INFO] Command returned no text."
        }
    } catch {
        Write-Host "[INFO] codex login status unavailable."
    }

    $codexHome = Join-Path $HOME ".codex"
    $auth = Join-Path $codexHome "auth.json"
    $config = Join-Path $codexHome "config.toml"

    Write-Host ""
    if (Test-Path $auth) {
        $fi = Get-Item $auth
        Write-Host ("[OK] Codex auth store present: auth.json ({0} bytes; contents not read)" -f $fi.Length)
    } else {
        Write-Host "[INFO] No ~/.codex/auth.json file found; authentication may use another local store."
    }

    if (Test-Path $config) {
        Write-Host "[OK] Codex config.toml present."
        $modelLines = Select-String -Path $config -Pattern '^\s*model\s*=|^\s*model_reasoning_effort\s*=' -ErrorAction SilentlyContinue
        foreach ($m in $modelLines) {
            Write-Host ("       {0}" -f $m.Line.Trim())
        }
    }
}

Section "3. ASTRA CLIENT VERSION GATE"

$astraMin = [version]"0.153.0"
$codexVerText = (& codex --version 2>$null | Out-String)
if ($codexVerText -match '(\d+\.\d+\.\d+)') {
    $installed = [version]$Matches[1]
    Write-Host ("Installed Codex CLI: {0}" -f $installed)
    Write-Host ("Required minimum for Astra: {0}" -f $astraMin)
    if ($installed -ge $astraMin) {
        Write-Host "[PASS] Codex CLI version meets the Astra client-version gate."
    } else {
        Write-Host "[ACTION REQUIRED] Update Codex CLI before Astra calibration."
    }
} else {
    Write-Host "[WARN] Could not parse Codex version automatically."
}

Section "4. HUGGING FACE TASK-DATA PREREQUISITES"

$hfCmd = Get-Command hf -ErrorAction SilentlyContinue
$hugCmd = Get-Command huggingface-cli -ErrorAction SilentlyContinue
if ($hfCmd) {
    Write-Host ("[OK] hf CLI found: {0}" -f $hfCmd.Source)
} elseif ($hugCmd) {
    Write-Host ("[OK] huggingface-cli found: {0}" -f $hugCmd.Source)
} else {
    Write-Host "[INFO] Hugging Face CLI not currently installed."
    Write-Host "       This is not yet a failure; we will install it only when task-data access is ready."
}

try {
    $hfPy = & python -c "import huggingface_hub; print(huggingface_hub.__version__)" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host ("[OK] Python huggingface_hub: {0}" -f ($hfPy | Out-String).Trim())
    } else {
        Write-Host "[INFO] Python huggingface_hub package not installed."
    }
} catch {
    Write-Host "[INFO] Python huggingface_hub package not installed."
}

Section "5. RESULT"
Write-Host "Inspection complete."
Write-Host "No model prompt was sent."
Write-Host "No credential contents were printed."
Write-Host "No benchmark data was downloaded."
Write-Host ""
Write-Host "=== END ACCESS INSPECTION ==="
