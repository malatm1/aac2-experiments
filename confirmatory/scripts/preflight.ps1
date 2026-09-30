param(
    [switch]$VerboseOutput
)

$ErrorActionPreference = "SilentlyContinue"

function Write-Section($title) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host $title
    Write-Host "============================================================"
}

function Get-CmdInfo($name, $versionArgs) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return [pscustomobject]@{
            Name = $name
            Found = $false
            Path = ""
            Version = ""
        }
    }

    $ver = ""
    try {
        $ver = (& $name @versionArgs 2>&1 | Out-String).Trim()
    } catch {
        $ver = "Version check failed: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Name = $name
        Found = $true
        Path = $cmd.Source
        Version = $ver
    }
}

function Show-CmdInfo($info) {
    if ($info.Found) {
        Write-Host ("[OK]   {0}" -f $info.Name)
        Write-Host ("       Path: {0}" -f $info.Path)
        Write-Host ("       Version: {0}" -f ($info.Version -replace "\r?\n"," | "))
    } else {
        Write-Host ("[MISS] {0}" -f $info.Name)
    }
}

function Safe-FilePreview($path, $patterns) {
    if (-not (Test-Path $path)) {
        return
    }

    Write-Host ("[FOUND] {0}" -f $path)
    foreach ($pattern in $patterns) {
        try {
            $matches = Select-String -Path $path -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
            foreach ($m in $matches) {
                $line = $m.Line
                # Redact obvious secrets/tokens/keys if present on same line.
                $line = $line -replace '(?i)(api[_-]?key\s*[=:]\s*)[^\s"'']+', '$1<REDACTED>'
                $line = $line -replace '(?i)(token\s*[=:]\s*)[^\s"'']+', '$1<REDACTED>'
                $line = $line -replace '(?i)(secret\s*[=:]\s*)[^\s"'']+', '$1<REDACTED>'
                Write-Host ("       {0}" -f $line.Trim())
            }
        } catch {}
    }
}

Write-Host "AAC 2.0 CONFIRMATORY-V2 LOCAL PREFLIGHT"
Write-Host ("Timestamp: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"))
Write-Host "This script does not launch GPT/Claude model calls."
Write-Host "It does not print API keys, tokens, or stored credentials."

Write-Section "1. WINDOWS / HOST"

try {
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Host ("OS: {0} {1}" -f $os.Caption, $os.Version)
    Write-Host ("Architecture: {0}" -f $os.OSArchitecture)
} catch {
    Write-Host ("OS: {0}" -f [System.Environment]::OSVersion.VersionString)
}

try {
    $drive = Get-PSDrive -Name ($PWD.Drive.Name)
    if ($drive) {
        Write-Host ("Current drive: {0}:" -f $drive.Name)
        Write-Host ("Free space: {0:N1} GB" -f ($drive.Free / 1GB))
        Write-Host ("Used space: {0:N1} GB" -f ($drive.Used / 1GB))
    }
} catch {}

Write-Host ("Current directory: {0}" -f (Get-Location))

Write-Section "2. REQUIRED COMMANDS"

$checks = @(
    (Get-CmdInfo "git" @("--version")),
    (Get-CmdInfo "python" @("--version")),
    (Get-CmdInfo "py" @("--version")),
    (Get-CmdInfo "docker" @("--version")),
    (Get-CmdInfo "wsl" @("--version")),
    (Get-CmdInfo "node" @("--version")),
    (Get-CmdInfo "npm" @("--version")),
    (Get-CmdInfo "claude" @("--version")),
    (Get-CmdInfo "codex" @("--version"))
)

foreach ($c in $checks) {
    Show-CmdInfo $c
}

Write-Section "3. DOCKER STATUS"

if (Get-Command docker -ErrorAction SilentlyContinue) {
    try {
        $dockerInfo = docker info --format "{{json .}}" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Docker engine is reachable."
            try {
                $obj = $dockerInfo | ConvertFrom-Json
                Write-Host ("     Server version: {0}" -f $obj.ServerVersion)
                Write-Host ("     OS/Arch: {0}/{1}" -f $obj.OperatingSystem, $obj.Architecture)
                Write-Host ("     CPUs: {0}" -f $obj.NCPU)
                if ($obj.MemTotal) {
                    Write-Host ("     Memory: {0:N1} GB" -f ($obj.MemTotal / 1GB))
                }
            } catch {
                if ($VerboseOutput) { Write-Host $dockerInfo }
            }
        } else {
            Write-Host "[WARN] Docker CLI exists but the Docker engine is not reachable."
            Write-Host "       Start Docker Desktop before calibration."
        }
    } catch {
        Write-Host "[WARN] Docker status check failed."
    }
} else {
    Write-Host "[MISS] Docker is not installed or not on PATH."
}

Write-Section "4. WSL STATUS"

if (Get-Command wsl -ErrorAction SilentlyContinue) {
    try {
        Write-Host (wsl --status 2>&1 | Out-String)
        Write-Host "Installed distributions:"
        Write-Host (wsl -l -v 2>&1 | Out-String)
    } catch {
        Write-Host "[WARN] Could not query WSL status."
    }
} else {
    Write-Host "[MISS] WSL command not found."
}

Write-Section "5. CLAUDE CODE LOCAL CONFIG"

$claudeHome = Join-Path $HOME ".claude"
if (Test-Path $claudeHome) {
    Write-Host ("[OK] Claude config directory exists: {0}" -f $claudeHome)
} else {
    Write-Host ("[INFO] Claude config directory not found at: {0}" -f $claudeHome)
}

$claudeSettings = Join-Path $claudeHome "settings.json"
Safe-FilePreview $claudeSettings @("model","effort","thinking")

Write-Host ""
Write-Host "Claude authentication status (if supported by this installed version):"
if (Get-Command claude -ErrorAction SilentlyContinue) {
    try {
        $auth = claude auth status 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host ($auth | Out-String)
        } else {
            Write-Host "[INFO] 'claude auth status' is unsupported or returned non-zero."
        }
    } catch {
        Write-Host "[INFO] Claude auth-status command unavailable."
    }
}

Write-Section "6. CODEX LOCAL CONFIG"

$codexHome = Join-Path $HOME ".codex"
if (Test-Path $codexHome) {
    Write-Host ("[OK] Codex config directory exists: {0}" -f $codexHome)
} else {
    Write-Host ("[INFO] Codex config directory not found at: {0}" -f $codexHome)
}

$codexConfig = Join-Path $codexHome "config.toml"
Safe-FilePreview $codexConfig @("model","reasoning","web_search","provider")

Write-Host ""
Write-Host "Codex authentication status (if supported by this installed version):"
if (Get-Command codex -ErrorAction SilentlyContinue) {
    try {
        $auth = codex login status 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host ($auth | Out-String)
        } else {
            Write-Host "[INFO] 'codex login status' is unsupported or returned non-zero."
        }
    } catch {
        Write-Host "[INFO] Codex login-status command unavailable."
    }
}

Write-Section "7. GIT REPOSITORY"

try {
    $inside = git rev-parse --is-inside-work-tree 2>$null
    if ($inside -eq "true") {
        Write-Host "[OK] Running inside a Git repository."
        Write-Host ("     Repo root: {0}" -f (git rev-parse --show-toplevel))
        Write-Host ("     Branch: {0}" -f (git branch --show-current))
        Write-Host ("     Commit: {0}" -f (git rev-parse HEAD))
        Write-Host ("     Remote: {0}" -f (git remote get-url origin))
    } else {
        Write-Host "[INFO] Current directory is not a Git repository."
    }
} catch {
    Write-Host "[INFO] Current directory is not a Git repository."
}

Write-Section "8. RESULT"

$requiredNames = @("git","docker","claude","codex")
$missing = @()
foreach ($n in $requiredNames) {
    if (-not (Get-Command $n -ErrorAction SilentlyContinue)) {
        $missing += $n
    }
}

$pythonAvailable = (Get-Command python -ErrorAction SilentlyContinue) -or (Get-Command py -ErrorAction SilentlyContinue)
if (-not $pythonAvailable) {
    $missing += "python/py"
}

if ($missing.Count -eq 0) {
    Write-Host "[PASS] Core preflight commands are present."
    Write-Host "       Next gate: clone/pin CyberGym-E2E and run one reserved calibration task."
} else {
    Write-Host ("[ACTION REQUIRED] Missing: {0}" -f ($missing -join ", "))
    Write-Host "Resolve these before benchmark calibration."
}

Write-Host ""
Write-Host "=== END PREFLIGHT ==="
