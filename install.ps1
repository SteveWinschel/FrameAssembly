# ==============================================================================
# FrameAssembly (frameassembly) — Windows PowerShell Zero-Admin Bootstrap Installer
# https://github.com/SteveWinschel/FrameAssembly
# https://frameassembly.ai.studio/
#
# Installs the prebuilt FrameAssembly release binary to
# $env:LOCALAPPDATA\Programs\FrameAssembly without administrator privileges,
# adds it to the user PATH, verifies SHA-256 against SHA256SUMS.txt, installs
# PowerShell Tab completions into $PROFILE if missing, and auto-installs the
# VS Code / Cursor / Windsurf / VSCodium / Antigravity extension (.vsix).
#
# Usage:
#   irm https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.ps1 | iex
#
# Options (when invoked as a script or scriptblock):
#   -DryRun         Show detected platform and planned actions without modifying the system
#   -NoVsCode       Skip automatic editor .vsix extension installation
#   -NoCompletions  Skip installing PowerShell Tab completion into $PROFILE
#   -Help           Display this help message and exit
# ==============================================================================

param(
    [switch]$DryRun,
    [switch]$NoVsCode,
    [switch]$NoCompletions,
    [Alias('h')]
    [switch]$Help
)

$ErrorActionPreference = 'Stop'

$ReleaseVersion = '3.0.0'
$VsixVersion = '3.0.0'
$GitHubReleaseBase = "https://github.com/SteveWinschel/FrameAssembly/releases/download/v$ReleaseVersion"
$VsixReleaseUrl = "$GitHubReleaseBase/frameassembly-vscode.vsix"
$VsixRawUrl = "https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/frameassembly-vscode/frameassembly-vscode-$VsixVersion.vsix"
$CompletionsRawUrl = 'https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/contrib/completions/frameassembly.ps1'

function Write-Info {
    param([string]$Message)
    Write-Host "[FrameAssembly] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[FrameAssembly] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "[FrameAssembly WARN] $Message" -ForegroundColor Yellow
}

function Show-Usage {
    @'
FrameAssembly (frameassembly) Windows PowerShell Bootstrap Installer

Usage:
  irm https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.ps1 | iex
  .\install.ps1 [-DryRun] [-NoVsCode] [-NoCompletions] [-Help]

Options:
  -DryRun         Show detected architecture and planned actions without modifying the system
  -NoVsCode       Skip installing the VS Code / Cursor / VSCodium editor extension
  -NoCompletions  Skip installing PowerShell Tab completion into $PROFILE
  -Help           Show this help message and exit
'@ | Write-Host
}

if ($Help) {
    Show-Usage
    return
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # Modern .NET / PowerShell 7+ enforces TLS 1.2+ automatically.
}

function Get-TargetArchiveName {
    $osArch = $null
    try {
        $osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    } catch {
        $osArch = $null
    }

    if ($osArch -eq 'Arm64' -or $env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {
        return 'frameassembly-windows-arm64.zip'
    }
    if ($osArch -eq 'X64' -or $env:PROCESSOR_ARCHITECTURE -eq 'AMD64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') {
        return 'frameassembly-windows-x64.zip'
    }
    throw "Unsupported Windows architecture ('$($env:PROCESSOR_ARCHITECTURE)'). FrameAssembly provides Windows x64 and ARM64 binaries."
}

function Invoke-DownloadFile {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile
    )
    $iwrParams = @{
        Uri         = $Uri
        OutFile     = $OutFile
        ErrorAction = 'Stop'
    }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $iwrParams['UseBasicParsing'] = $true
    }
    Invoke-WebRequest @iwrParams
}

function Get-ExpectedSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$SumsPath,
        [Parameter(Mandatory = $true)][string]$FileName
    )
    foreach ($line in Get-Content -Path $SumsPath -ErrorAction Stop) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+[*./\\]*([^\s]+)\s*$') {
            $hash = $Matches[1].ToLowerInvariant()
            $entryName = [System.IO.Path]::GetFileName($Matches[2])
            if ($entryName -eq $FileName) {
                return $hash
            }
        }
    }
    return $null
}

function Assert-FileSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$ExpectedHash,
        [Parameter(Mandatory = $true)][string]$DisplayName
    )
    $actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($actualHash -ne $ExpectedHash.ToLowerInvariant()) {
        throw "SHA-256 verification failed for $DisplayName. Expected: $ExpectedHash, Actual: $actualHash"
    }
    Write-Ok "Verified SHA-256 checksum for $DisplayName."
}

function Add-UserPathEntry {
    param([Parameter(Mandatory = $true)][string]$DirToAdd)

    $normalizedTarget = $DirToAdd.TrimEnd('\', '/')
    $currentUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @()
    if (-not [string]::IsNullOrWhiteSpace($currentUserPath)) {
        $entries = $currentUserPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }

    $alreadyPresent = $false
    foreach ($entry in $entries) {
        if ($entry.Trim().TrimEnd('\', '/').Equals($normalizedTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
            $alreadyPresent = $true
            break
        }
    }

    if (-not $alreadyPresent) {
        $newUserPath = if ($entries.Count -gt 0) {
            ($entries + $normalizedTarget) -join ';'
        } else {
            $normalizedTarget
        }
        [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
        Write-Ok "Added '$normalizedTarget' to user PATH (no Administrator rights required)."
    } else {
        Write-Info "'$normalizedTarget' is already in user PATH."
    }

    $sessionEntries = @()
    if (-not [string]::IsNullOrWhiteSpace($env:Path)) {
        $sessionEntries = $env:Path -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }
    $inSession = $false
    foreach ($entry in $sessionEntries) {
        if ($entry.Trim().TrimEnd('\', '/').Equals($normalizedTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
            $inSession = $true
            break
        }
    }
    if (-not $inSession) {
        $env:Path = if ([string]::IsNullOrWhiteSpace($env:Path)) {
            $normalizedTarget
        } else {
            "$normalizedTarget;$($env:Path)"
        }
    }
}

function Install-PowerShellCompletion {
    param(
        [Parameter(Mandatory = $true)][string]$InstallDir,
        [Parameter(Mandatory = $true)][string]$ExtractedDir
    )

    if ($NoCompletions) {
        Write-Info 'Skipping PowerShell Tab completion setup (-NoCompletions).'
        return
    }

    $completionsDir = Join-Path $InstallDir 'completions'
    $completionDest = Join-Path $completionsDir 'frameassembly.ps1'

    if ($DryRun) {
        Write-Info "[dry-run] Would install PowerShell completion script to $completionDest and wire into `$PROFILE ($PROFILE)"
        return
    }

    New-Item -ItemType Directory -Force -Path $completionsDir | Out-Null
    $bundledScript = Get-ChildItem -Path $ExtractedDir -Filter 'frameassembly.ps1' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $bundledScript -and (Test-Path $bundledScript.FullName)) {
        Copy-Item -Path $bundledScript.FullName -Destination $completionDest -Force
    } else {
        try {
            Invoke-DownloadFile -Uri $CompletionsRawUrl -OutFile $completionDest
        } catch {
            Write-WarnMsg "Could not download PowerShell completion script from ${CompletionsRawUrl}: $($_.Exception.Message)"
            return
        }
    }
    Unblock-File -Path $completionDest -ErrorAction SilentlyContinue

    if ([string]::IsNullOrWhiteSpace($PROFILE)) {
        Write-WarnMsg 'PowerShell $PROFILE path is empty; completion script saved to disk only.'
        return
    }

    $profileDir = Split-Path -Parent $PROFILE
    if (-not [string]::IsNullOrWhiteSpace($profileDir) -and -not (Test-Path $profileDir)) {
        New-Item -ItemType Directory -Force -Path $profileDir | Out-Null
    }
    if (-not (Test-Path $PROFILE)) {
        New-Item -ItemType File -Force -Path $PROFILE | Out-Null
    }

    $existingProfile = Get-Content -Path $PROFILE -Raw -ErrorAction SilentlyContinue
    if ($null -eq $existingProfile) {
        $existingProfile = ''
    }

    if ($existingProfile -notmatch 'frameassembly\.ps1') {
        $escapedDest = $completionDest.Replace("'", "''")
        $newline = [Environment]::NewLine
        $prefix = if ($existingProfile.Length -gt 0 -and -not $existingProfile.EndsWith("`n")) { $newline } else { '' }
        $block = "${prefix}${newline}# FrameAssembly Tab completion${newline}if (Test-Path '$escapedDest') {${newline}    . '$escapedDest'${newline}}${newline}"
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::AppendAllText($PROFILE, $block, $utf8NoBom)
        Write-Ok "Added FrameAssembly PowerShell Tab completions to `$PROFILE ($PROFILE)."
    } else {
        Write-Info "PowerShell Tab completions are already configured in `$PROFILE."
    }

    try {
        . $completionDest
    } catch {
        # Best-effort activation for current session.
    }
}

function Install-EditorExtension {
    param(
        [Parameter(Mandatory = $true)][string]$TempRoot,
        [Parameter(Mandatory = $true)][string]$SumsPath
    )

    if ($NoVsCode) {
        Write-Info 'Skipping editor .vsix extension install (-NoVsCode).'
        return
    }

    $detectedEditors = @()
    foreach ($candidate in @('code', 'cursor', 'codium', 'windsurf', 'agy')) {
        $cmd = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($null -ne $cmd) {
            $detectedEditors += $candidate
        }
    }

    if ($detectedEditors.Count -eq 0) {
        return
    }

    if ($DryRun) {
        Write-Info "[dry-run] Detected editors ($($detectedEditors -join ', ')); would download and install $VsixReleaseUrl (fallback: $VsixRawUrl)"
        return
    }

    $vsixPath = Join-Path $TempRoot 'frameassembly-vscode.vsix'
    $downloadedFromRelease = $false
    Write-Info "Downloading FrameAssembly Packet Studio extension (v$VsixVersion)..."
    try {
        Invoke-DownloadFile -Uri $VsixReleaseUrl -OutFile $vsixPath
        $downloadedFromRelease = $true
    } catch {
        try {
            Invoke-DownloadFile -Uri $VsixRawUrl -OutFile $vsixPath
        } catch {
            Write-WarnMsg "Could not download VS Code extension (.vsix): $($_.Exception.Message)"
            return
        }
    }

    if ($downloadedFromRelease -and (Test-Path $SumsPath)) {
        $expectedVsixHash = Get-ExpectedSha256 -SumsPath $SumsPath -FileName 'frameassembly-vscode.vsix'
        if (-not [string]::IsNullOrWhiteSpace($expectedVsixHash)) {
            Assert-FileSha256 -FilePath $vsixPath -ExpectedHash $expectedVsixHash -DisplayName 'frameassembly-vscode.vsix'
        }
    }

    foreach ($editorCli in $detectedEditors) {
        Write-Info "Installing extension via '$editorCli'..."
        try {
            & $editorCli --install-extension $vsixPath | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "Installed FrameAssembly extension in $editorCli."
            } else {
                Write-WarnMsg "'$editorCli --install-extension' exited with code $LASTEXITCODE."
            }
        } catch {
            Write-WarnMsg "Failed to install extension via '$editorCli': $($_.Exception.Message)"
        }
    }
}

$archiveName = Get-TargetArchiveName
$arch = if ($archiveName -eq 'frameassembly-windows-arm64.zip') { 'arm64' } else { 'x64' }
$archiveUrl = "$GitHubReleaseBase/$archiveName"
$sumsUrl = "$GitHubReleaseBase/SHA256SUMS.txt"

$localAppData = if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    $env:LOCALAPPDATA
} else {
    Join-Path $HOME 'AppData\Local'
}
$installDir = Join-Path $localAppData 'Programs\FrameAssembly'
$exeDest = Join-Path $installDir 'frameassembly.exe'

Write-Info "Starting FrameAssembly v$ReleaseVersion Windows ($arch) installer..."

if ($DryRun) {
    Write-Info "[dry-run] Detected Windows architecture: $arch"
    Write-Info "[dry-run] Would download checksums: $sumsUrl"
    Write-Info "[dry-run] Would download archive:   $archiveUrl"
    Write-Info "[dry-run] Would verify SHA-256 and install to: $exeDest"
    Write-Info "[dry-run] Would add '$installDir' to User PATH (no Admin required)"
    Install-PowerShellCompletion -InstallDir $installDir -ExtractedDir $installDir
    Install-EditorExtension -TempRoot $env:TEMP -SumsPath ''
    Write-Ok 'Dry run completed successfully.'
    return
}

$tempBase = if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
$workDir = Join-Path $tempBase ("frameassembly-install-" + [System.Guid]::NewGuid().ToString('N'))
$extractDir = Join-Path $workDir 'extract'
$sumsPath = Join-Path $workDir 'SHA256SUMS.txt'
$zipPath = Join-Path $workDir $archiveName

try {
    New-Item -ItemType Directory -Force -Path $workDir, $extractDir | Out-Null

    Write-Info "Downloading SHA256SUMS.txt from v$ReleaseVersion release..."
    Invoke-DownloadFile -Uri $sumsUrl -OutFile $sumsPath

    $expectedHash = Get-ExpectedSha256 -SumsPath $sumsPath -FileName $archiveName
    if ([string]::IsNullOrWhiteSpace($expectedHash)) {
        throw "Could not find a SHA-256 entry for '$archiveName' in $sumsUrl."
    }

    Write-Info "Downloading $archiveName..."
    Invoke-DownloadFile -Uri $archiveUrl -OutFile $zipPath

    Assert-FileSha256 -FilePath $zipPath -ExpectedHash $expectedHash -DisplayName $archiveName

    Write-Info "Extracting $archiveName..."
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    $exeSource = Get-ChildItem -Path $extractDir -Filter 'frameassembly.exe' -Recurse -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $exeSource) {
        throw "frameassembly.exe was not found inside $archiveName."
    }

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Copy-Item -Path $exeSource.FullName -Destination $exeDest -Force
    Unblock-File -Path $exeDest -ErrorAction SilentlyContinue

    $quickstartSrc = Get-ChildItem -Path $extractDir -Filter 'quickstart.frasm' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $quickstartSrc) {
        Copy-Item -Path $quickstartSrc.FullName -Destination (Join-Path $installDir 'quickstart.frasm') -Force
    }

    Add-UserPathEntry -DirToAdd $installDir
    Install-PowerShellCompletion -InstallDir $installDir -ExtractedDir $extractDir
    Install-EditorExtension -TempRoot $workDir -SumsPath $sumsPath

    $installedVer = (& $exeDest version 2>$null)
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($installedVer)) {
        Write-Ok "Successfully installed $installedVer to $exeDest!"
    } else {
        Write-Ok "Successfully installed FrameAssembly v$ReleaseVersion to $exeDest!"
    }

    Write-Info 'Quickstart (copy and paste to run right away):'
    @'
  @('host client { ip 10.0.0.10 }', 'host server { ip 10.0.0.20 }', 'compile {', '  client -> server http get uri "/healthz" hosthdr "api.example.com" wait 2ms', '  client <- server http status 200 reason "OK" body "ok"', '}') | Set-Content -Encoding Ascii quickstart.frasm; frameassembly show quickstart.frasm; frameassembly quickstart.frasm quickstart.pcap
'@ | Write-Host -ForegroundColor White
    Write-Host ''
    Write-Info 'Browser Playground: https://frameassembly.ai.studio/'
} finally {
    Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
