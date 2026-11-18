$ErrorActionPreference = 'Stop'

function Allow-AndExit {
    [Console]::Out.WriteLine('{"decision":"allow"}')
    exit 0
}

try {
    $payload = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($payload)) {
        Allow-AndExit
    }

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $lockDir = Join-Path $repoRoot 'temp\.locks'
    if (-not (Test-Path -LiteralPath $lockDir)) {
        Allow-AndExit
    }

    $data = $payload | ConvertFrom-Json
    $argsObj = $null
    if ($null -ne $data.toolCall -and $null -ne $data.toolCall.args) {
        $argsObj = $data.toolCall.args
    } elseif ($null -ne $data.tool_input) {
        $argsObj = $data.tool_input
    }

    $targetPath = ''
    if ($null -ne $argsObj) {
        if ($argsObj.PSObject.Properties.Name -contains 'Path' -and -not [string]::IsNullOrWhiteSpace($argsObj.Path)) {
            $targetPath = [string]$argsObj.Path
        } elseif ($argsObj.PSObject.Properties.Name -contains 'TargetFile' -and -not [string]::IsNullOrWhiteSpace($argsObj.TargetFile)) {
            $targetPath = [string]$argsObj.TargetFile
        }
    }

    if ([string]::IsNullOrWhiteSpace($targetPath)) {
        Allow-AndExit
    }

    $convId = ''
    if ($data.PSObject.Properties.Name -contains 'conversationId' -and $null -ne $data.conversationId) {
        $convId = [string]$data.conversationId
    }

    $norm = $targetPath.Replace('\', '/')
    $repoSlash = $repoRoot.Replace('\', '/').TrimEnd('/') + '/'
    if ($norm.StartsWith($repoSlash, [System.StringComparison]::OrdinalIgnoreCase)) {
        $norm = $norm.Substring($repoSlash.Length)
    }
    if ($norm.StartsWith('./')) {
        $norm = $norm.Substring(2)
    }

    $slug = 'lock_' + ($norm -replace '[^a-zA-Z0-9._-]', '__')
    $metaFile = Join-Path $lockDir ($slug + '.meta')

    if (Test-Path -LiteralPath $metaFile) {
        $rawMeta = ([System.IO.File]::ReadAllText($metaFile)).Trim()
        $parts = $rawMeta -split '\s+'
        if ($parts.Count -ge 2) {
            $holder = $parts[0]
            [long]$expiresAt = 0
            if ([long]::TryParse($parts[1], [ref]$expiresAt)) {
                $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                if ($now -lt $expiresAt) {
                    $callerId = if (-not [string]::IsNullOrWhiteSpace($env:FASM_AGENT_ID)) { $env:FASM_AGENT_ID } else { $convId }
                    if (-not [string]::IsNullOrWhiteSpace($callerId) -and ($holder -ne $callerId) -and ($env:FASM_LOCK_ENFORCE_STRICT -eq '1')) {
                        $rem = $expiresAt - $now
                        $reason = "File $norm is currently locked by parallel agent $holder (${rem}s remaining). Acquire lock via .agents/scripts/file_lock.sh or edit disjoint files."
                        $resp = @{ decision = 'deny'; reason = $reason } | ConvertTo-Json -Compress
                        [Console]::Out.WriteLine($resp)
                        exit 0
                    }
                } else {
                    Remove-Item -LiteralPath $metaFile -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    Allow-AndExit
} catch {
    Allow-AndExit
}