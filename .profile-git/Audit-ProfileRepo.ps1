[CmdletBinding()]
param([ValidateSet('staged', 'tracked')][string]$Mode = 'staged')

$ErrorActionPreference = 'Stop'
$root = (& git rev-parse --show-toplevel 2>$null | Out-String).Trim()
if (-not $root) { throw 'Not inside the Windows profile repository' }
Set-Location $root

$files = if ($Mode -eq 'staged') {
    @(& git diff --cached --name-only --diff-filter=ACMR)
} else {
    @(& git ls-tree -r --name-only HEAD)
}
$files = @($files | Where-Object { $_ })

$maxFileBytes = 8MB
$maxTotalBytes = 25MB
$totalBytes = 0L
$securityProblems = [Collections.Generic.List[string]]::new()
$skippedFiles = [Collections.Generic.List[object]]::new()

$forbiddenPaths = @(
    '(?i)(^|/)\.ssh(/|$)',
    '(?i)(^|/)NTUSER\.',
    '(?i)(^|/)(cookies?|login data|web data|local state|history)(/|$)',
    '(?i)(^|/)(cache|cachedmedia|logs?|crashdumps?|temp)(/|$)',
    '(?i)(loginusers\.vdf|config\.vdf)$',
    '(?i)(^|/)(Electronic Arts|EA Desktop)(/|$)',
    '(?i)\.(pem|pfx|p12|dmp|tmp|db|sqlite[0-9-]*)$'
)
$privateKeyHeader = '-----BEGIN [A-Z ]*PRIVATE KEY-----'
$inspectExtensions = @('.json', '.yaml', '.yml', '.xml', '.ini', '.cfg', '.conf', '.txt')

$retainedFiles = [Collections.Generic.List[string]]::new()

foreach ($file in $files) {
    $normalized = $file -replace '\\', '/'
    $isForbidden = $false
    $isApolloTls = ($normalized -match '(?i)^\.config/apollo/credentials/')
    foreach ($pattern in $forbiddenPaths) {
        if ($isApolloTls -and $pattern -match 'pem') { continue }
        if ($normalized -match $pattern) {
            $securityProblems.Add("forbidden path: $file")
            $isForbidden = $true
            break
        }
    }
    if ($isForbidden) { continue }

    # Inspect the exact snapshot that will be committed or pushed, not a
    # potentially different working-tree copy of the same path.
    $objectSpec = if ($Mode -eq 'staged') { ":$file" } else { "HEAD:$file" }
    $sizeText = (& git cat-file -s $objectSpec 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $sizeText -notmatch '^\d+$') {
        $securityProblems.Add("cannot inspect Git object: $file")
        continue
    }
    $size = [int64]$sizeText

    # Check for unencrypted private keys in text files (skip Apollo TLS keys which are intentionally included)
    if (-not $isApolloTls -and [IO.Path]::GetExtension($file).ToLowerInvariant() -in $inspectExtensions) {
        $content = (& git show $objectSpec 2>$null | Out-String)
        if ($content -match $privateKeyHeader) {
            $securityProblems.Add("unencrypted private key block: $file")
            continue
        }
    }

    # Size threshold check: 5MB
    if ($size -gt $maxFileBytes) {
        $sizeMb = [math]::Round($size / 1MB, 2)
        if ($Mode -eq 'staged') {
            # Gracefully unstage large file so it is not committed, but log it
            & git reset HEAD -- $file 2>$null | Out-Null
            $skippedFiles.Add([pscustomobject]@{
                Path = $file
                SizeBytes = $size
                SizeMB = $sizeMb
                Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            })
            Write-Warning "Skipped large blob (exceeds 8 MiB): $file ($sizeMb MiB). Unstaged from commit."
            continue
        } else {
            # In tracked mode, flag as problem since it is already committed in HEAD
            $securityProblems.Add("tracked file exceeds 8 MiB: $file ($sizeMb MiB)")
            continue
        }
    }

    $totalBytes += $size
    $retainedFiles.Add($file)
}

# Log skipped files to persistent audit log
if ($skippedFiles.Count -gt 0) {
    $logDir = Join-Path $root '.profile-git'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $logPath = Join-Path $logDir 'skipped-large-files.log'
    $logLines = $skippedFiles | ForEach-Object { "[$($_.Timestamp)] SKIPPED ($($_.SizeMB) MiB): $($_.Path)" }
    $logLines | Add-Content -Path $logPath -Encoding UTF8
    Write-Host "Logged $($skippedFiles.Count) skipped large file(s) to $logPath"
}

if ($totalBytes -gt $maxTotalBytes) {
    $securityProblems.Add("selected files exceed 25 MiB total ($([math]::Round($totalBytes / 1MB, 2)) MiB)")
}

if ($securityProblems.Count -gt 0) {
    $securityProblems | Sort-Object -Unique | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Host "Profile Git audit passed: $($retainedFiles.Count) files, $([math]::Round($totalBytes / 1MB, 2)) MiB."