<#
.SYNOPSIS
    The "did the protocol change?" button. Re-captures against the live lab and diffs.

.DESCRIPTION
    The committed corpus is a claim about what a real Exchange Server sends. This script is how
    that claim is re-tested: it captures the same scenarios again, into a scratch directory, and
    compares every byte against what is committed.

    Any difference at all is a finding. That is only a usable rule because capture already zeroes
    the handful of fields that genuinely differ every time - the clocks, the per-connection retry
    delay, the logon timestamps - and normalises the volatile headers. Each capture's .meta.txt
    itemises exactly what was zeroed, so the rule stays honest rather than convenient.

    What a difference means, in rough order of likelihood:

      * the mailbox changed - a message arrived, a folder was created. Re-seed or re-capture.
      * the server was updated. Re-measure the version-tied claims in the source, do not renumber
        them, and commit the new corpus with the new version in MANIFEST.toml.
      * this workspace changed what it sends. That is the interesting one, and the reason the
        request bodies are compared too.

    Nothing here writes to fixtures\. A verify that quietly overwrote the thing it was checking
    would be a verify that always passes.

.PARAMETER Mailbox
    The same mailbox identities Capture-Fixtures.ps1 was given.

.PARAMETER Password
    The password for those mailboxes. Defaults to MAPI_LIVE_PASSWORD.

.PARAMETER Root
    The committed fixtures directory. Defaults to fixtures\ in the repository.

.PARAMETER Keep
    Keep the scratch capture instead of deleting it, for inspecting a difference by hand.

.EXAMPLE
    powershell.exe -File scripts\Verify-Fixtures.ps1 -Mailbox developer,developer2
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]] $Mailbox,
    [string] $Password = $env:MAPI_LIVE_PASSWORD,
    [string] $Root,
    [switch] $Keep
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

$repoRoot = Get-RepoRoot
if (-not $Root) { $Root = Join-Path $repoRoot 'fixtures' }
if (-not (Test-Path -LiteralPath $Root)) { throw "No committed fixtures at $Root to verify." }

# See Capture-Fixtures.ps1: `powershell.exe -File` hands an array over as one comma-joined string.
$Mailbox = @($Mailbox | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } |
    Where-Object { $_ })

$scratch = Join-Path $env:TEMP "mapi-verify-$PID"
New-Item -ItemType Directory -Path $scratch -Force | Out-Null

Write-Step "Re-capturing into $scratch"

try {
    & "$PSScriptRoot\Capture-Fixtures.ps1" -Mailbox $Mailbox -Password $Password -Root $scratch
    if ($LASTEXITCODE -ne 0) { throw 'The re-capture failed; there is nothing to compare.' }

    # ---------------------------------------------------------------------
    # Compare. The manifest is excluded: it carries the capture date, which is
    # expected to differ and says nothing about the server.
    # ---------------------------------------------------------------------

    Write-Step 'Comparing against what is committed'

    function Get-FixtureFiles {
        <#
        .SYNOPSIS
            Every fixture under $Base, as a path relative to it.

        .DESCRIPTION
            Relative paths come from Resolve-Path -Relative rather than from trimming a prefix off
            each FullName. Trimming looks obviously correct and is not: $env:TEMP is routinely the
            8.3 short form (`ADMINI~1`) while an enumerated FullName is the long one, and the two
            differ in length, so every "relative" path comes out shifted by exactly that difference.
        #>
        [CmdletBinding()]
        param([Parameter(Mandatory)][string] $Base)

        Push-Location -LiteralPath $Base
        try {
            Get-ChildItem -Path . -Recurse -File |
                Where-Object { $_.FullName -notmatch '[\\/]raw[\\/]' } |
                Where-Object { $_.Name -ne 'MANIFEST.toml' } |
                ForEach-Object {
                    (Resolve-Path -LiteralPath $_.FullName -Relative).TrimStart('.', '\', '/').Replace('\', '/')
                }
        } finally {
            Pop-Location
        }
    }

    $committed = @(Get-FixtureFiles -Base $Root | Sort-Object)
    $fresh     = @(Get-FixtureFiles -Base $scratch | Sort-Object)

    $differences = New-Object System.Collections.Generic.List[psobject]

    foreach ($relative in ($committed | Where-Object { $fresh -notcontains $_ })) {
        $differences.Add([pscustomobject]@{ File = $relative; What = 'committed, but the server no longer produces it' })
    }
    foreach ($relative in ($fresh | Where-Object { $committed -notcontains $_ })) {
        $differences.Add([pscustomobject]@{ File = $relative; What = 'produced now, but not committed' })
    }

    foreach ($relative in ($committed | Where-Object { $fresh -contains $_ })) {
        $left  = [System.IO.File]::ReadAllBytes((Join-Path $Root $relative))
        $right = [System.IO.File]::ReadAllBytes((Join-Path $scratch $relative))

        if ($left.Length -ne $right.Length) {
            $differences.Add([pscustomobject]@{
                File = $relative
                What = "length: committed $($left.Length) bytes, now $($right.Length)"
            })
            continue
        }

        $at = -1
        for ($i = 0; $i -lt $left.Length; $i++) {
            if ($left[$i] -ne $right[$i]) { $at = $i; break }
        }
        if ($at -ge 0) {
            $differences.Add([pscustomobject]@{
                File = $relative
                What = ('first difference at byte {0} (0x{0:x}): committed 0x{1:x2}, now 0x{2:x2}' -f
                        $at, $left[$at], $right[$at])
            })
        }
    }

    if ($differences.Count -gt 0) {
        Write-Bad "$($differences.Count) difference(s) between the committed corpus and the server."
        Write-Host ''
        foreach ($difference in $differences) {
            Write-Host "    $($difference.File)" -ForegroundColor Red
            Write-Host "        $($difference.What)" -ForegroundColor Red
        }
        Write-Host ''
        Write-Host "    The fresh capture is at $scratch" -ForegroundColor Yellow
        Write-Host '    Read the .meta.txt on both sides before deciding what changed.' -ForegroundColor Yellow
        $script:Keep = $true
        exit 1
    }

    Write-Ok "$($committed.Count) file(s) identical; the server still sends what is committed"
    exit 0
} finally {
    if ($Keep) {
        Write-Host "    kept $scratch" -ForegroundColor DarkGray
    } else {
        Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
    }
}
