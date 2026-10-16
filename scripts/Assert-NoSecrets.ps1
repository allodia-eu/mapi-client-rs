<#
.SYNOPSIS
    Refuses to let anything that identifies a real deployment reach a commit.

.DESCRIPTION
    This script exists because of a failure mode that has already happened here: a scrub rule that
    matched nothing looks exactly like a scrub rule that worked. mapi-cli refuses to write a file
    that still carries one of its needles, and Capture-Fixtures.ps1 derives those needles from
    Exchange - but both of those are the same pair of eyes. This is the second, independent pair,
    and unlike them it needs no lab and runs in CI.

    Four checks, over every committed fixture file, in ASCII and in UTF-16LE, case-insensitively:

      1. GUIDs. A capture may carry only placeholder GUIDs - all zeros but for a two-digit
         suffix. Anything else is a real mailbox, replica or session identifier.
      2. Long hexadecimal runs. The blob inside a legacyExchangeDN is 32 hex characters; the same
         rule catches a leaked hash or handle. Placeholders are zeros but for a suffix.
      3. URL hosts. Every host named in a fixture must be one this repository chose.
      4. This machine's own names, when it has any - its NetBIOS name, its FQDN and its AD domain -
         plus whatever -Forbidden adds. On a CI runner these match nothing, which is fine: checks
         1 to 3 are the ones that carry CI.

    Check 4 then runs again over every other file git would commit - source, docs, scripts, the
    tracked ones and the new ones not yet added - when the repository's own fixtures are being
    checked. New files count because the gate runs before a commit, and a file only scanned once
    tracked would pass the gate with a name in it and be caught by nothing until after it landed. The other three would drown source code in OIDs
    and test vectors, but a lab's names have no business anywhere in it, and three of them had
    reached it unnoticed: the host name in mapi-cli's scrubber tests, the AD domain across
    mapi-autodiscover's, and the lab password in the NTLM tests. On the lab, the machine's names
    are exactly the ones that leaked; on a CI runner they match nothing.

    Binary fixtures are searched for the ASCII and UTF-16LE forms of each pattern rather than
    decoded, because a ROP buffer is not text and forcing it through a decoder would both miss
    matches and invent them.

.PARAMETER Root
    The fixtures directory. Defaults to fixtures\ in the repository.

.PARAMETER Forbidden
    Extra strings that must not appear. Capture-Fixtures.ps1 passes the values it just redacted.

.EXAMPLE
    powershell.exe -File scripts\Assert-NoSecrets.ps1

.EXAMPLE
    powershell.exe -File scripts\Assert-NoSecrets.ps1 -Forbidden '<lab host name>'
#>
[CmdletBinding()]
param(
    [string]   $Root,
    [string[]] $Forbidden = @()
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

# The source pass belongs to the repository's own check. Verify-Fixtures.ps1 points -Root at a
# fresh capture in TEMP, and re-reading the whole tree for each of those would only repeat this.
$scanTracked = -not $Root
if (-not $Root) { $Root = Join-Path (Get-RepoRoot) 'fixtures' }

# The hosts a committed fixture is allowed to name. `example.test` is the reserved-for-testing
# domain this repository uses throughout; `exchange-lab-01` is the placeholder every capture's real
# host name is replaced with.
$allowedHosts = @('exchange-lab-01', 'example.test', 'mail.example.test', 'localhost', '127.0.0.1')

# A placeholder identifier: zeros throughout but for a short numeric suffix that keeps two
# mailboxes apart.
$placeholderPattern = '^0*[0-9]{0,2}$'

$findings = New-Object System.Collections.Generic.List[psobject]

function Add-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $File,
        [Parameter(Mandatory)][string] $Check,
        [Parameter(Mandatory)][string] $Detail
    )
    $script:findings.Add([pscustomobject]@{ File = $File; Check = $Check; Detail = $Detail })
}

function Get-SearchableText {
    <#
    .SYNOPSIS
        The ASCII and UTF-16LE text hiding inside a file's bytes.

    .DESCRIPTION
        Two readings of the same bytes, because MAPI carries both encodings in one body: a
        distinguished name as 8-bit characters, a display name as UTF-16LE. A check that only did
        one of them would pass a capture whose folder names still said everything.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string] $Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $latin = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes)   # ISO-8859-1: byte = char
    $utf16 = [System.Text.Encoding]::Unicode.GetString($bytes)
    return @($latin, $utf16)
}

# This machine's own names, resolved once. Inside the file loop this was a DNS lookup per file per
# encoding, and it cannot change between files.
$names = @(@($Forbidden) + @(
    $env:COMPUTERNAME
    $env:USERDNSDOMAIN
    # The lab password, when this session has been given it. Only the scripts that need it are,
    # so a session that has run the live suite checks for it and one that has not cannot.
    $env:MAPI_LIVE_PASSWORD
    try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $null }
) | Where-Object { $_ -and $_.Length -ge 4 } | Select-Object -Unique)

$files = @()
if (Test-Path -LiteralPath $Root) {
    $files = @(Get-ChildItem -Path $Root -Recurse -File |
        Where-Object { $_.FullName -notmatch '[\\/]raw[\\/]' })
}

if ($files.Count -eq 0) {
    Write-Ok "no fixture files under $Root yet"
} else {
    Write-Step "Checking $($files.Count) fixture file(s) under $Root"
}

$repoRoot = Get-RepoRoot

foreach ($file in $files) {
    # -Root may point outside the repository - Verify-Fixtures.ps1 captures into TEMP - so trimming
    # the repository root off is only correct when the file is actually under it. Substring would
    # otherwise return a nonsense path, or throw outright on a root shorter than the repository's.
    $relative = if ($file.FullName.StartsWith($repoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        $file.FullName.Substring($repoRoot.Length).TrimStart('\', '/')
    } else {
        $file.FullName
    }

    foreach ($text in (Get-SearchableText -Path $file.FullName)) {

        # 1. GUIDs.
        foreach ($match in [regex]::Matches($text, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')) {
            $digits = ($match.Value -replace '-', '').TrimStart('0')
            if ($digits -notmatch $placeholderPattern) {
                Add-Finding -File $relative -Check 'guid' -Detail $match.Value
            }
        }

        # 2. Long hexadecimal runs, such as the blob inside a legacyExchangeDN.
        #
        # Not in MANIFEST.toml, which is a list of SHA-256 hashes and therefore nothing but long
        # hexadecimal runs by construction. Every other check still applies to it - a hash says
        # nothing about a deployment, but the file names beside it could.
        if ($file.Name -ne 'MANIFEST.toml') {
            foreach ($match in [regex]::Matches($text, '(?<![0-9a-fA-F])[0-9a-fA-F]{24,}(?![0-9a-fA-F])')) {
                $digits = $match.Value.TrimStart('0')
                if ($digits -notmatch $placeholderPattern) {
                    Add-Finding -File $relative -Check 'hex' -Detail $match.Value
                }
            }
        }

        # 3. URL hosts.
        foreach ($match in [regex]::Matches($text, '(?i)https?://([A-Za-z0-9._-]+)')) {
            $urlHost = $match.Groups[1].Value.ToLowerInvariant()
            if ($allowedHosts -notcontains $urlHost) {
                Add-Finding -File $relative -Check 'host' -Detail $match.Groups[1].Value
            }
        }

        # 4. Named strings.
        foreach ($name in $names) {
            if ($text.IndexOf($name, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                Add-Finding -File $relative -Check 'name' -Detail $name
            }
        }
    }
}

if ($scanTracked -and $names.Count -gt 0) {
    Initialize-GitOnPath
    $tracked = @(& git -C $repoRoot ls-files --cached --others --exclude-standard |
        Where-Object { $_ -notlike 'fixtures/*' })
    Write-Step "Checking $($tracked.Count) other file(s) git would commit for this machine's names"
    foreach ($path in $tracked) {
        $full = Join-Path $repoRoot $path
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
        foreach ($text in (Get-SearchableText -Path $full)) {
            foreach ($name in $names) {
                if ($text.IndexOf($name, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    Add-Finding -File $path -Check 'name' -Detail $name
                }
            }
        }
    }
}

if ($findings.Count -gt 0) {
    Write-Bad "$($findings.Count) finding(s). Do not commit these files."
    Write-Host ''
    foreach ($group in ($findings | Group-Object File)) {
        Write-Host "    $($group.Name)" -ForegroundColor Red
        foreach ($finding in ($group.Group | Select-Object Check, Detail -Unique)) {
            Write-Host "        [$($finding.Check)] $($finding.Detail)" -ForegroundColor Red
        }
    }
    Write-Host ''
    Write-Host '    In a fixture: widen the rules in Capture-Fixtures.ps1 and capture again, with' -ForegroundColor Yellow
    Write-Host '    replacements the same length as what they replace. Anywhere else: use the' -ForegroundColor Yellow
    Write-Host '    example.test names the rest of the repository uses.' -ForegroundColor Yellow
    exit 1
}

Write-Ok 'nothing tracked identifies a real deployment'
exit 0
