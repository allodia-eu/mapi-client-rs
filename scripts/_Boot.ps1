<#
.SYNOPSIS
    Common bootstrap for every mapi-client-rs script. Dot-source it first, always.

.DESCRIPTION
    Enforces the Windows PowerShell 5.1 (Desktop) requirement, then provides the handful of
    helpers every other script needs: repository root resolution, a *verified* poppler
    `pdftotext`, the SPEC.md document table, and the coverage floor from codecov.yml.

    Why 5.1 and not PowerShell 7:

        | Capability                              | 5.1 Desktop | 7.x Core                    |
        |-----------------------------------------|-------------|-----------------------------|
        | Add-PSSnapin, for the Exchange snapin   | works       | impossible (cmdlet absent)  |
        | Invoke-Command into an Exchange session | works       | fails (NoLanguage runspace) |
        | Import-PSSession implicit remoting      | works       | works, but unsupported by MS|

    The consequence worth stating plainly: 5.1 is Windows-only, so these scripts cannot run on
    Linux CI. That costs nothing, because CI has no Exchange access anyway — CI runs pure `cargo`
    against committed fixtures. These scripts are local and lab tooling only.

.EXAMPLE
    . "$PSScriptRoot\_Boot.ps1"
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Encoding note, because this bites exactly once and costs an hour.
#
# This file MUST be saved as UTF-8 *with* a BOM. Windows PowerShell 5.1 reads a
# BOM-less file as ANSI (Windows-1252), so a single non-ASCII character - an em
# dash in a comment is enough - arrives as mojibake, and if it lands inside a
# quoted string the parse fails.
#
# The failure mode is nastier than a syntax error, which is why Invoke-Gate.ps1
# checks the BOM mechanically: a dot-sourced file that fails to parse does NOT
# stop the calling script. The caller carries on with none of these functions
# defined and, unless it guards, exits 0. That is a false green in the gate.
# Hence Assert-BootLoaded below, which every script calls immediately.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# The 5.1 gate. Deliberately the very first thing that runs.
# ---------------------------------------------------------------------------

if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSEdition -ne 'Desktop') {
    throw ("mapi-client-rs scripts require Windows PowerShell 5.1 (Desktop). " +
           "You are on $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)). " +
           "Run 'powershell.exe', not 'pwsh'.")
}

# PS 5.1 negotiates SSL3/TLS 1.0 by default on some hosts, which every modern site rejects.
# Without this, Get-Specs.ps1 fails with an opaque "connection was closed" error.
[System.Net.ServicePointManager]::SecurityProtocol = `
    [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11

# ---------------------------------------------------------------------------
# Load guard
# ---------------------------------------------------------------------------

function Assert-BootLoaded {
    <#
    .SYNOPSIS
        No-op that proves _Boot.ps1 parsed and loaded. Call it right after dot-sourcing.

    .DESCRIPTION
        If _Boot.ps1 fails to parse, dot-sourcing it prints the parse error but does not stop the
        caller, which then runs on with no helpers defined and exits 0. Calling this function
        under $ErrorActionPreference = 'Stop' turns that silent false green into a hard failure,
        because a command that does not exist is a terminating error.
    #>
    [CmdletBinding()]
    param()
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

function Write-Step {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Message)
    Write-Host "    OK   $Message" -ForegroundColor Green
}

function Write-Warn {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Message)
    Write-Host "    WARN $Message" -ForegroundColor Yellow
}

function Write-Bad {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Message)
    Write-Host "    FAIL $Message" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# Repository layout
# ---------------------------------------------------------------------------

function Get-RepoRoot {
    <#
    .SYNOPSIS
        Absolute path to the repository root, derived from this script's own location.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

function Get-SpecDir {
    <#
    .SYNOPSIS
        Absolute path to the gitignored spec/ directory, created if absent.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $dir = Join-Path (Get-RepoRoot) 'spec'
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    return (Resolve-Path $dir).Path
}

# ---------------------------------------------------------------------------
# poppler
# ---------------------------------------------------------------------------

function Initialize-GitOnPath {
    <#
    .SYNOPSIS
        Ensures git.exe is resolvable, adding the standard install location to PATH if it is not.

    .DESCRIPTION
        Git for Windows can be installed such that git is only on Git Bash's own PATH and not on
        the Windows PATH at all. Everything that shells out to git then fails in a way that names
        git without explaining it - cargo-deny, for instance, reports only

            failed to fetch advisory database ... failed to spawn git: program not found

        which reads like a network or cargo-deny problem rather than a PATH one.

        Modifies PATH for this process only; nothing persists.
    #>
    [CmdletBinding()]
    param()

    if (Get-Command 'git.exe' -ErrorAction SilentlyContinue) { return }

    foreach ($dir in @(
        (Join-Path $env:ProgramFiles 'Git\cmd'),
        (Join-Path ${env:ProgramFiles(x86)} 'Git\cmd'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Git\cmd')
    )) {
        if (Test-Path -LiteralPath (Join-Path $dir 'git.exe')) {
            $env:PATH = "$dir;$env:PATH"
            Write-Verbose "Added $dir to PATH for this process"
            return
        }
    }

    Write-Warning ('git.exe is not on PATH and was not found in the usual locations. ' +
                   'cargo-deny cannot fetch its advisory database without it.')
}

function Get-NativeOutput {
    <#
    .SYNOPSIS
        Runs a native command and returns its merged stdout+stderr and exit code.

    .DESCRIPTION
        Needed because of a Windows PowerShell 5.1 trap: under
        $ErrorActionPreference = 'Stop', anything a native executable writes to stderr becomes a
        terminating NativeCommandError as soon as you merge the streams with 2>&1 - even when the
        command succeeded. poppler's pdftotext writes its version banner to stderr, so the
        straightforward `& $exe -v 2>&1` throws.

        Dropping the preference to Continue is scoped to this function, so callers keep Stop.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)][string] $FilePath,
        [Parameter()][string[]]        $Arguments = @()
    )

    $ErrorActionPreference = 'Continue'
    $output = & $FilePath @Arguments 2>&1 | Out-String

    return [pscustomobject]@{
        Output   = $output
        ExitCode = $LASTEXITCODE
    }
}

function Resolve-PdfToText {
    <#
    .SYNOPSIS
        Absolute path to poppler's pdftotext.exe, verified to actually be poppler.

    .DESCRIPTION
        Resolving this by name alone is a trap, and not a hypothetical one: the Python `pdftotext`
        package installs a shim of the same name that exits 0, prints "Done!" for -v, and takes
        different arguments. When it shadowed poppler on the original development machine,
        Check-SpecVersion.ps1 extracted nothing, found no version string, and would have reported
        a spec mismatch that did not exist.

        That particular shim has since been removed from that machine, which is exactly why the
        check stays: the next clone is on a machine nobody has audited.

        So: prefer an explicit MAPI_PDFTOTEXT override, then scan the known install locations, and
        in every case confirm the binary identifies itself as poppler before returning it. A tool
        that is silently the wrong tool is exactly the failure mode this repository keeps tripping
        over (see the fixture-scrubbing rule in CONTRIBUTING.md).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $candidates = New-Object System.Collections.Generic.List[string]

    if ($env:MAPI_PDFTOTEXT) { $candidates.Add($env:MAPI_PDFTOTEXT) }

    # winget's poppler package, which is how this machine has it.
    $wingetRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
    if (Test-Path -LiteralPath $wingetRoot) {
        Get-ChildItem -Path $wingetRoot -Filter 'pdftotext.exe' -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object { $candidates.Add($_.FullName) }
    }

    # Chocolatey / scoop / manual unzip, and finally whatever is on PATH.
    foreach ($p in @(
        'C:\ProgramData\chocolatey\bin\pdftotext.exe',
        (Join-Path $env:USERPROFILE 'scoop\shims\pdftotext.exe')
    )) { $candidates.Add($p) }

    Get-Command 'pdftotext.exe' -All -ErrorAction SilentlyContinue |
        ForEach-Object { $candidates.Add($_.Source) }

    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        if (-not (Test-Path -LiteralPath $candidate)) { continue }

        # poppler prints "pdftotext version 25.07.0" to stderr and exits non-zero for -v; the
        # Python shim prints "Done!" and exits 0. Match on the identifying string, not the code.
        $banner = (Get-NativeOutput -FilePath $candidate -Arguments @('-v')).Output
        if ($banner -match 'poppler') {
            $versionMatch = [regex]::Match($banner, 'pdftotext\s+version\s+(\S+)')
            $version = if ($versionMatch.Success) { $versionMatch.Groups[1].Value } else { 'unknown' }
            Write-Verbose "Using poppler pdftotext $version at $candidate"
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw ("poppler's pdftotext.exe was not found. Note that any pdftotext on PATH is not " +
           "sufficient — the Python package of the same name is not poppler and will silently " +
           "extract nothing. Install poppler (winget install oschwartz10612.Poppler) or set " +
           "MAPI_PDFTOTEXT to the full path of poppler's pdftotext.exe.")
}

# ---------------------------------------------------------------------------
# SPEC.md — the single source of truth for which documents, at which version
# ---------------------------------------------------------------------------

function Get-SpecManifest {
    <#
    .SYNOPSIS
        Parses the pinned-document table out of SPEC.md.

    .OUTPUTS
        One object per document with Name, Version, Pages, Covers, Url, PdfPath and TxtPath.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param()

    $specMd = Join-Path (Get-RepoRoot) 'SPEC.md'
    if (-not (Test-Path -LiteralPath $specMd)) {
        throw "SPEC.md not found at $specMd. It is the single source of truth for spec versions."
    }

    $content = Get-Content -LiteralPath $specMd -Raw
    $between = [regex]::Match(
        $content,
        '<!--\s*SPEC-TABLE-START\s*-->(.*?)<!--\s*SPEC-TABLE-END\s*-->',
        [System.Text.RegularExpressions.RegexOptions]::Singleline)

    if (-not $between.Success) {
        throw "SPEC.md is missing its SPEC-TABLE-START / SPEC-TABLE-END markers."
    }

    $specDir = Join-Path (Get-RepoRoot) 'spec'
    $docs = New-Object System.Collections.Generic.List[psobject]

    foreach ($line in ($between.Groups[1].Value -split "`r?`n")) {
        $trimmed = $line.Trim()
        if (-not $trimmed.StartsWith('|')) { continue }

        $cells = @($trimmed.Trim('|') -split '\|' | ForEach-Object { $_.Trim() })
        if ($cells.Count -lt 5) { continue }
        if ($cells[0] -eq 'Document') { continue }      # header row
        if ($cells[0] -match '^-{2,}$') { continue }    # separator row

        $docs.Add([pscustomobject]@{
            Name    = $cells[0]
            Version = $cells[1]
            Pages   = $cells[2]
            Covers  = $cells[3]
            Url     = $cells[4]
            PdfPath = Join-Path $specDir "$($cells[0]).pdf"
            TxtPath = Join-Path $specDir "$($cells[0]).txt"
        })
    }

    if ($docs.Count -eq 0) {
        throw "No document rows parsed from the SPEC.md table. Has its format changed?"
    }

    return $docs.ToArray()
}

# ---------------------------------------------------------------------------
# codecov.yml — the coverage floor, defined once
# ---------------------------------------------------------------------------

function Get-CoverageFloor {
    <#
    .SYNOPSIS
        The project coverage target from codecov.yml, as an integer percentage.

    .DESCRIPTION
        Read rather than duplicated so that the floor lives in exactly one file. CI does the same
        parse in ci.yml; if you change the shape of codecov.yml, change both.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $path = Join-Path (Get-RepoRoot) 'codecov.yml'
    $text = Get-Content -LiteralPath $path -Raw

    # Deliberately a targeted regex rather than a YAML parser: PS 5.1 ships none, and adding a
    # module dependency for one scalar is a worse trade than a regex with a guarded failure.
    $match = [regex]::Match($text, '(?ms)^\s*project:\s*\r?\n\s*default:\s*\r?\n\s*target:\s*(\d+)%')
    if (-not $match.Success) {
        throw "Could not read coverage.status.project.default.target from $path."
    }

    return [int]$match.Groups[1].Value
}

# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------

function Invoke-Native {
    <#
    .SYNOPSIS
        Runs a native command and throws if it exits non-zero.

    .DESCRIPTION
        PowerShell does not treat a non-zero exit code from a native executable as an error, so
        without this a failing `cargo clippy` in the middle of the gate scrolls past and the gate
        reports success.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $FilePath,
        [Parameter()][string[]]          $Arguments = @(),
        [Parameter()][string]            $WorkingDirectory
    )

    $previous = $null
    if ($WorkingDirectory) {
        $previous = (Get-Location).Path
        Set-Location -LiteralPath $WorkingDirectory
    }

    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$FilePath $($Arguments -join ' ') exited with code $LASTEXITCODE."
        }
    } finally {
        if ($previous) { Set-Location -LiteralPath $previous }
    }
}

function Get-CargoPath {
    <#
    .SYNOPSIS
        Absolute path to cargo.exe, so the scripts do not depend on PATH being inherited.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $cargo = Get-Command 'cargo.exe' -ErrorAction SilentlyContinue
    if ($cargo) { return $cargo.Source }

    $fallback = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path -LiteralPath $fallback) { return $fallback }

    throw "cargo.exe not found on PATH or at $fallback. Is the Rust toolchain installed?"
}

# The MAPI virtual directory, resolved once per run. It does not change while a script is running,
# and Get-MapiVirtualDirectory is slow enough that four calls are noticeable.
$script:MapiVirtualDirectory = $null

function Get-LabMailbox {
    <#
    .SYNOPSIS
        Everything a live run needs about one mailbox, asked of Exchange rather than typed.

    .DESCRIPTION
        The endpoint, the distinguished name, the SMTP address and the session LCID, derived from
        the Exchange management snapin. Nothing about anybody's deployment is committed to this
        repository, so every script that talks to the lab starts here.

        Shared because there were two copies and a third was about to appear. Capture-Fixtures.ps1
        keeps its own: it needs the mailbox GUID and the blob inside the distinguished name to build
        the scrub rules, which nothing else does, and pairing that down to this shape would leave it
        deriving half its material twice.

        The endpoint's ?MailboxId= parameter is not optional. Without it Exchange answers HTTP 400
        with no X-ResponseCode header at all, which reads like the URL being wrong rather than
        incomplete.

    .PARAMETER Identity
        The mailbox to ask about, as Get-Mailbox takes it.

    .OUTPUTS
        A PSCustomObject with Identity, Smtp, Dn, Guid, Endpoint, Language and Lcid.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)][string] $Identity
    )

    if (-not (Get-PSSnapin -Name 'Microsoft.Exchange.Management.PowerShell.SnapIn' -ErrorAction SilentlyContinue)) {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
    }

    if (-not $script:MapiVirtualDirectory) {
        $script:MapiVirtualDirectory = @(Get-MapiVirtualDirectory -Server $env:COMPUTERNAME)[0]
        if (-not $script:MapiVirtualDirectory) {
            throw "No MAPI virtual directory on $env:COMPUTERNAME."
        }
    }

    $box = Get-Mailbox -Identity $Identity
    $domain = ([string]$box.PrimarySmtpAddress -split '@')[-1]

    # The session locale, matched to the mailbox so the run is coherent. It does not translate
    # anything: folder names come back in whatever language the mailbox already holds them.
    #
    # Resolved defensively. A mailbox with no regional configuration reports no language at all,
    # and casting a name that is not a culture throws - which would abort a whole run before a
    # single request had been made, over a setting that only picks an LCID.
    $regional = Get-MailboxRegionalConfiguration -Identity $Identity -ErrorAction SilentlyContinue
    $language = if ($regional -and $regional.Language) { $regional.Language.Name } else { $null }
    $lcid = 0x0409
    if ($language) {
        try {
            $lcid = ([System.Globalization.CultureInfo]$language).LCID
        } catch {
            Write-Warn "$Identity reports language '$language', which is not a culture; using en-US."
        }
    }

    [pscustomobject]@{
        Identity = $Identity
        Smtp     = [string]$box.PrimarySmtpAddress
        Dn       = [string]$box.LegacyExchangeDN
        Guid     = [guid]$box.ExchangeGuid
        Endpoint = "$($script:MapiVirtualDirectory.InternalUrl)/emsmdb/?MailboxId=$($box.ExchangeGuid)@$domain"
        Language = $language
        Lcid     = $lcid
    }
}
