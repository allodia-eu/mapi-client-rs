<#
.SYNOPSIS
    Captures the fixture corpus from the live Exchange lab, redacted and ready to commit.

.DESCRIPTION
    CI never sees an Exchange server, so the committed captures under fixtures\ are the only thing
    standing between CI and a false green. This script is how they are produced.

    What it does, per mailbox:

      1. Asks Exchange for the mailbox's LegacyExchangeDN and ExchangeGuid, and the MAPI virtual
         directory's InternalUrl. Nothing about the deployment is typed or hard-coded.
      2. Derives a scrub rules file from those answers - the host name, the mailbox GUIDs in both
         their text and their 16-byte binary forms, the per-mailbox blob inside each distinguished
         name, and the Exchange organisation name. Every replacement is the same length as what it
         replaces, because fixtures are read by byte offset.
      3. Runs `mapi-cli capture`, which drives an ordinary client through a whole Session Context
         and writes each exchange as request/response/meta.
      4. Rebuilds fixtures\MANIFEST.toml with the server version, the capture date and a SHA-256
         per file, so drift is detectable rather than assumed absent.
      5. Runs Assert-NoSecrets.ps1 over the result. mapi-cli already refuses to write a file that
         still carries a needle; this is the independent second opinion, because a rule that
         matched nothing looks exactly like a rule that worked.

    The rules file is written to the user's TEMP directory, never into the repository: it contains
    exactly the values that must not be committed.

.PARAMETER Mailbox
    Exchange mailbox identities to capture, one scenario directory each. The directory is named
    after the mailbox's configured language, so `developer` (en-US) becomes `session-en-us`.

.PARAMETER Password
    The password for every mailbox named in -Mailbox. Defaults to MAPI_LIVE_PASSWORD.

.PARAMETER HostName
    The host name to redact. Defaults to this machine's, which is what the lab runs on.

.PARAMETER Root
    The fixtures directory. Defaults to fixtures\ in the repository.

.PARAMETER Set
    The fixture set, which names the server family these came from.

.PARAMETER SkipRefused
    Do not capture the refused-Connect scenario.

.PARAMETER KeepRaw
    Also write the unredacted originals to a gitignored raw\ directory, for debugging a scrub.

.EXAMPLE
    powershell.exe -File scripts\Capture-Fixtures.ps1 -Mailbox developer,developer2

.EXAMPLE
    powershell.exe -File scripts\Capture-Fixtures.ps1 -Mailbox developer -KeepRaw
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]] $Mailbox,
    [string]   $Password = $env:MAPI_LIVE_PASSWORD,
    [string]   $HostName = $env:COMPUTERNAME,
    [string]   $Root,
    [string]   $Set = 'exchange-se',
    [switch]   $SkipRefused,
    [switch]   $KeepRaw
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

$repoRoot = Get-RepoRoot
if (-not $Root) { $Root = Join-Path $repoRoot 'fixtures' }

# `powershell.exe -File` passes every argument as a plain string, so the documented
# `-Mailbox developer,developer2` arrives as the single element "developer,developer2" rather than
# as two. Splitting here makes the documented form work and costs nothing for the -Command form,
# which really does bind an array. The same trap is handled in Invoke-Gate.ps1.
$Mailbox = @($Mailbox | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } |
    Where-Object { $_ })

if (-not $Password) {
    throw ('No password. Pass -Password or set MAPI_LIVE_PASSWORD. Every mailbox named in ' +
           '-Mailbox is authenticated with it.')
}

# ---------------------------------------------------------------------------
# Placeholders
# ---------------------------------------------------------------------------

function New-Placeholder {
    <#
    .SYNOPSIS
        A replacement that is exactly as long as what it replaces.

    .DESCRIPTION
        The one rule a scrub may never break. mapi-cli refuses a rule whose two sides differ in
        length, so this pads or trims here rather than letting the capture fail later with a
        message about a file the operator never wrote.

        Padding is visible on purpose: `exchange-lab-01xx` reads as "this was padded", where a
        silent trim would read as a real name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string] $Value,
        [Parameter(Mandatory)][string] $Preferred,
        [char] $Fill = 'x'
    )

    if ($Preferred.Length -eq $Value.Length) { return $Preferred }
    if ($Preferred.Length -gt $Value.Length) {
        Write-Warn "placeholder '$Preferred' trimmed to $($Value.Length) characters"
        return $Preferred.Substring(0, $Value.Length)
    }
    return $Preferred + ([string]$Fill * ($Value.Length - $Preferred.Length))
}

function New-ZeroGuid {
    <#
    .SYNOPSIS
        A zero GUID whose last digit distinguishes one mailbox from another.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][int] $Index)

    return ('00000000-0000-0000-0000-0000000000{0:d2}' -f $Index)
}

function ConvertTo-HexString {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][byte[]] $Bytes)

    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

# ---------------------------------------------------------------------------
# What Exchange says about each mailbox
# ---------------------------------------------------------------------------

Write-Step 'Reading the deployment from Exchange'

if (-not (Get-PSSnapin -Name 'Microsoft.Exchange.Management.PowerShell.SnapIn' -ErrorAction SilentlyContinue)) {
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
}

$vdir = @(Get-MapiVirtualDirectory -Server $env:COMPUTERNAME)[0]
if (-not $vdir) { throw "No MAPI virtual directory on $env:COMPUTERNAME. Is MAPI/HTTP enabled?" }
if ($vdir.IISAuthenticationMethods -notcontains 'Basic') {
    throw ('Basic is not enabled on the MAPI virtual directory, and it is the only scheme ' +
           'mapi-client implements. Run scripts\Initialize-ExchangeLab.ps1 -EnableBasic.')
}

$serverVersion = (Get-ExchangeServer -Identity $env:COMPUTERNAME).AdminDisplayVersion.ToString()
Write-Host "    MAPI vdir  $($vdir.InternalUrl)"
Write-Host "    server     $serverVersion"

$targets = New-Object System.Collections.Generic.List[psobject]
$index = 0

foreach ($identity in $Mailbox) {
    $index++
    $box = Get-Mailbox -Identity $identity
    $regional = Get-MailboxRegionalConfiguration -Identity $identity

    $domain = ([string]$box.PrimarySmtpAddress -split '@')[-1]
    $language = if ($regional.Language) { $regional.Language.Name } else { 'en-US' }
    $lcid = ([System.Globalization.CultureInfo]$language).LCID

    # The per-mailbox blob inside a legacyExchangeDN: `cn=<32 hex>-<display name>`.
    $blob = [regex]::Match([string]$box.LegacyExchangeDN, 'cn=([0-9a-fA-F]{32})-')

    $targets.Add([pscustomobject]@{
        Index     = $index
        Identity  = $identity
        Smtp      = [string]$box.PrimarySmtpAddress
        Dn        = [string]$box.LegacyExchangeDN
        Guid      = [guid]$box.ExchangeGuid
        Blob      = if ($blob.Success) { $blob.Groups[1].Value } else { $null }
        Language  = $language
        Lcid      = $lcid
        Endpoint  = "$($vdir.InternalUrl)/emsmdb/?MailboxId=$($box.ExchangeGuid)@$domain"
        Scenario  = "session-$($language.ToLowerInvariant())"
        Items     = "items-$($language.ToLowerInvariant())"
        Writes    = "writes-$($language.ToLowerInvariant())"
    })

    Write-Host "    $identity  $language (LCID 0x$('{0:x4}' -f $lcid))  ->  session-$($language.ToLowerInvariant())"
}

# The Exchange organisation, taken from any distinguished name: `/o=<org>/`.
$organisation = [regex]::Match($targets[0].Dn, '^/o=([^/]+)/').Groups[1].Value

# ---------------------------------------------------------------------------
# The scrub rules
# ---------------------------------------------------------------------------

Write-Step 'Deriving the scrub rules'

$rules = New-Object System.Collections.Generic.List[string]
$rules.Add('# Generated by Capture-Fixtures.ps1. Never commit this file: it is a list of exactly')
$rules.Add('# the values that must not be committed. Fields are tab separated.')
$rules.Add('')

$hostShort = ($HostName -split '\.')[0]
$hostPlaceholder = New-Placeholder -Value $hostShort -Preferred 'exchange-lab-01'
$rules.Add("text`t$hostShort`t$hostPlaceholder")

# The DNS suffix, separately from the host label. Exchange embeds the fully qualified name in
# diagnostic strings inside the Connect response body - `ClientAccessServer=<fqdn>,ConnectTime=...`
# - and again in the X-CalculatedBETarget header, so a rule that only replaced the label would
# leave the deployment's domain in the corpus. A capture should name nothing real, and half a name
# is still a name.
$domains = @($targets.Smtp | ForEach-Object { ($_ -split '@')[-1] } | Select-Object -Unique)
foreach ($domain in $domains) {
    $rules.Add("text`t$domain`t$(New-Placeholder -Value $domain -Preferred 'lab.local')")
}

if ($organisation) {
    $orgPlaceholder = New-Placeholder -Value $organisation -Preferred 'Lab'
    $rules.Add("text`t/o=$organisation/`t/o=$orgPlaceholder/")
}

foreach ($target in $targets) {
    $guidText = $target.Guid.ToString()
    $rules.Add("text`t$guidText`t$(New-ZeroGuid -Index $target.Index)")

    # The same GUID again, as the sixteen raw bytes a RopLogon response carries. Text rules cannot
    # see those: MailboxGuid is binary, not a string. [MS-OXCSTOR] 2.2.1.1.3
    $guidBytes = ConvertTo-HexString -Bytes $target.Guid.ToByteArray()
    $zeroBytes = ConvertTo-HexString -Bytes ([guid](New-ZeroGuid -Index $target.Index)).ToByteArray()
    $rules.Add("bytes`t$guidBytes`t$zeroBytes")

    if ($target.Blob) {
        $blobPlaceholder = ('0' * ($target.Blob.Length - 2)) + ('{0:d2}' -f $target.Index)
        $rules.Add("text`t$($target.Blob)`t$blobPlaceholder")
    }
}

$rulesPath = Join-Path $env:TEMP "mapi-scrub-$PID.tsv"
# ASCII deliberately: every needle here is ASCII, and a BOM would become part of the first rule.
Set-Content -LiteralPath $rulesPath -Value $rules -Encoding Ascii
Write-Ok "$($rules.Count - 3) rule(s) written to $rulesPath"

# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

$cargo = Get-CargoPath
$captured = New-Object System.Collections.Generic.List[string]

function Invoke-Capture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Scenario,
        [Parameter(Mandatory)][string]   $Name,
        [Parameter(Mandatory)][hashtable] $Environment,
        [string[]] $Extra = @()
    )

    foreach ($key in $Environment.Keys) { Set-Item "env:$key" $Environment[$key] }

    $arguments = @(
        'run', '--quiet', '--package', 'mapi-cli', '--',
        'capture', $Scenario,
        '--root', $Root,
        '--set', $Set,
        '--name', $Name,
        '--scrub', $rulesPath
    )
    if ($KeepRaw) { $arguments += '--raw' }
    $arguments += $Extra

    Invoke-Native -FilePath $cargo -WorkingDirectory $repoRoot -Arguments $arguments
    $script:captured.Add($Name)
}

try {
    foreach ($target in $targets) {
        $environment = @{
            MAPI_LIVE_ENDPOINT = $target.Endpoint
            MAPI_LIVE_USER_DN  = $target.Dn
            MAPI_LIVE_USERNAME = $target.Smtp
            MAPI_LIVE_PASSWORD = $Password
            MAPI_LIVE_LOCALE   = "0x$('{0:x4}' -f $target.Lcid)"
        }

        Write-Step "Capturing $($target.Scenario) from $($target.Identity)"
        Invoke-Capture -Scenario 'session' -Name $target.Scenario -Environment $environment

        # The items scenario needs a mailbox seeded by Add-LabItems.ps1: a calendar with events in
        # it, a contacts folder with email addresses, and one message with a large body and one
        # attachment of each kind. It refuses to write a capture that would carry an empty calendar
        # or a body small enough to fit a single read, so a mailbox that has not been seeded fails
        # here by name rather than producing a corpus that proves nothing.
        Write-Step "Capturing $($target.Items) from $($target.Identity)"
        Invoke-Capture -Scenario 'items' -Name $target.Items -Environment $environment

        # The one scenario that writes. It creates a draft, reads it back and deletes it, so the
        # mailbox ends as it started - and it declares the message id the server minted, so the
        # capture zeroes it and a re-capture of an unchanged server produces the same bytes. If it
        # fails part way it says so and names the draft it left behind.
        Write-Step "Capturing $($target.Writes) from $($target.Identity)"
        Invoke-Capture -Scenario 'writes' -Name $target.Writes -Environment $environment
    }

    if (-not $SkipRefused) {
        # A distinguished name in the right shape for a mailbox that does not exist. The refusal is
        # what a client sees for a mailbox it cannot map, and it arrives as HTTP 200 with
        # X-ResponseCode 0 and a non-zero ErrorCode in the body - a shape no HTTP-level check would
        # ever catch, which is why it belongs in the corpus.
        $first = $targets[0]
        $unknown = $first.Dn -replace 'cn=[0-9a-fA-F]{32}-.*$', 'cn=00000000000000000000000000000000-No Such User'

        Write-Step 'Capturing connect-refused'
        Invoke-Capture -Scenario 'connect-refused' -Name 'connect-refused' -Extra @(
            '--user-dn-override', $unknown
        ) -Environment @{
            MAPI_LIVE_ENDPOINT = $first.Endpoint
            MAPI_LIVE_USER_DN  = $first.Dn
            MAPI_LIVE_USERNAME = $first.Smtp
            MAPI_LIVE_PASSWORD = $Password
            MAPI_LIVE_LOCALE   = "0x$('{0:x4}' -f $first.Lcid)"
        }
    }
} finally {
    Remove-Item -LiteralPath $rulesPath -Force -ErrorAction SilentlyContinue
    foreach ($name in 'MAPI_LIVE_ENDPOINT', 'MAPI_LIVE_USER_DN', 'MAPI_LIVE_USERNAME',
                      'MAPI_LIVE_PASSWORD', 'MAPI_LIVE_LOCALE') {
        Remove-Item "env:$name" -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------

Write-Step 'Rebuilding MANIFEST.toml'

# The version the *server itself* put in X-ServerApplication, taken from a capture rather than from
# Get-ExchangeServer. The two disagree - the cmdlet says `Version 15.2 (Build 2562.17)` where the
# header says `Exchange/15.02.2562.045` - and this repository standardised on the header, because
# that is the value a client can see and therefore the one a version-tied claim can be checked
# against. [MS-OXCMAPIHTTP] 2.2.3.3.7
$anyMeta = @(Get-ChildItem -Path $Root -Filter '*.meta.txt' -Recurse -File)[0]
if ($anyMeta) {
    $reported = [regex]::Match(
        (Get-Content -LiteralPath $anyMeta.FullName -Raw),
        '(?im)^x-serverapplication:\s*(\S+)'
    )
    if ($reported.Success) { $serverVersion = $reported.Groups[1].Value }
}

& "$PSScriptRoot\Write-FixtureManifest.ps1" -Root $Root -ServerVersion $serverVersion
if ($LASTEXITCODE -ne 0) { throw 'Writing MANIFEST.toml failed.' }

# ---------------------------------------------------------------------------
# The independent check
# ---------------------------------------------------------------------------

Write-Step 'Checking the result for anything that identifies the lab'
& "$PSScriptRoot\Assert-NoSecrets.ps1" -Root $Root -Forbidden @(
    $hostShort
    $targets.Guid.ToString()
    $targets.Blob | Where-Object { $_ }
)
if ($LASTEXITCODE -ne 0) {
    throw ('Assert-NoSecrets.ps1 found something. Do NOT commit fixtures\. Widen the rules in ' +
           'this script and capture again.')
}

Write-Ok "$($captured.Count) scenario(s) captured: $($captured -join ', ')"
Write-Host ''
Write-Host '  Review the diff before committing. A fixture is a claim about what a server sent.' -ForegroundColor DarkGray
exit 0
