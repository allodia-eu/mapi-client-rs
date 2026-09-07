<#
.SYNOPSIS
    Runs the ignored live tests against a real Exchange Server.

.DESCRIPTION
    CI never sees an Exchange Server, so a green CI badge means "the fake server and the committed
    fixtures still decode" and nothing more. This script is the other half: the deliberate,
    manual act of pointing the client at a real deployment.

    Everything that identifies a deployment is passed in, never committed. Supply the four values
    as parameters or as environment variables of the same names:

        MAPI_LIVE_ENDPOINT   the MailStore URL, verbatim from Autodiscover, including its
                             ?MailboxId= query parameter. Without that parameter Exchange answers
                             HTTP 400 with no X-ResponseCode at all.
        MAPI_LIVE_USER_DN    the mailbox's legacyExchangeDN, again verbatim.
        MAPI_LIVE_USERNAME   an account with rights to that mailbox.
        MAPI_LIVE_PASSWORD   its password.

    Three more are optional, and name a *second* mailbox for the send test to deliver to:

        MAPI_LIVE_SECOND_ENDPOINT, MAPI_LIVE_SECOND_USER_DN, MAPI_LIVE_SECOND_USERNAME

    That test needs them because RopSubmitMessage answers with nothing at all - the only evidence
    it did anything is in the recipient's mailbox, which the sender cannot read. Running with
    -Mailbox developer,developer2 sets them for each run in turn, so each mailbox sends to the
    other. The password is the one already given.

    Two traps worth not rediscovering:

      * Basic authentication must be enabled on the MAPI virtual directory, because that is the
        only scheme this crate implements. Check with
        `Get-MapiVirtualDirectory -Server $env:COMPUTERNAME | Select IISAuthenticationMethods`.
      * Never pass the distinguished name through Git Bash. MSYS rewrites a leading /o= into a
        Windows path, and Exchange reports the result as ecUnknownUser — which reads like a
        credential fault and is not one. This script exists partly so that nobody has to.

.PARAMETER Mailbox
    Exchange mailbox identities to run against, in turn. Everything else is then derived from the
    local Exchange snapin, so only a password is needed.

    Worth using more than one, and worth making them differ in language: a mailbox's folder names
    are localised to the language it was provisioned with, so a client that is subtly wrong about
    names passes against an English mailbox and fails against a Dutch one.

.PARAMETER Endpoint
    Overrides MAPI_LIVE_ENDPOINT.

.PARAMETER UserDn
    Overrides MAPI_LIVE_USER_DN.

.PARAMETER Username
    Overrides MAPI_LIVE_USERNAME.

.PARAMETER Password
    Overrides MAPI_LIVE_PASSWORD.

.EXAMPLE
    powershell.exe -File scripts\Test-Live.ps1

.EXAMPLE
    powershell.exe -File scripts\Test-Live.ps1 -Mailbox developer,developer2 -Password '<password>'

.EXAMPLE
    powershell.exe -File scripts\Test-Live.ps1 -Endpoint 'https://mail.example.test/mapi/emsmdb/?MailboxId=...@example.test'
#>
[CmdletBinding()]
param(
    [string[]] $Mailbox = @(),
    [string]   $Endpoint,
    [string]   $UserDn,
    [string]   $Username,
    [string]   $Password
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

# See Capture-Fixtures.ps1: `powershell.exe -File` hands an array over as one comma-joined string.
$Mailbox = @($Mailbox | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } |
    Where-Object { $_ })

if ($Endpoint) { $env:MAPI_LIVE_ENDPOINT = $Endpoint }
if ($UserDn)   { $env:MAPI_LIVE_USER_DN  = $UserDn }
if ($Username) { $env:MAPI_LIVE_USERNAME = $Username }
if ($Password) { $env:MAPI_LIVE_PASSWORD = $Password }

$cargo = Get-CargoPath

function Invoke-LiveSuite {
    <#
    .SYNOPSIS
        Runs the ignored tests once, against whatever the MAPI_LIVE_* variables currently name.
    #>
    [CmdletBinding()]
    param()

    Write-Step "Running the live tests against $(([uri]$env:MAPI_LIVE_ENDPOINT).Host)"
    Write-Host '    Nothing here runs in CI. This is the only thing that proves the protocol.' -ForegroundColor DarkGray

    Invoke-Native -FilePath $script:cargo -WorkingDirectory (Get-RepoRoot) -Arguments @(
        'test', '--package', 'mapi-client', '--test', 'live',
        '--', '--ignored', '--nocapture', '--test-threads', '1'
    )
}

# ---------------------------------------------------------------------------
# The -Mailbox path: ask Exchange for everything except the password.
# ---------------------------------------------------------------------------

if ($Mailbox.Count -gt 0) {
    if (-not $env:MAPI_LIVE_PASSWORD) {
        throw 'Running by -Mailbox still needs -Password (or MAPI_LIVE_PASSWORD).'
    }

    # The send test needs a second mailbox, because the evidence that a RopSubmitMessage did
    # anything is in the mailbox it was sent to and the sender cannot read it. Every run addresses
    # the *next* mailbox in the list, wrapping - so with two mailboxes each sends to the other, and
    # with one there is nothing to set and the send test says so by name rather than being skipped
    # silently.
    $partners = @{}
    for ($i = 0; $i -lt $Mailbox.Count; $i++) {
        if ($Mailbox.Count -gt 1) {
            $partners[$Mailbox[$i]] = $Mailbox[($i + 1) % $Mailbox.Count]
        }
    }

    foreach ($identity in $Mailbox) {
        $box = Get-LabMailbox -Identity $identity
        $language = $box.Language

        $env:MAPI_LIVE_ENDPOINT = $box.Endpoint
        $env:MAPI_LIVE_USER_DN  = $box.Dn
        $env:MAPI_LIVE_USERNAME = $box.Smtp
        $env:MAPI_LIVE_LOCALE   = '0x{0:x4}' -f $box.Lcid

        # Whom this run sends to. The same password: the lab's mailboxes share one, and a second
        # place to type a password is not an improvement.
        foreach ($name in 'MAPI_LIVE_SECOND_ENDPOINT', 'MAPI_LIVE_SECOND_USER_DN', 'MAPI_LIVE_SECOND_USERNAME') {
            Remove-Item "env:$name" -ErrorAction SilentlyContinue
        }
        if ($partners.ContainsKey($identity)) {
            $other = Get-LabMailbox -Identity $partners[$identity]
            $env:MAPI_LIVE_SECOND_ENDPOINT = $other.Endpoint
            $env:MAPI_LIVE_SECOND_USER_DN  = $other.Dn
            $env:MAPI_LIVE_SECOND_USERNAME = $other.Smtp
        }

        Write-Host ''
        Write-Host "  == $identity ($(if ($language) { $language } else { 'no language set' }))$(if ($partners.ContainsKey($identity)) { ", sending to $($partners[$identity])" }) ==" -ForegroundColor White
        Invoke-LiveSuite
    }

    Write-Host ''
    Write-Ok "The live tests passed against $($Mailbox.Count) mailbox(es): $($Mailbox -join ', ')"
    exit 0
}

$required = @(
    @{ Name = 'MAPI_LIVE_ENDPOINT'; What = 'the MailStore URL from Autodiscover, with its ?MailboxId= parameter' },
    @{ Name = 'MAPI_LIVE_USER_DN';  What = "the mailbox's legacyExchangeDN" },
    @{ Name = 'MAPI_LIVE_USERNAME'; What = 'an account with rights to that mailbox' },
    @{ Name = 'MAPI_LIVE_PASSWORD'; What = 'its password' }
)

$missing = @($required | Where-Object { -not (Get-Item "env:$($_.Name)" -ErrorAction SilentlyContinue) })
if ($missing.Count -gt 0) {
    Write-Bad 'The live tests need a server to talk to. Not set:'
    foreach ($item in $missing) {
        Write-Host ("         {0,-20} {1}" -f $item.Name, $item.What) -ForegroundColor Red
    }
    Write-Host ''
    Write-Host '    Pass them as parameters, or set them for the session:' -ForegroundColor Yellow
    Write-Host '        $env:MAPI_LIVE_ENDPOINT = ''https://...''' -ForegroundColor Yellow
    Write-Host '    See the comment-based help at the top of this script.' -ForegroundColor Yellow
    exit 1
}

# The endpoint without its MailboxId parameter is the single most common way to lose an afternoon,
# and it fails as an HTTP 400 with no X-ResponseCode, which does not name the cause.
if ($env:MAPI_LIVE_ENDPOINT -notmatch 'MailboxId=') {
    Write-Warn 'MAPI_LIVE_ENDPOINT has no MailboxId= parameter. Exchange answers such a URL with'
    Write-Warn 'an empty HTTP 400 and no X-ResponseCode header. Use the URL Autodiscover gave you.'
}

Invoke-LiveSuite

Write-Ok 'The live tests passed against a real server.'
Write-Host ''
Write-Host '  One mailbox proves one language. Folder names are localised to the language a' -ForegroundColor DarkGray
Write-Host '  mailbox was provisioned with, so run -Mailbox with two that differ.' -ForegroundColor DarkGray
exit 0
