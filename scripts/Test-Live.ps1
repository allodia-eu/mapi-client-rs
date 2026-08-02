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

    Two traps worth not rediscovering:

      * Basic authentication must be enabled on the MAPI virtual directory, because that is the
        only scheme this crate implements. Check with
        `Get-MapiVirtualDirectory -Server $env:COMPUTERNAME | Select IISAuthenticationMethods`.
      * Never pass the distinguished name through Git Bash. MSYS rewrites a leading /o= into a
        Windows path, and Exchange reports the result as ecUnknownUser — which reads like a
        credential fault and is not one. This script exists partly so that nobody has to.

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
    powershell.exe -File scripts\Test-Live.ps1 -Endpoint 'https://mail.example.test/mapi/emsmdb/?MailboxId=...@example.test'
#>
[CmdletBinding()]
param(
    [string] $Endpoint,
    [string] $UserDn,
    [string] $Username,
    [string] $Password
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

if ($Endpoint) { $env:MAPI_LIVE_ENDPOINT = $Endpoint }
if ($UserDn)   { $env:MAPI_LIVE_USER_DN  = $UserDn }
if ($Username) { $env:MAPI_LIVE_USERNAME = $Username }
if ($Password) { $env:MAPI_LIVE_PASSWORD = $Password }

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

Write-Step "Running the live tests against $(([uri]$env:MAPI_LIVE_ENDPOINT).Host)"
Write-Host '    Nothing here runs in CI. This is the only thing that proves the protocol.' -ForegroundColor DarkGray

$cargo = Get-CargoPath
Invoke-Native -FilePath $cargo -WorkingDirectory (Get-RepoRoot) -Arguments @(
    'test', '--package', 'mapi-client', '--test', 'live',
    '--', '--ignored', '--nocapture', '--test-threads', '1'
)

Write-Ok 'The live tests passed against a real server.'
exit 0
