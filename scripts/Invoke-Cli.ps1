<#
.SYNOPSIS
    Runs one mapi-cli command against a lab mailbox, with everything but the password derived from
    Exchange.

.DESCRIPTION
    Test-Live.ps1 and Capture-Fixtures.ps1 cover the two scripted things one does to the lab: prove
    the client still works, and refresh the corpus. Most of the time actually spent against a live
    server is neither. It is asking one question, reading the answer, and asking a better one -
    which is how every measurement recorded in this repository's doc comments was made, and which
    needs nothing but the five MAPI_LIVE_* variables set for one mailbox.

    Setting them by hand is where this used to go wrong, in two ways this script exists to remove:

      * The endpoint has to carry ?MailboxId=<ExchangeGuid>@<domain>. Without it Exchange answers
        HTTP 400 with no X-ResponseCode header at all, which reads like the URL being wrong rather
        than incomplete.
      * A legacyExchangeDN must never be typed into Git Bash. MSYS rewrites the leading /o= into
        C:/Program Files/Git/o=..., and Exchange reports the result as ecUnknownUser - which reads
        like a credential or a server fault and sends you debugging the wrong thing entirely.

    Both are avoided by never handling either value: this asks the Exchange snapin and passes the
    answers to the child process in its own environment, so nothing about the deployment reaches a
    shell history.

    The variables are set for this process only. Nothing leaks into the caller's session, and
    running two mailboxes in turn cannot mix them up.

.PARAMETER Mailbox
    The mailbox to run as. Omit it to use whatever MAPI_LIVE_* variables are already set, which is
    the path for a lab this machine cannot ask Exchange about.

.PARAMETER Password
    Its password. Defaults to MAPI_LIVE_PASSWORD.

.PARAMETER Arguments
    Everything after the parameters above, passed to mapi-cli verbatim.

.EXAMPLE
    powershell.exe -File scripts\Invoke-Cli.ps1 -Mailbox developer messages --folder inbox

.EXAMPLE
    powershell.exe -File scripts\Invoke-Cli.ps1 -Mailbox developer2 state --folder drafts --id 0x...

    Reads back what mark and flag did. These operations answer with one byte or with nothing at
    all, so reading the item back is the only way to know they did what they said - which is how
    three of the four deviations recorded against Exchange in this repository were found.

.EXAMPLE
    powershell.exe -File scripts\Invoke-Cli.ps1 -Mailbox developer --dump ping

    mapi-cli's own flags go through unchanged; --dump hex-dumps every request and response.
#>
# PositionalBinding is off deliberately. With it on, `Invoke-Cli.ps1 ping` binds `ping` to -Mailbox
# and leaves nothing to run, which is a confusing way to fail: the error says there is no subcommand
# while the subcommand is right there on the line. Off, every mapi-cli argument reaches $Arguments
# and -Mailbox has to be named.
[CmdletBinding(PositionalBinding = $false)]
param(
    [string] $Mailbox,
    [string] $Password = $env:MAPI_LIVE_PASSWORD,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Arguments = @()
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

if ($Arguments.Count -eq 0) {
    throw ('Nothing to run. Give mapi-cli a subcommand: ' +
           'scripts\Invoke-Cli.ps1 -Mailbox developer messages --folder inbox')
}

# ---------------------------------------------------------------------------
# Where to point it
# ---------------------------------------------------------------------------

if ($Mailbox) {
    if (-not $Password) {
        throw 'Running by -Mailbox still needs -Password (or MAPI_LIVE_PASSWORD).'
    }

    $box = Get-LabMailbox -Identity $Mailbox
    $env:MAPI_LIVE_ENDPOINT = $box.Endpoint
    $env:MAPI_LIVE_USER_DN  = $box.Dn
    $env:MAPI_LIVE_USERNAME = $box.Smtp
    $env:MAPI_LIVE_PASSWORD = $Password
    $env:MAPI_LIVE_LOCALE   = '0x{0:x4}' -f $box.Lcid

    $language = if ($box.Language) { $box.Language } else { 'no language set' }
    Write-Step "mapi-cli $($Arguments -join ' ')  as $($box.Smtp) ($language)"
} else {
    $missing = @('MAPI_LIVE_ENDPOINT', 'MAPI_LIVE_USER_DN', 'MAPI_LIVE_USERNAME',
                 'MAPI_LIVE_PASSWORD') |
        Where-Object { -not (Get-Item "env:$_" -ErrorAction SilentlyContinue) }
    if ($missing) {
        throw ("No -Mailbox, and $($missing -join ', ') " +
               'not set. Pass -Mailbox to have this ask Exchange for them.')
    }
    Write-Step "mapi-cli $($Arguments -join ' ')  as $env:MAPI_LIVE_USERNAME"
}

# ---------------------------------------------------------------------------
# Run it
# ---------------------------------------------------------------------------

# Not Invoke-Native: that throws on a non-zero exit, and a mapi-cli command failing is frequently
# the answer rather than the problem. A refusal from the server is a measurement.
$cargo = Get-CargoPath
& $cargo @('run', '--quiet', '--package', 'mapi-cli', '--') @Arguments
$code = $LASTEXITCODE

foreach ($name in 'MAPI_LIVE_ENDPOINT', 'MAPI_LIVE_USER_DN', 'MAPI_LIVE_USERNAME',
                  'MAPI_LIVE_PASSWORD', 'MAPI_LIVE_LOCALE') {
    Remove-Item "env:$name" -ErrorAction SilentlyContinue
}

if ($code -ne 0) {
    Write-Warn "mapi-cli exited with code $code"
}
exit $code
