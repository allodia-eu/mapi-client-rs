<#
.SYNOPSIS
    Keeps one logon going against a real Exchange Server for as long as it is told to.

.DESCRIPTION
    The live suite proves each thing a session does once. This proves a session lasts: cycle after
    cycle, a busy stretch of reads in one Session Context, an idle stretch kept alive by PING, and
    an idle stretch past the context's lifetime that the next request recovers from. See
    crates\mapi-client\tests\soak.rs for what each cycle asserts.

    Everything it does is a read, and it is meant to be pointed at a mailbox no other suite counts
    the contents of - by default the shared mailbox, opened with the account that has FullAccess
    to it - so that it can run beside the live suite without changing what that suite asserts.

    Before and after, it reads the server's own count of MAPI/HTTP Session Contexts, which a soak
    that leaked contexts - one per reconnect, say - would leave higher. The count is server-wide,
    so anything else running against the lab moves it too; read it as evidence, not as a proof.

    Like the live suite, nothing here runs in CI, and nothing that identifies the lab is passed in
    but the password: the mailbox's endpoint and distinguished name come from the Exchange snapin.

.PARAMETER Mailbox
    The mailbox to open. Defaults to the lab's shared mailbox.

.PARAMETER As
    The account to open it with, which needs FullAccess to it. Defaults to developer.

.PARAMETER Auth
    The scheme to authenticate with: basic (the default), ntlm or negotiate, as Test-Live takes it.

    Negotiate is the one worth a long run. Every new HTTP connection is authenticated with a Kerberos
    service ticket, and the domain's tickets last ten hours by default (MaxTicketAge and
    MaxServiceAge in the Default Domain Policy), so a run longer than that has to be seen fetching
    new ones. With Negotiate the soak refuses to go on if Kerberos is not what authenticated, and
    this script reports every TGT and service ticket the KDC issued to the account during the run
    (Security events 4768 and 4769), and how many Kerberos network logons - one per new HTTP
    connection - it made each hour (4624). The KDC is this lab's Exchange server, so the events
    are on this machine. Anything else authenticating as the same account during the run shows up
    there too.

.PARAMETER Minutes
    How long to keep going. A cycle takes about 42 minutes at the default idle times and is never
    cut short, so the run ends at the first cycle boundary past this.

.PARAMETER Password
    The account's password. Overrides MAPI_LIVE_PASSWORD.

.EXAMPLE
    powershell.exe -File scripts\Test-Soak.ps1 -Minutes 1440 -Password '<password>'

.EXAMPLE
    powershell.exe -File scripts\Test-Soak.ps1 -Auth negotiate -Minutes 720 -Password '<password>'
#>
[CmdletBinding()]
param(
    [string] $Mailbox = 'shared',
    [string] $As = 'developer',
    [ValidateSet('basic', 'ntlm', 'negotiate')]
    [string] $Auth = 'basic',
    [int]    $Minutes = 60,
    [string] $Password
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

if ($Password) { $env:MAPI_LIVE_PASSWORD = $Password }
if (-not $env:MAPI_LIVE_PASSWORD) {
    throw 'The soak needs -Password (or MAPI_LIVE_PASSWORD).'
}

$box = Get-LabMailbox -Identity $Mailbox
$account = Get-LabMailbox -Identity $As
$env:MAPI_LIVE_ENDPOINT = $box.Endpoint
$env:MAPI_LIVE_USER_DN  = $box.Dn
$env:MAPI_LIVE_USERNAME = $account.Smtp
$env:MAPI_SOAK_MINUTES  = "$Minutes"
$env:MAPI_LIVE_AUTH     = $Auth

$counter = '\MSExchange MapiHttp Emsmdb\Connection Count'
function Get-ContextCount {
    [CmdletBinding()]
    [OutputType([int])]
    param()
    [int] (Get-Counter -Counter $counter).CounterSamples[0].CookedValue
}

# The account's Kerberos trail, gathered as the run goes rather than at the end: the Security log
# rolls over, and on this lab it holds about eleven hours.
$user = ($account.Smtp -split '@')[0]
$started = Get-Date
$trail = Join-Path ([IO.Path]::GetTempPath()) "mapi-soak-kerberos-$PID.csv"
$watch = $null

# One row per event, keyed by its record id: two logons in the same second are two rows, and a row
# gathered twice - by the watcher and by the last sweep - is one.
$collect = {
    param($user, $since, $until)
    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 4768, 4769, 4624; StartTime = $since; EndTime = $until
    } -ErrorAction SilentlyContinue | Where-Object {
        if ($_.Id -eq 4624) {
            "$($_.Properties[5].Value)" -eq $user -and "$($_.Properties[10].Value)" -eq 'Kerberos'
        } else {
            "$($_.Properties[0].Value)" -like "$user*"
        }
    } | ForEach-Object {
        # Named, because inside a switch $_ is the value switched on, not the event.
        $event = $_
        $what = switch ($event.Id) {
            4768 { 'TGT' }
            4769 { "service ticket for $($event.Properties[2].Value)" }
            default { 'logon' }
        }
        '{0},{1:s},{2}' -f $event.RecordId, $event.TimeCreated, $what
    }
}

if ($Auth -eq 'negotiate') {
    $watch = Start-Job -ArgumentList $user, $started, $trail, $collect.ToString() -ScriptBlock {
        param($user, $since, $file, $collect)
        $collect = [scriptblock]::Create($collect)
        while ($true) {
            $until = Get-Date
            & $collect $user $since $until | Add-Content -Path $file
            $since = $until
            Start-Sleep -Seconds 300
        }
    }
}

function Write-KerberosTrail {
    <#
    .SYNOPSIS
        Says which tickets the KDC issued to the soak's account, and how often it logged on.

    .DESCRIPTION
        What the watcher gathered as the run went, and one last sweep over the whole run, so that
        the last minutes before the end are not lost between the watcher's passes. Either alone can
        fall short: the watcher by up to five minutes at the end, the sweep by whatever the
        Security log has rolled over since the start.
    #>
    [CmdletBinding()]
    param()
    if (-not $watch) { return }
    Start-Sleep -Seconds 5
    Stop-Job $watch
    Remove-Job $watch -Force
    $gathered = @(if (Test-Path $trail) { Get-Content $trail })
    $swept = @(& $collect $user $started (Get-Date))
    $rows = @($gathered + $swept | Where-Object { $_ } |
        Sort-Object { [long]($_ -split ',', 3)[0] } -Unique |
        ForEach-Object { ($_ -split ',', 2)[1] } | Sort-Object)
    Write-Step "Kerberos for $user since $($started.ToString('s')), from the Security log"
    foreach ($row in $rows | Where-Object { $_ -notmatch ',logon$' }) {
        Write-Host "    $($row -replace ',', '  ')"
    }
    $logons = $rows | Where-Object { $_ -match ',logon$' } |
        Group-Object { $_.Substring(0, 13) } | Sort-Object Name
    foreach ($hour in $logons) {
        Write-Host ("    {0}:00  {1} Kerberos network logons" -f $hour.Name, $hour.Count)
    }
    Remove-Item $trail -ErrorAction SilentlyContinue
}

$before = Get-ContextCount
Write-Step "Soaking $Mailbox as $As over $Auth for $Minutes minutes; $before Session Contexts on the server"

try {
    # hickory-dns, as Test-Live builds the suite, so that Negotiate finds the realm's KDCs the way a
    # caller with no resolver of its own would.
    Invoke-Native -FilePath (Get-CargoPath) -WorkingDirectory (Get-RepoRoot) -Arguments @(
        'test', '--package', 'mapi-client', '--test', 'soak', '--features', 'hickory-dns', '--',
        '--ignored', '--nocapture', '--test-threads', '1'
    )
} finally {
    Write-KerberosTrail
}

# A disconnected context is gone at once, but give the server a moment to count it.
Start-Sleep -Seconds 5
$after = Get-ContextCount
Write-Ok "The soak passed. Session Contexts on the server: $before before, $after after."
if ($after -gt $before) {
    Write-Warn 'More than before. Something else may be using the lab; if nothing is, the soak left a context behind.'
}
exit 0
