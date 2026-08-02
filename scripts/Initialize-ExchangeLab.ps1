<#
.SYNOPSIS
    Prepares an Exchange lab for live testing and fixture capture.

.DESCRIPTION
    Two things a lab needs before anything in this repository can talk to it, and neither is the
    default:

      * Basic authentication on the MAPI virtual directory. It is the only scheme mapi-client
        implements, and a default-configured Exchange offers Negotiate and NTLM only. Without it a
        live run fails with an HTTP 401 that lists the schemes the server does accept - which is
        the right diagnostic, but not one you want to discover twice.
      * A mailbox to read. Two, in fact: the folder names in a mailbox are localised to the
        language it was provisioned with, so a corpus captured from one locale proves nothing about
        another. `Postvak IN` is not `Inbox`, and a client that assumed otherwise would be wrong in
        a way no English-language test could catch.

    Everything here is idempotent: existing mailboxes are reported and left alone.

.PARAMETER Mailbox
    Mailboxes to create, as `alias:language` pairs. The language is an ordinary culture name and
    sets both the mailbox's regional configuration and, through it, its folder names.

.PARAMETER Password
    The password for every mailbox created. Existing mailboxes are not touched.

.PARAMETER OrganizationalUnit
    Where to create the mailboxes. Defaults to the domain's Users container.

.PARAMETER EnableBasic
    Enable Basic on the MAPI virtual directory, keeping whatever else is enabled.

.PARAMETER Seed
    Send six messages to each mailbox, so a contents table has something to page through. The list
    is the same for every mailbox, and what crates\mapi-cli\tests\replay.rs asserts about a corpus
    is asserted about a mailbox seeded from it, so changing one means re-capturing and changing
    the other.

    Seeding adds to an Inbox, it cannot reset one. Seed a mailbox this script just created, or
    clear the Inbox first; otherwise the capture describes a mailbox nothing in this repository
    can reproduce.

.EXAMPLE
    powershell.exe -File scripts\Initialize-ExchangeLab.ps1 -EnableBasic

.EXAMPLE
    powershell.exe -File scripts\Initialize-ExchangeLab.ps1 `
        -Mailbox developer:en-US,developer2:nl-NL -Password '<password>' -EnableBasic -Seed
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]] $Mailbox = @(),
    [string]   $Password,
    [string]   $OrganizationalUnit,
    [switch]   $EnableBasic,
    [switch]   $Seed
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

# See Capture-Fixtures.ps1: `powershell.exe -File` hands an array over as one comma-joined string.
# Without this the `.EXAMPLE` above binds language to `en-US,developer2:nl-NL`, and the failure
# names CultureInfo rather than the argument that was actually mangled.
$Mailbox = @($Mailbox | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } |
    Where-Object { $_ })

if (-not (Get-PSSnapin -Name 'Microsoft.Exchange.Management.PowerShell.SnapIn' -ErrorAction SilentlyContinue)) {
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
}

# ---------------------------------------------------------------------------
# The MAPI virtual directory
# ---------------------------------------------------------------------------

Write-Step 'MAPI virtual directory'

$vdir = @(Get-MapiVirtualDirectory -Server $env:COMPUTERNAME)[0]
if (-not $vdir) { throw "No MAPI virtual directory on $env:COMPUTERNAME. Is MAPI/HTTP enabled?" }

Write-Host "    InternalUrl  $($vdir.InternalUrl)"
Write-Host "    auth         $($vdir.IISAuthenticationMethods -join ', ')"

if ($vdir.IISAuthenticationMethods -contains 'Basic') {
    Write-Ok 'Basic is already enabled'
} elseif ($EnableBasic) {
    # Added to what is there rather than replacing it: taking Negotiate away would break Outlook
    # against the same lab, and this repository has no business doing that.
    $methods = @($vdir.IISAuthenticationMethods) + 'Basic'
    if ($PSCmdlet.ShouldProcess($vdir.Identity, "enable Basic alongside $($vdir.IISAuthenticationMethods -join ', ')")) {
        Set-MapiVirtualDirectory -Identity $vdir.Identity -IISAuthenticationMethods $methods
        Write-Ok "Basic enabled; restart IIS or run `iisreset` for it to take effect"
    }
} else {
    Write-Warn 'Basic is NOT enabled, and it is the only scheme mapi-client implements.'
    Write-Warn 'Re-run with -EnableBasic, or expect HTTP 401 from every live run.'
}

# ---------------------------------------------------------------------------
# Mailboxes
# ---------------------------------------------------------------------------

foreach ($specification in $Mailbox) {
    $parts = $specification -split ':', 2
    $alias = $parts[0]
    $language = if ($parts.Count -gt 1 -and $parts[1]) { $parts[1] } else { 'en-US' }

    Write-Step "Mailbox $alias ($language)"

    $existing = Get-Mailbox -Identity $alias -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Ok "already exists: $($existing.PrimarySmtpAddress)"
    } else {
        if (-not $Password) {
            throw "Creating $alias needs -Password."
        }
        $secure = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $arguments = @{
            Name              = $alias
            Alias             = $alias
            UserPrincipalName = "$alias@$((Get-AcceptedDomain | Where-Object { $_.Default }).DomainName)"
            Password          = $secure
        }
        if ($OrganizationalUnit) { $arguments['OrganizationalUnit'] = $OrganizationalUnit }

        if ($PSCmdlet.ShouldProcess($alias, 'create mailbox')) {
            $existing = New-Mailbox @arguments -ErrorAction Stop
            Write-Ok "created $($existing.PrimarySmtpAddress)"
        }
    }

    # The language is what makes the second mailbox worth having: it decides what the special
    # folders are called, and those names are what a hierarchy table returns.
    $regional = Get-MailboxRegionalConfiguration -Identity $alias -ErrorAction SilentlyContinue
    if ($regional -and $regional.Language -and $regional.Language.Name -eq $language) {
        Write-Ok "language already $language"
    } elseif ($PSCmdlet.ShouldProcess($alias, "set language to $language")) {
        Set-MailboxRegionalConfiguration -Identity $alias -Language $language -LocalizeDefaultFolderName:$true
        Write-Ok "language set to $language; folder names follow on the next logon"
    }
}

# ---------------------------------------------------------------------------
# Something to read
# ---------------------------------------------------------------------------

if ($Seed) {
    foreach ($specification in $Mailbox) {
        $alias = ($specification -split ':', 2)[0]
        $box = Get-Mailbox -Identity $alias -ErrorAction SilentlyContinue
        if (-not $box) { continue }

        Write-Step "Seeding $alias"

        # Seeding adds; it does not reset. A mailbox that already holds messages ends up with these
        # on top of whatever was there, and the corpus captured from it then matches no list in
        # this repository. Clear the Inbox first, or seed only a mailbox this script just created.
        #
        # Found by FolderType, not by path: /Inbox is what an en-US mailbox calls it and
        # /Postvak IN is what developer2 does, which is the whole point of having the second one.
        #
        # Treated as a hint, not a fact. This statistic is cached and lags the mailbox by minutes -
        # it still reported six messages in each Inbox some time after both had been emptied - so
        # it can only be trusted when it says there is something there, and not even then straight
        # after a clear. `mapi-cli messages` reads the contents table itself and always tells the
        # truth, which is what to use when the answer actually matters.
        $already = (Get-MailboxFolderStatistics -Identity $alias -FolderScope Inbox |
            Where-Object { $_.FolderType -eq 'Inbox' } |
            Select-Object -First 1).ItemsInFolder
        if ($already -gt 0) {
            Write-Warn "$alias may already hold $already message(s); seeding adds to them, it does not replace them"
            Write-Warn "  that count is cached and lags - check with ``mapi-cli messages`` before believing it"
        }

        # One subject long enough to be truncated. A table cuts a string value at 255 characters
        # and says so nowhere except in the value's own length, so a mailbox with nothing long in
        # it cannot prove that this crate notices. [MS-OXCDATA] 2.11.1
        $long = ('Long subject to force a table value length limit. ' * 8).Substring(0, 300)

        # Every mailbox gets this same list, and it is shaped by what crates\mapi-cli\tests\replay.rs
        # asserts of a corpus captured from a mailbox seeded here: six rows, exactly one of them
        # truncated, one carrying accented characters and one carrying a codepoint outside the
        # Basic Multilingual Plane.
        # Subject text has nothing to do with a mailbox's language - folder names do - so seeding
        # the two mailboxes differently would only invite a reader to wonder which differences
        # matter. The one that matters is Dutch folder names, and it comes from the language above.
        #
        # The non-ASCII is written as codepoints, never as literals. A BOM-less script read as ANSI
        # by 5.1 turns an accented letter into two mojibake characters and sends it, and a message
        # cannot be un-sent: that is how developer2 came to hold subjects that no longer match this
        # list. A pure-ASCII subject would decode the same whether or not the reader understands
        # UTF-16LE, so it proves nothing, and only a surrogate pair proves a pair is not read as
        # two characters. [MS-OXCDATA] 2.11.1
        $subjects = @(
            'First seeded message',
            "Second seeded message with accents: caf$([char]0xE9), na$([char]0xEF)ve, Zo$([char]0xEB)",
            "Third seeded message with an emoji: $([char]::ConvertFromUtf32(0x1F600))",
            'Fourth seeded message',
            $long,
            'Sixth seeded message'
        )

        foreach ($subject in $subjects) {
            if ($PSCmdlet.ShouldProcess($box.PrimarySmtpAddress, 'send a seed message')) {
                Send-MailMessage -SmtpServer 'localhost' -Port 25 `
                    -From $box.PrimarySmtpAddress -To $box.PrimarySmtpAddress `
                    -Subject $subject -Body 'Seeded for fixture capture.' `
                    -Encoding ([System.Text.Encoding]::UTF8)
            }
        }
        Write-Ok "$($subjects.Count) message(s) sent"
    }
}

Write-Host ''
Write-Ok 'Lab ready. Next: scripts\Test-Live.ps1, then scripts\Capture-Fixtures.ps1.'
exit 0
