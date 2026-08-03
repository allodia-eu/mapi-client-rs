<#
.SYNOPSIS
    Puts calendar events, contacts and an attachment-bearing message into a lab mailbox.

.DESCRIPTION
    Initialize-ExchangeLab.ps1 -Seed sends mail, which is all a folder-and-table client needed.
    Reading *items* needs more than that: a calendar with real start times, a contacts folder with
    real email addresses, a body too large for a ROP response buffer, and an attachment of each of
    the two kinds that are read completely differently.

    Everything here goes in through EWS rather than MAPI, deliberately. This workspace does not
    write anything yet - that is a later phase - so the lab has to be populated by something else,
    and using the client under test to build its own fixtures would prove nothing.

    Seeding ADDS. Run it against a mailbox whose calendar and contacts folder are empty, or the
    corpus captured afterwards will not match the counts the live tests assert.

    Two things are sized rather than arbitrary:

      * The message body is deliberately larger than the 32 KiB this client reads per
        RopReadStream, so that reading it whole needs more than one round trip. A body that fitted
        in one chunk would leave the paging path with no evidence behind it.
      * One attachment is a file (PidTagAttachMethod = afByValue) and one is an embedded message
        (afEmbeddedMessage). The second has no PidTagAttachDataBinary at all, so a client that only
        ever read that property reports it as empty - which is the bug the corpus exists to catch.

.PARAMETER Mailbox
    Mailbox aliases to seed, in turn. Comma-separated: powershell.exe -File flattens an array
    argument into one string, so every script here splits on commas.

.PARAMETER Password
    The password for those mailboxes. EWS is reached with Basic authentication, as the mailbox
    owner rather than as an administrator.

.PARAMETER Server
    The host to reach EWS on. Defaults to this machine, which is where the lab Exchange runs.

.PARAMETER Domain
    The SMTP domain the mailboxes live in.

.PARAMETER Include
    Which kinds of item to create. All three by default; naming one is for re-running after a
    partial failure, where creating the others again would double them.

.EXAMPLE
    powershell.exe -File scripts\Add-LabItems.ps1 -Mailbox developer,developer2 -Password '<password>'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]] $Mailbox = @('developer'),
    [Parameter(Mandatory = $true)]
    [string]   $Password,
    [string]   $Server,
    [string]   $Domain = 'dev.local',
    [ValidateSet('Appointments', 'Contacts', 'Message')]
    [string[]] $Include = @('Appointments', 'Contacts', 'Message')
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

$Mailbox = @($Mailbox | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } |
    Where-Object { $_ })
$Include = @($Include | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } |
    Where-Object { $_ })
if (-not $Server) { $Server = $env:COMPUTERNAME }

# A lab certificate is self-signed and not in the machine's trust store. This is the same "I know
# this is a lab" decision that --insecure is for mapi-cli, and it is why this script is not for
# anything but a lab.
Add-Type -TypeDefinition @'
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class LabCertificatePolicy {
    public static void Trust() {
        ServicePointManager.ServerCertificateValidationCallback =
            delegate (object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; };
    }
}
'@ -ErrorAction SilentlyContinue
[LabCertificatePolicy]::Trust()

$ewsUrl = "https://$Server/EWS/Exchange.asmx"
$typesNamespace = 'http://schemas.microsoft.com/exchange/services/2006/types'
$messagesNamespace = 'http://schemas.microsoft.com/exchange/services/2006/messages'
$namespaces = @'
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
'@

function Invoke-Ews {
    <#
    .SYNOPSIS
        Sends one SOAP body and returns the response XML, failing loudly on a SOAP-level error.

    .DESCRIPTION
        EWS answers HTTP 200 for a request it refused, with the reason in a ResponseCode element -
        exactly the shape MAPI/HTTP uses for a refused Connect. Checking the status code alone
        would report a failed create as a success and leave the mailbox short of what the fixtures
        expect.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Body,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential] $Credential
    )

    $envelope = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope $namespaces>
  <soap:Header><t:RequestServerVersion Version="Exchange2013" /></soap:Header>
  <soap:Body>
$Body
  </soap:Body>
</soap:Envelope>
"@

    $response = Invoke-WebRequest -Uri $script:ewsUrl -Method Post -ContentType 'text/xml; charset=utf-8' `
        -Body ([System.Text.Encoding]::UTF8.GetBytes($envelope)) -Credential $Credential -UseBasicParsing

    [xml] $xml = $response.Content

    # By local name AND namespace. GetElementsByTagName('ResponseCode') matches the *qualified*
    # name, so against a response whose prefix is m: it silently matches nothing - and a check that
    # silently matches nothing is a check that always passes.
    $codes = @($xml.GetElementsByTagName('ResponseCode', $script:messagesNamespace) |
        ForEach-Object { $_.'#text' })
    if ($codes.Count -eq 0) {
        throw 'The EWS response carried no ResponseCode at all, which no successful call does.'
    }
    $bad = @($codes | Where-Object { $_ -ne 'NoError' })
    if ($bad.Count -gt 0) {
        throw "EWS refused the request: $($bad -join ', ')"
    }
    return $xml
}

function Get-ItemId {
    <#
    .SYNOPSIS
        The ItemId of the first item a CreateItem response reports.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][xml] $Response)

    $node = @($Response.GetElementsByTagName('ItemId', $script:typesNamespace))[0]
    if (-not $node) { throw 'The CreateItem response carried no ItemId.' }
    return @{ Id = $node.Id; ChangeKey = $node.ChangeKey }
}

# ---------------------------------------------------------------------------
# The items themselves
# ---------------------------------------------------------------------------

# Fixed dates, never Get-Date. A capture taken from a mailbox seeded with "today" would differ from
# every later capture, and Verify-Fixtures.ps1 would report a change on every run.
$appointments = @(
    @{ Subject = 'Quarterly design review'; Start = '2026-09-01T09:00:00Z'; End = '2026-09-01T10:00:00Z'; Location = 'Room 1'; Busy = 'Busy' },
    @{ Subject = 'Fixture capture window'; Start = '2026-09-02T13:30:00Z'; End = '2026-09-02T14:00:00Z'; Location = 'Room 2'; Busy = 'Tentative' },
    @{ Subject = 'All-day inventory'; Start = '2026-09-03T00:00:00Z'; End = '2026-09-04T00:00:00Z'; Location = 'Off site'; Busy = 'Free' }
)

$contacts = @(
    @{ Given = 'Ada'; Surname = 'Lovelace'; Company = 'Analytical Engines'; Phone = '+44 20 7946 0001'; Email = 'ada@example.test' },
    @{ Given = 'Grace'; Surname = 'Hopper'; Company = 'Compilers Inc'; Phone = '+1 202 555 0002'; Email = 'grace@example.test' },
    @{ Given = 'Edsger'; Surname = 'Dijkstra'; Company = 'Shortest Paths BV'; Phone = '+31 20 555 0003'; Email = 'edsger@example.test' }
)

function New-LargeBody {
    <#
    .SYNOPSIS
        An HTML body comfortably past the 32 KiB this client reads per RopReadStream.

    .DESCRIPTION
        Built from a fixed string repeated a fixed number of times, so the same seeding run twice
        produces the same bytes. Every line is numbered, which means a truncated read is visible as
        a missing line number rather than as text that merely looks short.
    #>
    [CmdletBinding()]
    param([int] $Lines = 900)

    $builder = New-Object System.Text.StringBuilder
    [void] $builder.Append('<html><body>')
    for ($i = 1; $i -le $Lines; $i++) {
        [void] $builder.Append(("<p>Line {0:D4} of a body deliberately larger than one stream read.</p>" -f $i))
    }
    [void] $builder.Append('</body></html>')
    return $builder.ToString()
}

function Add-Appointments {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory = $true)][System.Management.Automation.PSCredential] $Credential)

    foreach ($item in $script:appointments) {
        $body = @"
    <m:CreateItem SendMeetingInvitations="SendToNone">
      <m:SavedItemFolderId><t:DistinguishedFolderId Id="calendar" /></m:SavedItemFolderId>
      <m:Items>
        <t:CalendarItem>
          <t:Subject>$($item.Subject)</t:Subject>
          <t:Body BodyType="Text">Seeded by scripts\Add-LabItems.ps1.</t:Body>
          <t:Start>$($item.Start)</t:Start>
          <t:End>$($item.End)</t:End>
          <t:Location>$($item.Location)</t:Location>
          <t:LegacyFreeBusyStatus>$($item.Busy)</t:LegacyFreeBusyStatus>
        </t:CalendarItem>
      </m:Items>
    </m:CreateItem>
"@
        if ($PSCmdlet.ShouldProcess($item.Subject, 'create a calendar item')) {
            [void] (Invoke-Ews -Body $body -Credential $Credential)
        }
    }

    # One recurring series, so that PidLidRecurring and PidLidAppointmentRecur have something to
    # report. This client reads the pattern and deliberately does not expand it into occurrences.
    $body = @"
    <m:CreateItem SendMeetingInvitations="SendToNone">
      <m:SavedItemFolderId><t:DistinguishedFolderId Id="calendar" /></m:SavedItemFolderId>
      <m:Items>
        <t:CalendarItem>
          <t:Subject>Daily standup (recurring)</t:Subject>
          <t:Body BodyType="Text">Seeded by scripts\Add-LabItems.ps1.</t:Body>
          <t:Start>2026-09-07T08:00:00Z</t:Start>
          <t:End>2026-09-07T08:15:00Z</t:End>
          <t:Location>Room 3</t:Location>
          <t:LegacyFreeBusyStatus>Busy</t:LegacyFreeBusyStatus>
          <t:Recurrence>
            <t:DailyRecurrence><t:Interval>1</t:Interval></t:DailyRecurrence>
            <t:NumberedRecurrence>
              <t:StartDate>2026-09-07</t:StartDate>
              <t:NumberOfOccurrences>5</t:NumberOfOccurrences>
            </t:NumberedRecurrence>
          </t:Recurrence>
        </t:CalendarItem>
      </m:Items>
    </m:CreateItem>
"@
    if ($PSCmdlet.ShouldProcess('Daily standup (recurring)', 'create a recurring calendar item')) {
        [void] (Invoke-Ews -Body $body -Credential $Credential)
    }
    Write-Ok "$($script:appointments.Count + 1) calendar item(s) created"
}

function Add-Contacts {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory = $true)][System.Management.Automation.PSCredential] $Credential)

    foreach ($item in $script:contacts) {
        $body = @"
    <m:CreateItem>
      <m:SavedItemFolderId><t:DistinguishedFolderId Id="contacts" /></m:SavedItemFolderId>
      <m:Items>
        <t:Contact>
          <t:DisplayName>$($item.Given) $($item.Surname)</t:DisplayName>
          <t:GivenName>$($item.Given)</t:GivenName>
          <t:CompanyName>$($item.Company)</t:CompanyName>
          <t:EmailAddresses>
            <t:Entry Key="EmailAddress1">$($item.Email)</t:Entry>
          </t:EmailAddresses>
          <t:PhoneNumbers>
            <t:Entry Key="BusinessPhone">$($item.Phone)</t:Entry>
          </t:PhoneNumbers>
          <t:Surname>$($item.Surname)</t:Surname>
        </t:Contact>
      </m:Items>
    </m:CreateItem>
"@
        if ($PSCmdlet.ShouldProcess("$($item.Given) $($item.Surname)", 'create a contact')) {
            [void] (Invoke-Ews -Body $body -Credential $Credential)
        }
    }
    Write-Ok "$($script:contacts.Count) contact(s) created"
}

function Add-AttachedMessage {
    <#
    .SYNOPSIS
        One Inbox message with a large body, a file attachment and an embedded-message attachment.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory = $true)][System.Management.Automation.PSCredential] $Credential)

    $html = New-LargeBody
    $escaped = [System.Security.SecurityElement]::Escape($html)
    $body = @"
    <m:CreateItem MessageDisposition="SaveOnly">
      <m:SavedItemFolderId><t:DistinguishedFolderId Id="inbox" /></m:SavedItemFolderId>
      <m:Items>
        <t:Message>
          <t:Subject>Seeded message with a large body and two attachments</t:Subject>
          <t:Body BodyType="HTML">$escaped</t:Body>
        </t:Message>
      </m:Items>
    </m:CreateItem>
"@
    if (-not $PSCmdlet.ShouldProcess('the attachment-bearing message', 'create it')) { return }

    $created = Get-ItemId -Response (Invoke-Ews -Body $body -Credential $Credential)

    # A file attachment, whose PidTagAttachMethod is afByValue and whose bytes are in
    # PidTagAttachDataBinary.
    $content = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(
        "attachment seeded by scripts\Add-LabItems.ps1`r`n" * 40))
    $body = @"
    <m:CreateAttachment>
      <m:ParentItemId Id="$($created.Id)" ChangeKey="$($created.ChangeKey)" />
      <m:Attachments>
        <t:FileAttachment>
          <t:Name>notes.txt</t:Name>
          <t:ContentType>text/plain</t:ContentType>
          <t:Content>$content</t:Content>
        </t:FileAttachment>
      </m:Attachments>
    </m:CreateAttachment>
"@
    [void] (Invoke-Ews -Body $body -Credential $Credential)

    # An item attachment, whose PidTagAttachMethod is afEmbeddedMessage. It has no
    # PidTagAttachDataBinary at all - RopOpenEmbeddedMessage is the only way in.
    $body = @"
    <m:CreateAttachment>
      <m:ParentItemId Id="$($created.Id)" ChangeKey="$($created.ChangeKey)" />
      <m:Attachments>
        <t:ItemAttachment>
          <t:Name>forwarded.msg</t:Name>
          <t:Message>
            <t:Subject>The message inside the attachment</t:Subject>
            <t:Body BodyType="Text">This one is reached with RopOpenEmbeddedMessage and by nothing else.</t:Body>
          </t:Message>
        </t:ItemAttachment>
      </m:Attachments>
    </m:CreateAttachment>
"@
    [void] (Invoke-Ews -Body $body -Credential $Credential)

    Write-Ok "1 message created, with a $([Math]::Round($html.Length / 1KB)) KB body and 2 attachments"
}

# ---------------------------------------------------------------------------

foreach ($alias in $Mailbox) {
    Write-Step "Seeding items into $alias"

    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential("$alias@$Domain", $secure)

    if ($Include -contains 'Appointments') { Add-Appointments -Credential $credential }
    if ($Include -contains 'Contacts') { Add-Contacts -Credential $credential }
    if ($Include -contains 'Message') { Add-AttachedMessage -Credential $credential }
}

Write-Host ''
Write-Ok 'Lab items created. Next: mapi-cli events, mapi-cli contacts, mapi-cli message --body.'
exit 0
