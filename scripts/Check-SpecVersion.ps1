<#
.SYNOPSIS
    Verifies that every downloaded specification PDF is the version SPEC.md pins.

.DESCRIPTION
    This is the tripwire for "Microsoft revised the protocol". Every page of an Open Specification
    document carries a header stamp of the form

        [MS-OXCROPS] - v20250520

    so this script runs poppler's pdftotext over the first pages of each local PDF, reads the
    stamp, and fails on any mismatch with the table in SPEC.md. A version bump therefore forces a
    deliberate review — read the document's own revision summary — rather than silent drift.

    Anchoring the regex on the document name rather than on a bare v-number is deliberate: it also
    catches a PDF saved under the wrong filename, which a bare version match would wave through.

    Pairs with Verify-Fixtures.ps1, which catches the same class of drift from the server side.

.PARAMETER Quiet
    Only report failures.

.EXAMPLE
    powershell.exe -File scripts\Check-SpecVersion.ps1
#>
[CmdletBinding()]
param(
    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

$docs      = Get-SpecManifest
$pdftotext = Resolve-PdfToText
$failures  = New-Object System.Collections.Generic.List[string]
$missing   = New-Object System.Collections.Generic.List[string]

if (-not $Quiet) { Write-Step "Verifying $($docs.Count) specification versions against SPEC.md" }

foreach ($doc in $docs) {
    if (-not (Test-Path -LiteralPath $doc.PdfPath)) {
        $missing.Add($doc.Name)
        continue
    }

    # The stamp repeats on every page, so two pages is plenty and keeps this near-instant even
    # though MS-OXCROPS is 236 pages. Extracting from the PDF rather than trusting the committed
    # .txt is the point: a stale extract must not be able to mask a changed document.
    $extract = Get-NativeOutput -FilePath $pdftotext `
        -Arguments @('-f', '1', '-l', '2', '-layout', $doc.PdfPath, '-')
    if ($extract.ExitCode -ne 0) {
        $failures.Add("$($doc.Name): pdftotext failed with exit code $($extract.ExitCode)")
        continue
    }

    $pattern = '\[' + [regex]::Escape($doc.Name) + '\]\s*-\s*(v\d{8})'
    $match   = [regex]::Match($extract.Output, $pattern)

    if (-not $match.Success) {
        $failures.Add(
            "$($doc.Name): no '[$($doc.Name)] - vYYYYMMDD' stamp found in the first two pages. " +
            "Either the PDF is not the document it claims to be, or Microsoft changed the header.")
        continue
    }

    $found = $match.Groups[1].Value
    if ($found -ne $doc.Version) {
        $failures.Add("$($doc.Name): SPEC.md pins $($doc.Version), the local PDF is $found")
        continue
    }

    # A .txt extract older than its PDF is how a "grep says the spec allows this" argument gets
    # made against a document that no longer exists.
    if (Test-Path -LiteralPath $doc.TxtPath) {
        $pdfTime = (Get-Item -LiteralPath $doc.PdfPath).LastWriteTimeUtc
        $txtTime = (Get-Item -LiteralPath $doc.TxtPath).LastWriteTimeUtc
        if ($txtTime -lt $pdfTime) {
            $failures.Add(
                "$($doc.Name): spec\$($doc.Name).txt is older than the PDF. " +
                "Re-run Get-Specs.ps1 -Force, or the extracts you grep are stale.")
            continue
        }
    } else {
        $failures.Add("$($doc.Name): spec\$($doc.Name).txt is missing. Run Get-Specs.ps1.")
        continue
    }

    if (-not $Quiet) { Write-Ok "$($doc.Name) $found" }
}

if ($missing.Count -gt 0) {
    Write-Bad "Not downloaded: $($missing -join ', ')"
    Write-Host "    Run: powershell.exe -File scripts\Get-Specs.ps1" -ForegroundColor Yellow
    exit 1
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Bad 'Specification version check failed:'
    foreach ($failure in $failures) { Write-Host "         $failure" -ForegroundColor Red }
    Write-Host ''
    Write-Host '    A version bump is not a merge conflict to resolve — read the document''s own' -ForegroundColor Yellow
    Write-Host '    revision summary, then update the SPEC.md table deliberately.' -ForegroundColor Yellow
    exit 1
}

if (-not $Quiet) { Write-Ok "All $($docs.Count) documents match SPEC.md" }
exit 0
