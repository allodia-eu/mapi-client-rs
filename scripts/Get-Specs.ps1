<#
.SYNOPSIS
    Downloads the six pinned Microsoft Open Specification documents into the gitignored spec/.

.DESCRIPTION
    Reads the document table from SPEC.md — the single source of truth — downloads each PDF, then
    extracts it to text with poppler's pdftotext so the specifications are greppable.

    The PDFs are never committed. The IP notice permits local copies "in order to develop
    implementations", but shipping 26 MB of Microsoft PDFs in a public repository is unnecessary
    and muddies the licensing story. A fresh clone is one command from having the sources.

    Verification of the release stamp inside each PDF is Check-SpecVersion.ps1's job, and this
    script runs it at the end unless -SkipVerify is given.

.PARAMETER Force
    Re-download documents that are already present.

.PARAMETER SkipVerify
    Do not run Check-SpecVersion.ps1 afterwards.

.EXAMPLE
    powershell.exe -File scripts\Get-Specs.ps1
#>
[CmdletBinding()]
param(
    [switch] $Force,
    [switch] $SkipVerify
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

$specDir    = Get-SpecDir
$docs       = Get-SpecManifest
$pdftotext  = Resolve-PdfToText

Write-Step "Fetching $($docs.Count) specification documents into $specDir"

foreach ($doc in $docs) {
    if ((Test-Path -LiteralPath $doc.PdfPath) -and -not $Force) {
        $sizeMb = [math]::Round((Get-Item -LiteralPath $doc.PdfPath).Length / 1MB, 1)
        Write-Ok "$($doc.Name).pdf already present ($sizeMb MB) — use -Force to re-download"
    } else {
        Write-Host "    GET  $($doc.Name) ($($doc.Version))"
        # -UseBasicParsing matters on 5.1: without it Invoke-WebRequest wants the Internet
        # Explorer engine, which is absent on Server Core and throws on first run elsewhere.
        Invoke-WebRequest -Uri $doc.Url -OutFile $doc.PdfPath -UseBasicParsing

        $sizeMb = [math]::Round((Get-Item -LiteralPath $doc.PdfPath).Length / 1MB, 1)
        Write-Ok "$($doc.Name).pdf downloaded ($sizeMb MB)"
    }

    if ((Test-Path -LiteralPath $doc.TxtPath) -and -not $Force) {
        continue
    }

    # -layout preserves the column structure, which matters enormously: the packet diagrams and
    # the field tables are unreadable once the columns are flattened.
    & $pdftotext -layout $doc.PdfPath $doc.TxtPath
    if ($LASTEXITCODE -ne 0) {
        throw "pdftotext failed on $($doc.Name).pdf with exit code $LASTEXITCODE."
    }

    $lines = (Get-Content -LiteralPath $doc.TxtPath | Measure-Object -Line).Lines
    Write-Ok "$($doc.Name).txt extracted ($lines lines)"
}

Write-Host ''
Write-Host 'The text extracts are the useful artefact day to day:' -ForegroundColor DarkGray
Write-Host '    Select-String -Path spec\MS-OXCROPS.txt -Pattern ''RopQueryRows'' -Context 2' -ForegroundColor DarkGray
Write-Host ''

if (-not $SkipVerify) {
    & "$PSScriptRoot\Check-SpecVersion.ps1"
}
