<#
.SYNOPSIS
    Rewrites every scripts\*.ps1 as UTF-8 with a BOM.

.DESCRIPTION
    Windows PowerShell 5.1 reads a BOM-less file as ANSI (Windows-1252). One non-ASCII character
    in a comment is then enough to corrupt the parse, and because a dot-sourced file that fails to
    parse does not stop its caller, the result is a script that runs with none of its helpers
    defined and exits 0.

    Most editors and every tool that writes UTF-8 "the modern way" omit the BOM, so this will be
    needed again. Invoke-Gate.ps1 checks the invariant; this restores it.

    Deliberately does not touch anything outside scripts\ - Rust sources and YAML want no BOM.

.PARAMETER WhatIf
    Report what would change without writing.

.EXAMPLE
    powershell.exe -File scripts\Repair-ScriptEncoding.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
$utf8Bom   = New-Object System.Text.UTF8Encoding($true)
$repaired  = 0

foreach ($file in (Get-ChildItem -Path $scriptDir -Filter '*.ps1' -Recurse -File)) {
    $bytes  = [System.IO.File]::ReadAllBytes($file.FullName)
    $hasBom = $bytes.Length -ge 3 -and
              $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF

    if ($hasBom) {
        Write-Verbose "$($file.Name) already has a BOM"
        continue
    }

    # Read as UTF-8 explicitly. The file was written as UTF-8; it is only PowerShell's *default*
    # interpretation of a BOM-less file that is wrong, not the bytes.
    $text = [System.IO.File]::ReadAllText($file.FullName, [System.Text.UTF8Encoding]::new($false))

    if ($PSCmdlet.ShouldProcess($file.FullName, 'add UTF-8 BOM')) {
        [System.IO.File]::WriteAllText($file.FullName, $text, $utf8Bom)
        Write-Host "  fixed  $($file.Name)" -ForegroundColor Green
    } else {
        Write-Host "  would fix  $($file.Name)" -ForegroundColor Yellow
    }
    $repaired++
}

if ($repaired -eq 0) {
    Write-Host 'All scripts already UTF-8 with BOM.' -ForegroundColor Green
} else {
    Write-Host "$repaired script(s) processed." -ForegroundColor Cyan
}
