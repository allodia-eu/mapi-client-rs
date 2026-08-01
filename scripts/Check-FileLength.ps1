<#
.SYNOPSIS
    Fails if any Rust source file exceeds the 500-line limit.

.DESCRIPTION
    The limit is a structural constraint, not a style preference. A binary protocol codec attracts
    thousand-line "all the ROPs" modules, and once a file passes a certain size the reviewer stops
    reading it as a whole and starts reading it as a diff. Capping the file forces the module split
    that keeps each layer — wire, http, rop, oxcdata — reviewable on its own.

    Counts every line, including comments and blank lines. Comments are the spec citations; a file
    that is 300 lines of code and 400 lines of citation is still 700 lines to read.

.PARAMETER MaxLines
    The limit. Defaults to 500 and should not be raised without a good reason.

.PARAMETER Path
    Root to scan. Defaults to the repository root.

.EXAMPLE
    powershell.exe -File scripts\Check-FileLength.ps1
#>
[CmdletBinding()]
param(
    [int]    $MaxLines = 500,
    [string] $Path
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

if (-not $Path) { $Path = Get-RepoRoot }
$root = (Resolve-Path -LiteralPath $Path).Path

Write-Step "Checking Rust source files against the $MaxLines-line limit"

$files = Get-ChildItem -Path $root -Filter '*.rs' -Recurse -File |
    Where-Object { $_.FullName -notmatch '\\target\\' }

$violations = New-Object System.Collections.Generic.List[psobject]
$longest    = 0
$longestOne = ''

foreach ($file in $files) {
    $lines = (Get-Content -LiteralPath $file.FullName | Measure-Object -Line).Lines
    $relative = $file.FullName.Substring($root.Length).TrimStart('\')

    if ($lines -gt $longest) {
        $longest    = $lines
        $longestOne = $relative
    }

    if ($lines -gt $MaxLines) {
        $violations.Add([pscustomobject]@{ File = $relative; Lines = $lines })
    }
}

if ($violations.Count -gt 0) {
    Write-Bad "$($violations.Count) file(s) over the limit:"
    foreach ($v in ($violations | Sort-Object -Property Lines -Descending)) {
        Write-Host ("         {0,5}  {1}" -f $v.Lines, $v.File) -ForegroundColor Red
    }
    exit 1
}

if ($files.Count -eq 0) {
    Write-Ok 'No Rust source files yet'
} else {
    Write-Ok "$($files.Count) file(s), longest is $longest lines ($longestOne)"
}
exit 0
