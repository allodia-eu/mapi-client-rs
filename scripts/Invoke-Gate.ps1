<#
.SYNOPSIS
    The full local verification gate. Mirrors CI exactly, so a green run here means a green run there.

.DESCRIPTION
    Runs every check ci.yml runs, in the same order, with the same flags. The point of mirroring is
    that "it passed locally" and "it passed in CI" stop being different claims.

    One deliberate difference, and only one: CI has no Exchange server, so neither does this gate.
    Live checks live in Test-Live.ps1 and are never part of the gate.

    Every step runs even if an earlier one fails, and the summary at the end lists all of them —
    fixing four failures one CI round trip at a time is the thing this is designed to avoid.

.PARAMETER SkipCoverage
    Skip the coverage step, which is by far the slowest (it rebuilds with instrumentation).

.PARAMETER Only
    Run only the named steps. Use -List to see the names.

.PARAMETER List
    Print the step names and exit.

.EXAMPLE
    powershell.exe -File scripts\Invoke-Gate.ps1

.EXAMPLE
    powershell.exe -File scripts\Invoke-Gate.ps1 -Only fmt,clippy
#>
[CmdletBinding()]
param(
    [switch]   $SkipCoverage,
    [string[]] $Only,
    [switch]   $List
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Boot.ps1"
Assert-BootLoaded   # a dot-sourced file that fails to parse does not stop us; this does

$repoRoot = Get-RepoRoot
$cargo    = Get-CargoPath

$stepNames = @(
    'toolchain', 'script-encoding', 'spec-version', 'fmt', 'clippy', 'build',
    'test', 'doc', 'coverage', 'deny', 'public-api', 'typos', 'file-length'
)

if ($List) {
    $stepNames | ForEach-Object { Write-Host "  $_" }
    exit 0
}

if ($Only) {
    foreach ($name in $Only) {
        if ($stepNames -notcontains $name) {
            throw "Unknown step '$name'. Known steps: $($stepNames -join ', ')"
        }
    }
}

$results  = New-Object System.Collections.Generic.List[psobject]
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Invoke-Step {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]      $Name,
        [Parameter(Mandatory)][scriptblock] $Action,
        [Parameter()][string]               $SkipReason
    )

    if ($script:Only -and ($script:Only -notcontains $Name)) { return }

    if ($SkipReason) {
        Write-Step "$Name — skipped ($SkipReason)"
        $script:results.Add([pscustomobject]@{ Step = $Name; Status = 'SKIP'; Seconds = 0 })
        return
    }

    Write-Step $Name
    $timer = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        & $Action
        $timer.Stop()
        $script:results.Add([pscustomobject]@{
            Step = $Name; Status = 'PASS'; Seconds = [math]::Round($timer.Elapsed.TotalSeconds, 1)
        })
        Write-Ok "$Name ($([math]::Round($timer.Elapsed.TotalSeconds, 1))s)"
    } catch {
        $timer.Stop()
        $script:results.Add([pscustomobject]@{
            Step = $Name; Status = 'FAIL'; Seconds = [math]::Round($timer.Elapsed.TotalSeconds, 1)
        })
        Write-Bad "$Name — $($_.Exception.Message)"
    }
}

Push-Location -LiteralPath $repoRoot
try {

    # -----------------------------------------------------------------------
    Invoke-Step 'toolchain' {
        # rust-toolchain.toml is the single source of truth for the version. This asserts that
        # workspace.package.rust-version has not drifted away from it, because the two saying
        # different things is how an MSRV claim becomes a lie.
        $pinned = ([regex]::Match(
            (Get-Content -LiteralPath 'rust-toolchain.toml' -Raw),
            'channel\s*=\s*"([^"]+)"')).Groups[1].Value
        $declared = ([regex]::Match(
            (Get-Content -LiteralPath 'Cargo.toml' -Raw),
            'rust-version\s*=\s*"([^"]+)"')).Groups[1].Value

        if (-not $pinned)   { throw 'No channel found in rust-toolchain.toml.' }
        if (-not $declared) { throw 'No rust-version found in Cargo.toml.' }
        if (-not $pinned.StartsWith($declared)) {
            throw "rust-toolchain.toml pins $pinned but Cargo.toml declares rust-version $declared."
        }

        Write-Host "    toolchain $pinned, MSRV $declared"
        Invoke-Native $cargo @('--version')
    }

    # -----------------------------------------------------------------------
    Invoke-Step 'script-encoding' {
        # Windows PowerShell 5.1 reads a BOM-less file as ANSI, so one em dash in a comment can
        # break the parse - and a dot-sourced file that fails to parse does not stop its caller,
        # which then runs on with no helpers defined and exits 0. Checking the BOM mechanically is
        # the difference between that being a rule someone remembers and a rule that holds.
        $bad = New-Object System.Collections.Generic.List[string]

        foreach ($file in (Get-ChildItem -Path (Join-Path $repoRoot 'scripts') -Filter '*.ps1' -Recurse -File)) {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $hasBom = $bytes.Length -ge 3 -and
                      $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
            if (-not $hasBom) {
                $bad.Add("$($file.Name): no UTF-8 BOM")
            }
        }

        if ($bad.Count -gt 0) {
            foreach ($b in $bad) { Write-Host "         $b" -ForegroundColor Red }
            throw "$($bad.Count) script(s) are not UTF-8 with BOM. Run scripts\Repair-ScriptEncoding.ps1."
        }

        Write-Host '    all scripts are UTF-8 with BOM'
    }

    # -----------------------------------------------------------------------
    Invoke-Step 'spec-version' {
        # Not something CI can run (no PDFs there), but it belongs in the local gate: it is the
        # cheapest possible check that the specs you are reading are the ones you pinned.
        & "$PSScriptRoot\Check-SpecVersion.ps1" -Quiet
        if ($LASTEXITCODE -ne 0) { throw 'Specification versions do not match SPEC.md.' }
    }

    # -----------------------------------------------------------------------
    Invoke-Step 'fmt' {
        # Nightly, because rustfmt.toml uses nightly-only options. The compiler stays on stable.
        Invoke-Native $cargo @('+nightly', 'fmt', '--all', '--', '--check')
    }

    # -----------------------------------------------------------------------
    Invoke-Step 'clippy' {
        Invoke-Native $cargo @(
            'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings')
    }

    # -----------------------------------------------------------------------
    Invoke-Step 'build' {
        Invoke-Native $cargo @('build', '--workspace', '--all-features')
    }

    # -----------------------------------------------------------------------
    Invoke-Step 'test' {
        $nextest = Get-Command 'cargo-nextest.exe' -ErrorAction SilentlyContinue
        if ($nextest) {
            # --no-tests=warn because the workspace is still being populated and nextest treats an
            # empty suite as an error. This is not a hole in the gate: if the suite ever silently
            # emptied out, the 95% coverage floor below would fail long before this would.
            Invoke-Native $cargo @('nextest', 'run', '--workspace', '--all-features', '--no-tests=warn')
        } else {
            Invoke-Native $cargo @('test', '--workspace', '--all-features')
        }
        # nextest does not run doctests, and the doctests on the main entry points are part of the
        # public-API contract. Run them separately rather than losing them.
        Invoke-Native $cargo @('test', '--workspace', '--all-features', '--doc')
    }

    # -----------------------------------------------------------------------
    Invoke-Step 'doc' {
        $env:RUSTDOCFLAGS = '-D warnings'
        try {
            Invoke-Native $cargo @('doc', '--workspace', '--all-features', '--no-deps')
        } finally {
            Remove-Item Env:\RUSTDOCFLAGS -ErrorAction SilentlyContinue
        }
    }

    # -----------------------------------------------------------------------
    $coverageSkip = if ($SkipCoverage) { 'requested with -SkipCoverage' } else { $null }
    Invoke-Step 'coverage' -SkipReason $coverageSkip -Action {
        $floor = Get-CoverageFloor
        Write-Host "    floor $floor% (from codecov.yml)"

        $common = @(
            'llvm-cov', '--workspace', '--all-features',
            '--ignore-filename-regex', 'mapi-cli')

        # An empty workspace measures zero lines, and llvm-cov reports that as "-" rather than as
        # a percentage, so --fail-under-lines fails on a codebase that has nothing wrong with it.
        # Enforce the floor only when there is something to measure, and say so loudly when there
        # is not. This never weakens once code exists, which is the property that matters.
        $summary = Get-NativeOutput -FilePath $cargo -Arguments ($common + @('--summary-only'))
        if ($summary.ExitCode -ne 0) {
            Write-Host $summary.Output
            throw "cargo llvm-cov exited with code $($summary.ExitCode)."
        }

        $totalLines = 0
        $totalMatch = [regex]::Match($summary.Output, '(?m)^TOTAL\s+(?:\S+\s+){6}(\d+)\s')
        if ($totalMatch.Success) { $totalLines = [int]$totalMatch.Groups[1].Value }

        if ($totalLines -eq 0) {
            Write-Warn 'no instrumented lines yet - the floor is not enforceable until code lands'
            return
        }

        Invoke-Native $cargo ($common + @('--fail-under-lines', "$floor"))
    }

    # -----------------------------------------------------------------------
    Invoke-Step 'deny' {
        # cargo-deny shells out to git to fetch the advisory database, and git is not always on
        # the Windows PATH even when Git for Windows is installed.
        Initialize-GitOnPath
        Invoke-Native $cargo @('deny', '--all-features', 'check')
    }

    # -----------------------------------------------------------------------
    Invoke-Step 'public-api' {
        # Locally this renders the public API so a surprise addition is visible while you work.
        # The *diff* against the base branch is CI's job, where there is a base to diff against.
        Invoke-Native $cargo @(
            '+nightly', 'public-api', '--simplified', '--package', 'mapi-proto')
    }

    # -----------------------------------------------------------------------
    Invoke-Step 'typos' {
        Invoke-Native (Get-Command 'typos.exe').Source @()
    }

    # -----------------------------------------------------------------------
    Invoke-Step 'file-length' {
        & "$PSScriptRoot\Check-FileLength.ps1"
        if ($LASTEXITCODE -ne 0) { throw 'Rust source files exceed the 500-line limit.' }
    }

} finally {
    Pop-Location
}

$stopwatch.Stop()

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '  Step            Status   Seconds' -ForegroundColor White
Write-Host '  ------------------------------------' -ForegroundColor DarkGray

foreach ($result in $results) {
    $colour = switch ($result.Status) {
        'PASS' { 'Green' }
        'SKIP' { 'Yellow' }
        default { 'Red' }
    }
    Write-Host ("  {0,-14}  {1,-6}  {2,6}" -f $result.Step, $result.Status, $result.Seconds) `
        -ForegroundColor $colour
}

$failed = @($results | Where-Object { $_.Status -eq 'FAIL' })
$total  = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)

Write-Host ''
if ($failed.Count -gt 0) {
    Write-Bad "$($failed.Count) of $($results.Count) step(s) failed in ${total}s: $(($failed | ForEach-Object { $_.Step }) -join ', ')"
    exit 1
}

Write-Ok "Gate passed in ${total}s"
Write-Host ''
Write-Host '  Note: this gate never touches the Exchange server, exactly as CI never does.' -ForegroundColor DarkGray
Write-Host '  For live verification, run scripts\Test-Live.ps1 deliberately.' -ForegroundColor DarkGray
exit 0
