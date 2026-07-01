<#
    Reproducible test: run the Sigma rules in this repo against real public attack
    samples (EVTX-ATTACK-SAMPLES) using Chainsaw.

    Usage (from the repo root, on Windows PowerShell):
        ./tests/run_public_sample_tests.ps1

    It downloads Chainsaw and the sample .evtx files into a temp working dir (nothing is
    committed to the repo), runs the rules, and prints the detections. See docs/testing.md
    for the locally-generated tests (T1059.001 and T1078.001), which need a lab host.
#>

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$work     = Join-Path $env:TEMP "sigma-rule-pack-tests"
$samples  = Join-Path $work "samples"
New-Item -ItemType Directory -Force -Path $samples | Out-Null

# 1. Chainsaw
$chainsawZip = Join-Path $work "chainsaw.zip"
$chainsawExe = Join-Path $work "chainsaw\chainsaw.exe"
if (-not (Test-Path $chainsawExe)) {
    Write-Host "Downloading Chainsaw..."
    $url = "https://github.com/WithSecureLabs/chainsaw/releases/download/v2.16.0/chainsaw_x86_64-pc-windows-msvc.zip"
    Invoke-WebRequest -Uri $url -OutFile $chainsawZip
    Expand-Archive -Path $chainsawZip -DestinationPath $work -Force
}

# 2. Public attack samples (LSASS credential dumping = T1003)
$base = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master"
$files = @(
    "Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx",
    "Credential Access/sysmon_10_11_lsass_memdump.evtx",
    "Credential Access/babyshark_mimikatz_powershell.evtx"
)
foreach ($f in $files) {
    $out = Join-Path $samples (Split-Path $f -Leaf)
    if (-not (Test-Path $out)) {
        Write-Host "Downloading sample: $f"
        $enc = $f -replace " ", "%20"
        Invoke-WebRequest -Uri "$base/$enc" -OutFile $out
    }
}

# 3. Run the rules against the samples
$mapping = Join-Path $work "chainsaw\mappings\sigma-event-logs-all.yml"
Write-Host "`nRunning Chainsaw with the repo's Sigma rules...`n"
& $chainsawExe hunt $samples -s (Join-Path $repoRoot "rules") --mapping $mapping
