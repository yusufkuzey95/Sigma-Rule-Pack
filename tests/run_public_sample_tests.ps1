<#
    Runs the repo's Sigma rules against real public attack samples (EVTX-ATTACK-SAMPLES)
    with Chainsaw, so you can see the LSASS rule actually fire.

    Run from the repo root:  ./tests/run_public_sample_tests.ps1

    Grabs Chainsaw + the sample logs into a temp folder (nothing gets committed). The
    PowerShell and Guest rules were tested on lab-generated logs instead - see docs/testing.md.
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
