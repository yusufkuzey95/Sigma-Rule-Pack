# Tests

Proof that the rules actually fire on real attack telemetry. Full write-up and results are
in [`../docs/testing.md`](../docs/testing.md).

## `run_public_sample_tests.ps1`

Reproducible test against **real public attack samples**
([EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)) using
[Chainsaw](https://github.com/WithSecureLabs/chainsaw). It downloads the tool and the sample
logs into a temp folder (nothing large or third-party is committed here) and runs this repo's
Sigma rules against them.

```powershell
./tests/run_public_sample_tests.ps1
```

Expected: the **LSASS memory access** rule (T1003.001) fires on the mimikatz / LSASS-dump
samples.

## Locally-generated tests (T1059.001, T1078.001)

The PowerShell-encoded-command and Guest-account rules were validated against telemetry
generated on a lab host (Sysmon Event ID 1, and Windows Security Event ID 4625). Those steps
and results are documented in [`../docs/testing.md`](../docs/testing.md). The generated logs
are **not** committed because they contain host-specific identifiers.
