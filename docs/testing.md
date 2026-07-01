# Testing the rules against real telemetry

Writing a detection is only half the job — you have to prove it actually fires on the
behavior it targets. Each rule in this pack was validated against **real Windows event
telemetry** using [Chainsaw](https://github.com/WithSecureLabs/chainsaw), which runs Sigma
rules directly against `.evtx` event logs.

Telemetry came from two sources:

- **Public attack samples** — real logs captured during actual attacks, from the
  [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) dataset.
- **Locally generated telemetry** — where no public sample fit the rule's exact event, I
  generated the event on a lab host (Sysmon for process creation, the Windows Security log
  for authentication) using harmless commands, then exported the log and tested against it.

## Results

| Rule | ATT&CK | Telemetry source | Result |
|------|--------|------------------|--------|
| PowerShell encoded command | T1059.001 | Locally generated (Sysmon EID 1) | ✅ Fired on the `-EncodedCommand` run |
| LSASS memory access | T1003.001 | 3 public attack samples (mimikatz, memdump, babyshark) | ✅ Fired on all three |
| Guest account auth activity | T1078.001 | Locally generated (Security EID 4625) | ✅ Fired on the real failed Guest logon |

## Details

### T1059.001 — PowerShell encoded command (+ a proven blind spot)

Installed Sysmon on a lab host and ran two harmless encoded PowerShell commands (each just
prints a string):

- `powershell -EncodedCommand <base64>` → **rule fired** ✅ (command line contains `-enc`)
- `powershell -e <base64>` (abbreviated flag) → **rule did NOT fire** ⛔

Both events were present in the log — the rule correctly matched the first and missed the
second. This **demonstrates, with real telemetry, the false-negative gap documented in the
rule's note**: PowerShell accepts abbreviated flags (`-e`, `-en`, …), so matching only
`-enc` misses the shorter forms. Closing that gap is a planned improvement.

### T1003.001 — LSASS memory access

Ran the rule against three independent real attack samples that capture LSASS credential
dumping (Sysmon Event ID 10). The rule fired on all three, matching `TargetImage` =
`lsass.exe` with a memory-read `GrantedAccess` mask (`0x1010`) — genuine
`sekurlsa::logonpasswords`-style telemetry.

### T1078.001 — Guest account (and an honest pivot)

The rule originally targeted only a *successful* Guest logon (Event 4624). While testing, I
found modern Windows **denies the Guest account interactive logon by default** (it lacks the
logon right), so a real successful Guest logon could not be produced on the host — the
attempt failed with status `0xC000015B` ("logon type not granted"), which Windows records as
a **4625 (failed logon)**.

Rather than force insecure changes to grant Guest a logon right, I **redesigned the rule** to
match authentication activity on the Guest account whether it **succeeds (4624) or fails
(4625)**. This is a stronger detection: it also catches an attacker *probing* the dormant
account, often the earlier signal. The rule then fired on the real `4625` Guest event
generated during testing.

## Reproducing this

The public-sample tests are reproducible with the script in [`../tests/`](../tests/), which
downloads Chainsaw and the relevant samples and runs the rules against them. The
locally-generated tests require a lab host (generating Sysmon and Security telemetry) and are
documented above rather than committed, because those logs contain host-specific identifiers.

## What this is not (scope / honesty)

This validates that the rules fire on real telemetry. It is **not** a full live lab: a
Sysmon-instrumented VM running the complete [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
test suite is a planned extension (see the roadmap in the README). The local generation here
covers the specific events these three rules target, not a broad adversary-emulation run.
