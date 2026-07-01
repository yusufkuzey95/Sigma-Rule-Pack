# Testing the rules against real telemetry

Each rule was validated against real Windows event telemetry using
[Chainsaw](https://github.com/WithSecureLabs/chainsaw), which runs Sigma rules directly
against `.evtx` logs. Telemetry came from two sources:

- **Public attack samples** — real logs captured during actual attacks, from the
  [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) dataset.
- **Locally generated telemetry** — where no public sample fit a rule's exact event, I
  generated it on a lab host (Sysmon for process creation, the Windows Security log for
  authentication) with harmless commands, exported the log, and tested against it.

## Results

| Rule | ATT&CK | Telemetry source | Result |
|------|--------|------------------|--------|
| PowerShell encoded command | T1059.001 | Locally generated (Sysmon EID 1) | ✅ Fired on the `-EncodedCommand` run |
| LSASS memory access | T1003.001 | 3 public attack samples (mimikatz, memdump, babyshark) | ✅ Fired on all three |
| Guest account auth activity | T1078.001 | Locally generated (Security EID 4625) | ✅ Fired on the real failed Guest logon |

## Details

### T1059.001 — PowerShell encoded command

Ran two harmless encoded PowerShell commands on a Sysmon lab host:

- `powershell -EncodedCommand <base64>` → fired ✅ (command line contains `-enc`)
- `powershell -e <base64>` (abbreviated flag) → did not fire ⛔

Both events were in the log; the rule matched the first and missed the second, confirming the
blind spot noted in the rule — matching only `-enc` misses PowerShell's abbreviated flags
(`-e`, `-en`, …).

### T1003.001 — LSASS memory access

Ran the rule against three real attack samples of LSASS credential dumping (Sysmon Event
ID 10). It fired on all three, matching `TargetImage` = `lsass.exe` with a memory-read
`GrantedAccess` mask (`0x1010`) — `sekurlsa::logonpasswords`-style telemetry.

### T1078.001 — Guest account

The rule originally matched only a successful Guest logon (Event 4624). Modern Windows denies
the Guest account interactive logon by default, so the logon attempt failed with status
`0xC000015B` ("logon type not granted") — recorded as a **4625**. I updated the rule to match
Guest authentication whether it succeeds (4624) or fails (4625), which also catches an
attacker probing the account. It then fired on the real 4625 event.

## Reproducing this

The public-sample tests run from [`../tests/`](../tests/), which downloads Chainsaw and the
samples and runs the rules against them. The locally-generated tests need a lab host and
aren't committed, since those logs contain host-specific identifiers.
