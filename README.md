# Sigma Rule Pack

[![Validate Sigma rules](https://github.com/yusufkuzey95/Sigma-Rule-Pack/actions/workflows/validate.yml/badge.svg)](https://github.com/yusufkuzey95/Sigma-Rule-Pack/actions/workflows/validate.yml)

A detection-as-code repo: Sigma detection rules mapped to MITRE ATT&CK, each with false-positive notes, validated with pySigma, tested against real attack telemetry, and linted in CI on every push. Includes a web dashboard for browsing the rules and their results.

Built as a portfolio project to demonstrate practical detection-engineering workflows.

## What it does

- Detects real attacker behavior with **3 Sigma rules** — encoded PowerShell (T1059.001), LSASS credential dumping (T1003), and misuse of the built-in Guest account (T1078).
- Maps every rule to a **MITRE ATT&CK** technique, so coverage is explicit and auditable.
- Ships a **false-positive note per rule** — what benign activity trips it, how to tell real from noise, and its known blind spots.
- Validates and converts rules to Splunk queries with **pySigma**, enforced by **GitHub Actions CI** on every push.
- Confirms each rule fires on **real attack telemetry** using [Chainsaw](https://github.com/WithSecureLabs/chainsaw).
- Presents everything in a **Flask dashboard** — ATT&CK mappings, SIEM queries, and test results.

## Status

✅ Complete.

- [x] 3 Sigma rules (T1059.001, T1003, T1078)
- [x] False-positive / analyst notes per rule
- [x] pySigma validation + Splunk conversion
- [x] GitHub Actions CI (lints on every push)
- [x] Tested against real attack telemetry (Chainsaw)
- [x] Web dashboard

## ATT&CK coverage

| Tactic | Technique | Sub-technique | Rule | Tested |
|--------|-----------|---------------|------|--------|
| Execution | T1059 Command & Scripting Interpreter | T1059.001 PowerShell | [`powershell_encoded_command.yml`](rules/execution/powershell_encoded_command.yml) | ✅ |
| Credential Access | T1003 OS Credential Dumping | T1003.001 LSASS Memory | [`lsass_memory_access.yml`](rules/credential-access/lsass_memory_access.yml) | ✅ |
| Persistence / Initial Access | T1078 Valid Accounts | T1078.001 Default Accounts | [`guest_account_logon.yml`](rules/persistence/guest_account_logon.yml) | ✅ |

I spread the rules across three different tactics rather than three flavors of one, so the pack starts to form a real coverage map.

## About

Sigma is a vendor-neutral detection format: you write a rule once in YAML and convert it to whatever SIEM you run (Splunk, Microsoft Sentinel, Elastic). Because the rules are plain text, they live in git and get linted and tested like code — that's detection-as-code. The rules here target telemetry from Sysmon and the Windows Security log, tagged with the MITRE ATT&CK techniques they cover.

## Repo layout

```
rules/                  Sigma rules, grouped by ATT&CK tactic
  execution/              powershell_encoded_command.yml      (T1059.001)
  credential-access/      lsass_memory_access.yml             (T1003)
  persistence/            guest_account_logon.yml             (T1078)
docs/                   per-rule detection + false-positive notes, plus testing.md
tests/                  reproducible test script (rules vs. real attack samples)
webapp/                 Flask dashboard for browsing the rule pack
requirements.txt        pinned pySigma tooling
.github/workflows/      CI pipeline (lints rules on every push)
```

## Validating the rules

```
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt

sigma check rules/                                                    # lint every rule
sigma convert -t splunk -p sysmon rules/execution/powershell_encoded_command.yml   # convert to Splunk
```

`sigma check rules/` reports 0 errors and 0 issues, and the same check runs in CI on every push. The PowerShell rule, for example, converts to:

```
EventID=1 Image="*\\powershell.exe" CommandLine="*-enc*"
```

## Testing against real telemetry

Each rule was run against real Windows event logs with [Chainsaw](https://github.com/WithSecureLabs/chainsaw) — some from the public [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) dataset, some generated on a lab host. Full write-up: [`docs/testing.md`](docs/testing.md).

| Rule | ATT&CK | Telemetry | Result |
|------|--------|-----------|--------|
| PowerShell encoded command | T1059.001 | Sysmon EID 1 (lab) | ✅ fired on `-EncodedCommand`; correctly missed the abbreviated `-e` form (a documented blind spot) |
| LSASS memory access | T1003.001 | 3 real public attack samples | ✅ fired on all three |
| Guest account auth activity | T1078.001 | Security EID 4625 (lab) | ✅ fired on a real failed Guest logon |

The public-sample test is reproducible: [`tests/run_public_sample_tests.ps1`](tests/run_public_sample_tests.ps1).

## Web dashboard

A Flask app presents the rule pack visually — each rule's ATT&CK mapping, severity, detection logic, generated Splunk query, false-positive notes, and test result.

```
pip install -r requirements.txt
python webapp/app.py                  # then open http://127.0.0.1:5000
```

## License

Released under the MIT License — see [LICENSE](LICENSE).
