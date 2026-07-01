# Sigma Rule Pack

[![Validate Sigma rules](https://github.com/yusufkuzey95/Sigma-Rule-Pack/actions/workflows/validate.yml/badge.svg)](https://github.com/yusufkuzey95/Sigma-Rule-Pack/actions/workflows/validate.yml)

A detection-as-code project: a set of hand-written Sigma detection rules mapped to MITRE ATT&CK, each documented with its likely false positives, validated with pySigma, tested against real attack telemetry, and linted automatically in CI on every push.

Built as a learning project to demonstrate practical detection-engineering workflows — every rule was written and reasoned through by hand so I can explain each line.

## Status

✅ **Complete.** Three rules across three ATT&CK tactics — written, documented, validated, and tested against real telemetry, with CI enforcing rule quality on every push.

- [x] Hand-written Sigma rules for T1059.001, T1003, T1078
- [x] False-positive / analyst notes for each rule
- [x] Validated + converted to SIEM queries with pySigma
- [x] Tested against real attack telemetry with Chainsaw
- [x] GitHub Actions CI (lints rules on every push)
- [ ] *Planned enhancement:* full Sysmon-instrumented VM with live Atomic Red Team emulation

## What's inside

- **Three detections that catch real attacker behavior** — encoded PowerShell, LSASS credential dumping, and misuse of the built-in Guest account.
- **Every rule mapped to MITRE ATT&CK** by technique ID, so the coverage is explicit and auditable.
- **A false-positive note per rule** — what benign activity could trip it, how an analyst tells real from noise, and the rule's known blind spots.
- **Proof they work** — each rule was run against real Windows event logs and shown to fire on the behavior it targets (including a deliberately documented miss).
- **A web dashboard** to browse the rules, their SIEM queries, and test results ([see below](#web-demo)).
- **CI** that lints every rule on every push, so a broken rule never ships.

## ATT&CK coverage

| Tactic | Technique | Sub-technique | Rule | Tested |
|--------|-----------|---------------|------|--------|
| Execution | T1059 Command & Scripting Interpreter | T1059.001 PowerShell | [`powershell_encoded_command.yml`](rules/execution/powershell_encoded_command.yml) | ✅ |
| Credential Access | T1003 OS Credential Dumping | T1003.001 LSASS Memory | [`lsass_memory_access.yml`](rules/credential-access/lsass_memory_access.yml) | ✅ |
| Persistence / Initial Access | T1078 Valid Accounts | T1078.001 Default Accounts | [`guest_account_logon.yml`](rules/persistence/guest_account_logon.yml) | ✅ |

These are three *different* tactics on purpose. Covering only one tactic would leave me blind to everything else an attacker does — spreading across tactics is the start of a real coverage map.

> On T1078: the technique spans several tactics (Initial Access, Persistence, Privilege Escalation, Defense Evasion). I filed it under `persistence/` for the folder layout and tagged the rule with the two tactics this specific Guest-account detection actually serves.

## Repo layout

```
rules/                  Sigma rules, grouped by ATT&CK tactic
  execution/              powershell_encoded_command.yml      (T1059.001)
  credential-access/      lsass_memory_access.yml             (T1003)
  persistence/            guest_account_logon.yml             (T1078)
docs/                   per-rule detection + false-positive notes, plus testing.md
tests/                  reproducible test script (rules vs. real attack samples)
webapp/                 Flask dashboard to browse the rule pack
requirements.txt        pinned pySigma tooling for validation
.github/workflows/      CI pipeline (lints rules on every push)
```

## Background

A few terms this project is built on, in case anyone reading isn't deep in security:

**Sigma** is a vendor-neutral way to write a detection rule once, in YAML, and convert it to whichever SIEM a team actually runs (Splunk, Microsoft Sentinel, Elastic, etc.). Because the rules are plain text, they live in git, get reviewed, and get tested automatically — that's what "detection-as-code" means.

**MITRE ATT&CK** is a public catalog of attacker behavior. A *tactic* is the attacker's goal (e.g. Execution), a *technique* is the method (T1059, Command and Scripting Interpreter), and a sub-technique is a specific flavor (T1059.001, PowerShell). Tagging each rule with its ID makes the pack's coverage obvious at a glance.

**Sysmon** is a free Microsoft tool that adds detailed Windows logging — command lines, parent processes, one process reading another's memory — that default Windows logging doesn't reliably capture. The rules query the events Sysmon produces; without that telemetry there's nothing to detect.

## Validating the rules

The rules are linted and converted with the official Sigma tooling (pySigma), so they're proven well-formed before they ship:

```
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt

# lint every rule (structure + valid ATT&CK tags)
sigma check rules/

# convert a rule into a real SIEM query
sigma convert -t splunk -p sysmon rules/execution/powershell_encoded_command.yml
```

`sigma check rules/` reports **0 errors, 0 issues**. Example of the same rule converted to Splunk (the vendor-neutral YAML becomes an actual SIEM search):

```
EventID=1 Image="*\\powershell.exe" CommandLine="*-enc*"
```

The `-p sysmon` / `-p splunk_windows` part is a *processing pipeline* — it maps the rule's generic log source (e.g. `process_creation`) onto how a specific environment actually stores those events (Sysmon `EventID=1`, the Windows Security channel, etc.). The same `sigma check` runs in CI on every push.

## Testing against real telemetry

Linting proves a rule is *well-formed*; testing proves it actually *fires* on the behavior it targets. Each rule was run against real Windows event logs with [Chainsaw](https://github.com/WithSecureLabs/chainsaw) — some from the public [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) dataset, some generated on a lab host. Full write-up: [`docs/testing.md`](docs/testing.md).

| Rule | ATT&CK | Telemetry | Result |
|------|--------|-----------|--------|
| PowerShell encoded command | T1059.001 | Locally generated (Sysmon EID 1) | ✅ fired on `-EncodedCommand`; **correctly missed** the abbreviated `-e` form (a documented blind spot) |
| LSASS memory access | T1003.001 | 3 real public attack samples | ✅ fired on all three |
| Guest account auth activity | T1078.001 | Locally generated (Security EID 4625) | ✅ fired on a real failed Guest logon |

The public-sample test is reproducible: [`tests/run_public_sample_tests.ps1`](tests/run_public_sample_tests.ps1).

A full Sysmon-instrumented VM running the complete Atomic Red Team suite is a planned extension — the tests above validate each rule's specific target events.

## Web demo

A small Flask dashboard presents the rule pack visually — each rule's ATT&CK mapping, severity, detection logic, the pySigma-generated Splunk query, its false-positive notes, and its test result. It's a thin layer over the same rule files and the same pySigma engine the CLI uses.

```
pip install -r requirements.txt      # includes Flask
python webapp/app.py                  # then open http://127.0.0.1:5000
```

## License

Released under the MIT License — see [LICENSE](LICENSE).
