# Sigma Rule Pack

A detection-as-code project I'm building to learn detection engineering: a set of hand-written Sigma detection rules mapped to MITRE ATT&CK techniques, each documented with its likely false positives, and eventually a CI pipeline that lints and tests the rules automatically.

Built as a learning project to demonstrate practical detection-engineering workflows.

> 🚧 Work in progress. I'm building this in phases and committing as I go, so this README grows as the project does. The three rules are written and documented; validation and the test lab are next.

## Status

- [x] M0 — Foundations & repo structure
- [x] M1 — Hand-write the three Sigma rules
- [x] M2 — False-positive notes for each rule
- [x] M3 — Validate rules locally with pySigma
- [ ] M4 — Sysmon + Atomic Red Team test lab
- [ ] M5 — GitHub Actions CI (lint + test)
- [ ] M6 — Polish (coverage table, example output, docs)

## Scope: the rules I'm targeting

| ATT&CK ID  | Technique             | Tactic            | Folder                     |
|------------|-----------------------|-------------------|----------------------------|
| T1059.001  | PowerShell            | Execution         | `rules/execution/`         |
| T1003      | OS Credential Dumping | Credential Access | `rules/credential-access/` |
| T1078      | Valid Accounts        | Persistence\*     | `rules/persistence/`       |

\* T1078 spans several tactics (Initial Access, Persistence, Privilege Escalation, Defense Evasion). I filed it under persistence for the folder layout, and tagged the rule with the two tactics this specific Guest-logon detection actually serves (Persistence, Initial Access) rather than all four.

These are three *different* tactics on purpose. Covering only one tactic would leave me blind to everything else an attacker does — spreading across tactics is the start of a real coverage map.

## Repo layout

```
rules/                  Sigma rules, grouped by ATT&CK tactic
  execution/              powershell_encoded_command.yml      (T1059.001)
  credential-access/      lsass_memory_access.yml             (T1003)
  persistence/            guest_account_logon.yml             (T1078)
docs/                   per-rule detection + false-positive notes
requirements.txt        pinned pySigma tooling for validation
.github/workflows/      CI pipeline (added in M5)
```

## Background

A few terms this project is built on, in case anyone reading isn't deep in security:

**Sigma** is a vendor-neutral way to write a detection rule once, in YAML, and convert it to whichever SIEM a team actually runs (Splunk, Microsoft Sentinel, Elastic, etc.). Because the rules are plain text, they live in git, get reviewed, and get tested automatically — that's what "detection-as-code" means.

**MITRE ATT&CK** is a public catalog of attacker behavior. A *tactic* is the attacker's goal (e.g. Execution), a *technique* is the method (T1059, Command and Scripting Interpreter), and a sub-technique is a specific flavor (T1059.001, PowerShell). Tagging each rule with its ID makes the pack's coverage obvious at a glance.

**Sysmon** is a free Microsoft tool that adds detailed Windows logging — command lines, parent processes, one process reading another's memory — that default Windows logging doesn't reliably capture. The rules will query the events Sysmon produces; without that telemetry there's nothing to detect.

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

`sigma check rules/` currently reports **0 errors, 0 issues**. Example of the same rule
converted to Splunk (the vendor-neutral YAML becomes an actual SIEM search):

```
EventID=1 Image="*\\powershell.exe" CommandLine="*-enc*"
```

The `-p sysmon` / `-p splunk_windows` part is a *processing pipeline* — it maps the rule's
generic log source (e.g. `process_creation`) onto how a specific environment actually stores
those events (Sysmon `EventID=1`, the Windows Security channel, etc.). This is wired into CI
in M5 so it runs automatically on every push.
