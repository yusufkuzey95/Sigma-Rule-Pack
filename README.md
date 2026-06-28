# Sigma Rule Pack

A detection-as-code project I'm building to learn detection engineering: a set of hand-written Sigma detection rules mapped to MITRE ATT&CK techniques, each documented with its likely false positives, and eventually a CI pipeline that lints and tests the rules automatically.

Built as a learning project to demonstrate practical detection-engineering workflows.

> 🚧 Early work in progress. I'm building this in phases and committing as I go, so this README grows as the project does. Right now the repo structure is in place and the rules are next.

## Status

- [x] M0 — Foundations & repo structure
- [ ] M1 — Hand-write the three Sigma rules
- [ ] M2 — False-positive notes for each rule
- [ ] M3 — Validate rules locally with pySigma
- [ ] M4 — Sysmon + Atomic Red Team test lab
- [ ] M5 — GitHub Actions CI (lint + test)
- [ ] M6 — Polish (coverage table, example output, docs)

## Scope: the rules I'm targeting

| ATT&CK ID  | Technique             | Tactic            | Folder                     |
|------------|-----------------------|-------------------|----------------------------|
| T1059.001  | PowerShell            | Execution         | `rules/execution/`         |
| T1003      | OS Credential Dumping | Credential Access | `rules/credential-access/` |
| T1078      | Valid Accounts        | Persistence\*     | `rules/persistence/`       |

\* T1078 spans several tactics (Initial Access, Persistence, Privilege Escalation, Defense Evasion); the rule will tag the full mapping, but I filed it under persistence for the folder layout.

These are three *different* tactics on purpose. Covering only one tactic would leave me blind to everything else an attacker does — spreading across tactics is the start of a real coverage map.

## Repo layout

```
rules/                  Sigma rules, grouped by ATT&CK tactic (empty for now)
  execution/
  credential-access/
  persistence/
docs/                   per-rule false-positive notes (added in M2)
.github/workflows/      CI pipeline (added in M5)
```

## Background

A few terms this project is built on, in case anyone reading isn't deep in security:

**Sigma** is a vendor-neutral way to write a detection rule once, in YAML, and convert it to whichever SIEM a team actually runs (Splunk, Microsoft Sentinel, Elastic, etc.). Because the rules are plain text, they live in git, get reviewed, and get tested automatically — that's what "detection-as-code" means.

**MITRE ATT&CK** is a public catalog of attacker behavior. A *tactic* is the attacker's goal (e.g. Execution), a *technique* is the method (T1059, Command and Scripting Interpreter), and a sub-technique is a specific flavor (T1059.001, PowerShell). Tagging each rule with its ID makes the pack's coverage obvious at a glance.

**Sysmon** is a free Microsoft tool that adds detailed Windows logging — command lines, parent processes, one process reading another's memory — that default Windows logging doesn't reliably capture. The rules will query the events Sysmon produces; without that telemetry there's nothing to detect.
