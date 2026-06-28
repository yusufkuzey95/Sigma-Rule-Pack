# Sigma Rule Pack (Detection-as-Code)

A small, well-documented set of Sigma detection rules mapped to MITRE ATT&CK,
built so I can explain every part of it. This is a learning + portfolio project,
so I'm writing the rules by hand and documenting the reasoning instead of just
pulling in a big public ruleset.

> Status: work in progress. I'm building this in phases and committing as I go.

## What this project is

A "detection-as-code" repo. That means the detection rules are plain text files
that live in git, get reviewed, and (eventually) get tested automatically in CI —
the same way you'd treat application source code. The point is to show I can not
only write detections but also version, document, and test them like an engineer.

The rules target three attacker behaviors to start:

| ATT&CK ID  | Technique                       | Tactic            | Folder                      |
|------------|---------------------------------|-------------------|-----------------------------|
| T1059.001  | PowerShell                      | Execution         | `rules/execution/`          |
| T1003      | OS Credential Dumping           | Credential Access | `rules/credential-access/`  |
| T1078      | Valid Accounts                  | Persistence*      | `rules/persistence/`        |

\* T1078 actually spans several tactics (Initial Access, Persistence, Privilege
Escalation, Defense Evasion). I filed it under persistence here for the folder
layout, but the rule itself tags the full mapping.

I picked three *different* tactics on purpose. If all my rules covered only one
tactic, I'd be blind to everything else an attacker does. Spreading across tactics
is the start of a coverage map.

## Some background (for anyone reading this who isn't in security)

**What's a detection rule?** It's a saved question you ask your logs over and over,
automatically: "did something suspicious just happen?" If yes, it raises an alert
for a human analyst to look at. It doesn't block anything itself — detection is
about *noticing and notifying*, not fixing.

**What's Sigma?** Every SIEM (the big searchable log database a security team uses
— Splunk, Microsoft Sentinel, Elastic, etc.) speaks its own query language. Sigma
is a vendor-neutral way to write a detection rule once, in YAML, and then convert
it to whichever SIEM you actually run. Write once, deploy anywhere. Because the
rules are just text, you can keep them in git — which is the whole reason
"detection-as-code" is possible.

**What's MITRE ATT&CK?** A free, public catalog of how real attackers behave, with
a standard ID for each behavior. A *tactic* is the attacker's goal (the "why", e.g.
Execution). A *technique* is the method (the "how", e.g. T1059 Command and Scripting
Interpreter), and a sub-technique is a specific flavor (T1059.001 PowerShell).
Tagging each rule with its ATT&CK ID makes it obvious what threats this pack covers.

**Why Sysmon?** Plain Windows doesn't log enough detail to catch these behaviors —
it often won't record the command line, the parent process, or one process reading
another's memory. Sysmon is a free Microsoft tool you install that adds that rich
logging. My rules query the events Sysmon produces. No telemetry, no detection.

## Repo layout

```
rules/                  Sigma rules, grouped by ATT&CK tactic
  execution/
  credential-access/
  persistence/
docs/                   notes, including false-positive analysis per rule
.github/workflows/      CI pipeline (pySigma lint + tests) — added later
```

## False positives

Every rule here gets a note in `docs/` about why it might fire on benign activity.
A rule that screams on normal admin work is worse than useless — analysts learn to
ignore it (alert fatigue) and real attacks slip through. Documenting and tuning for
false positives is half the job, so I'm treating it as a first-class part of each
rule, not an afterthought.

## Roadmap

- [x] Repo structure + README
- [ ] Hand-write and document the three rules
- [ ] False-positive notes for each
- [ ] Validate rules locally with pySigma
- [ ] Sysmon + Atomic Red Team lab to test detections
- [ ] GitHub Actions CI to lint and test the rules automatically

## Tools / references

- Sigma + pySigma — https://github.com/SigmaHQ/sigma
- MITRE ATT&CK — https://attack.mitre.org
- Sysmon (Sysinternals) — https://learn.microsoft.com/sysinternals/downloads/sysmon
- Atomic Red Team — https://github.com/redcanaryco/atomic-red-team
