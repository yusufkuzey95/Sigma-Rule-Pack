# Detection note: LSASS Memory Access with Read Rights

- **Rule file:** [`rules/credential-access/lsass_memory_access.yml`](../rules/credential-access/lsass_memory_access.yml)
- **ATT&CK:** [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) (Tactic: Credential Access)
- **Severity:** critical · **Status:** experimental

## What it detects

Fires when a process opens a handle to `lsass.exe` (`TargetImage`) with a `GrantedAccess`
mask that includes the rights needed to **read another process's memory**. This is the
core action behind OS credential dumping (e.g. Mimikatz, procdump against LSASS). It uses
Sysmon **Event ID 10 (process access)**, not process creation — the attack is about
reaching into memory, not about a command line.

## Why it matters

LSASS holds users' credentials (passwords/hashes) in memory while they are logged in. An
attacker who reads LSASS memory can scrape those credentials and use them to move to other
systems (lateral movement). Credential dumping usually means an attacker is already on the
host and trying to expand access — which is why this rule is rated critical.

## False positives

Legitimate software does read LSASS memory:

- Antivirus / EDR products, which constantly inspect process memory (including LSASS) for
  threats. This is the most common benign trigger.
- Some backup, monitoring, or system-management tools that read process memory.

### How an analyst tells benign from malicious

The decisive field is **`SourceImage`** — the process doing the accessing:

- **Recognized security product** (e.g. `MsMpEng.exe` / Windows Defender, or the EDR agent)
  running from its normal signed install path under `C:\Program Files\...` → almost
  certainly benign; it is doing its job.
- **Unexpected or suspicious process** — an unknown `.exe`, something running from a temp or
  download folder, a renamed or unsigned binary, or a known dumping tool
  (`mimikatz`, `procdump`) → has no business reading LSASS memory. Investigate hard.

So the question is not "automated vs. human" (LSASS access is always program-driven) but
"is `SourceImage` a legitimate security tool, or a process that should never touch LSASS?"

### Tuning ideas

- Exclude the specific AV/EDR `SourceImage` paths in use with a `filter` and
  `condition: selection and not filter`.
- Keep the exclusions tight (match on the full signed path), so an attacker can't dodge the
  rule just by naming their tool `MsMpEng.exe`.

## Known limitations (false negatives)

- The `GrantedAccess` list covers common memory-read masks, but a tool could request a
  different mask that still allows reading memory and slip past. The list may need to grow
  as new tooling appears.
- Attackers can dump LSASS *without* directly opening its memory — e.g. by creating a memory
  dump file via other Windows features, or abusing a signed tool. Those techniques would not
  trigger this specific rule and need their own detections.
