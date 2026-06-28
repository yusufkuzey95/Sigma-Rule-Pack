# Detection note: PowerShell Encoded Command Execution

- **Rule file:** [`rules/execution/powershell_encoded_command.yml`](../rules/execution/powershell_encoded_command.yml)
- **ATT&CK:** [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) (Tactic: Execution)
- **Severity:** medium · **Status:** experimental

## What it detects

Fires when a process ending in `powershell.exe` runs with a command line containing
`-enc` — the `-EncodedCommand` flag, which takes a base64-encoded command instead of
plain text.

## Why it matters

Attackers use `-EncodedCommand` to **obfuscate** what PowerShell is doing. Encoding the
command hides keywords (download cradles, `Invoke-Mimikatz`, etc.) from casual log review
and from simple keyword-based detections. Seeing encoded PowerShell isn't proof of an
attack, but it's a strong signal worth a human look, because legitimate users rarely type
encoded commands by hand.

## False positives

Encoded PowerShell is also produced by legitimate automation, because management tools
generate encoded commands programmatically:

- Enterprise management / RMM tools (SCCM, Microsoft Intune, monitoring agents).
- Software installers that wrap PowerShell steps.
- In-house scheduled tasks and admin automation scripts.

### How an analyst tells benign from malicious

1. **Decode the encoded blob first — this is the most valuable step.** The base64 string
   after `-enc` decodes back into the actual command PowerShell ran. That decoded command
   *is the evidence*: benign automation decodes to mundane config/registry work, while
   malware decodes to obvious badness (a `DownloadString` cradle, `Invoke-Mimikatz`, a
   reverse shell). Decoding reveals **what the command actually does** — direct evidence,
   not circumstantial.
2. **Check `ParentImage` — what launched PowerShell?** A document or mail app
   (`WINWORD.EXE`, `outlook.exe`) or a browser spawning encoded PowerShell is highly
   suspicious. A known management service launching it is more likely benign automation.
3. **Check `User`** — a service account that routinely runs automation leans benign; a
   regular human user or an unexpected account leans malicious.

Parent process and user are supporting context; the decoded command is the decisive clue.

### Tuning ideas (once we baseline the environment)

- Exclude known-good parents (e.g. the SCCM/Intune agent paths) with a `filter` and
  `condition: selection and not filter`.
- Exclude specific service accounts that legitimately run encoded automation.
- Promote to `high` once false positives are understood and filtered.

## Known limitations (false negatives)

PowerShell accepts **abbreviated** flags: `-e`, `-en`, `-enco`, etc. all work the same as
`-enc`. Because this rule matches `CommandLine|contains: '-enc'`, an attacker using
`powershell -e <base64>` would **slip past it** — a false negative. A more robust version
would also match the shorter abbreviations (e.g. `-e`/`-en`), while being careful that
short strings like `-e` don't introduce new false positives (they appear in many benign
flags). This is a planned improvement during the tuning/testing phase.
