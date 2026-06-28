# Detection note: Successful Logon Using the Built-in Guest Account

- **Rule file:** [`rules/persistence/guest_account_logon.yml`](../rules/persistence/guest_account_logon.yml)
- **ATT&CK:** [T1078.001 — Valid Accounts: Default Accounts](https://attack.mitre.org/techniques/T1078/001/) (Tactics: Initial Access, Persistence, Privilege Escalation, Defense Evasion)
- **Severity:** high · **Status:** experimental

## What it detects

Fires on a successful logon (Windows Security **Event ID 4624**) where `TargetUserName` is
`Guest`. This rule reads the **Windows Security log**, not Sysmon — authentication events
come from Windows auditing.

## Why it matters

T1078 (Valid Accounts) is hard to detect because the attacker uses **legitimate
credentials** and simply logs in — there is no malware or malformed artifact to match on.
The Guest account is a useful exception: it is disabled by default and should *never* log
on, so a *successful* Guest logon is abnormal on its own, with no per-user baseline needed.
It can indicate an attacker reusing a valid-but-dormant account.

## False positives

- IT staff deliberately testing or auditing the Guest account.
- Lab, kiosk, training, or test environments that intentionally enable Guest logons.

Note: a low-skill person guessing their way into Guest is **not** a false positive — that
is unauthorized access the rule correctly caught. A false positive means the activity was
benign/authorized, not merely unsophisticated.

### How an analyst investigates

`TargetUserName` (Guest) is already known from the alert. The fields that add value are:

- **`LogonType`** — *how* they logged on: `2` = interactive (at the keyboard), `3` =
  network, `10` = RemoteInteractive (RDP). A network or RDP Guest logon is far more
  concerning than a local interactive one.
- **`IpAddress`** — *where from*: an internal address is less alarming than an unknown or
  external IP.

Also worth checking: was the Guest account recently enabled (look for the account-management
events that precede the logon)? An attacker often has to enable Guest before using it.

## Known limitations (false negatives) and scope

- This rule only catches the **Guest** account. The broader T1078 problem — stolen normal
  user/admin credentials being used to log in — looks identical to legitimate activity and
  **cannot** be caught by a static rule like this one. Those cases need anomaly/behavioral
  detection (impossible travel, unusual hours, logins from new locations), which requires a
  baseline of each user's normal behavior (UEBA) or correlation rules — beyond a single
  static Sigma rule.
- Future related rules to consider: interactive logons by service accounts, and
  password-spray detection (many 4625 failures), which needs counting/aggregation.
