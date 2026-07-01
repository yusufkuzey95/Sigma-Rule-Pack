# Detection note: Authentication Activity Involving the Built-in Guest Account

- **Rule file:** [`rules/persistence/guest_account_logon.yml`](../rules/persistence/guest_account_logon.yml)
- **ATT&CK:** [T1078.001 — Valid Accounts: Default Accounts](https://attack.mitre.org/techniques/T1078/001/) (Tactics tagged: Persistence, Initial Access. T1078 as a technique also spans Privilege Escalation and Defense Evasion, but this detection is scoped to the two tactics it actually serves.)
- **Severity:** high · **Status:** experimental

## What it detects

Fires on **any authentication involving the built-in Guest account** — a successful logon
(Windows Security **Event ID 4624**) *or* a failed one (**Event ID 4625**) where
`TargetUserName` is `Guest`. This rule reads the **Windows Security log**, not Sysmon —
authentication events come from Windows auditing.

> **Design note:** the rule originally targeted only successful logons (4624). During
> testing I found that modern Windows blocks the Guest account from interactive logon by
> default (it lacks the logon right), so a real *successful* Guest logon is hard to produce
> — but the *attempt* still generates a 4625. Catching both success and failure is actually
> a stronger detection: it also flags an attacker **probing** the dormant Guest account,
> which is often the earlier warning sign.

## Why it matters

T1078 (Valid Accounts) is hard to detect because the attacker uses **legitimate
credentials** and simply logs in — there is no malware or malformed artifact to match on.
The Guest account is a useful exception: it is disabled by default and should *never* be
used, so *any* authentication activity involving it — success or failure — is abnormal on
its own, with no per-user baseline needed. It can indicate an attacker reusing or probing a
valid-but-dormant account.

## False positives

- IT staff deliberately testing or auditing the Guest account.
- Lab, kiosk, training, or test environments that intentionally enable Guest logons.
- Automated scanners or misconfigured software repeatedly hitting the Guest account (these
  show up as repeated 4625 failures).

Note: a low-skill person guessing their way into Guest is **not** a false positive — that
is unauthorized access the rule correctly caught. A false positive means the activity was
benign/authorized, not merely unsophisticated.

### How an analyst investigates

`TargetUserName` (Guest) is already known from the alert. The fields that add value are:

- **`EventID`** — `4624` (it *succeeded* — investigate urgently) vs `4625` (it *failed* —
  probing; check whether it is repeating).
- **`LogonType`** — *how*: `2` = interactive, `3` = network, `10` = RemoteInteractive (RDP).
  A network or RDP Guest attempt is more concerning than a local one.
- **`IpAddress`** — *where from*: internal is less alarming than an unknown/external IP.
- **`Status` / `SubStatus`** (on 4625) — *why it failed* (e.g. `0xC000015B` = logon type not
  granted, `0xC0000072` = account disabled).

Also worth checking: was the Guest account recently enabled (look for the account-management
events that precede the activity)? An attacker often has to enable Guest before using it.

## Testing

Validated against real telemetry (see [`docs/testing.md`](testing.md)): a genuine `4625`
Guest-logon-failure event was generated on a lab host and the rule fired on it. A `4624`
success path is covered by the same rule but was not reproducible on the test host because
Windows denies Guest interactive logon by default.

## Known limitations (false negatives) and scope

- This rule only catches the **Guest** account. The broader T1078 problem — stolen normal
  user/admin credentials being used to log in — looks identical to legitimate activity and
  **cannot** be caught by a static rule like this one. Those cases need anomaly/behavioral
  detection (impossible travel, unusual hours, new-location logins), which requires a
  baseline of each user's normal behavior (UEBA) or correlation rules — beyond a single
  static Sigma rule.
- Future related rules to consider: interactive logons by service accounts, and
  password-spray detection (many 4625 failures across accounts), which needs
  counting/aggregation.
