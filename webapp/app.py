"""
Small Flask dashboard for the rule pack. Reads the rules in rules/, converts each one to a
Splunk query with pySigma, and shows it next to its test result.

Run it:  python webapp/app.py  ->  http://127.0.0.1:5000  (dev server, local use only)
"""

import glob
import os

import yaml
from flask import Flask, render_template

from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_audit_pipeline

BASE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(BASE, "..", "rules")

app = Flask(__name__)

TACTIC_NAMES = {
    "execution": "Execution",
    "credential-access": "Credential Access",
    "persistence": "Persistence",
    "initial-access": "Initial Access",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "lateral-movement": "Lateral Movement",
}

# test results from docs/testing.md
TEST_RESULTS = {
    "powershell_encoded_command.yml": {
        "status": "pass",
        "label": "Passed (+ documented blind spot)",
        "detail": "Fired on a real -EncodedCommand process-creation event (Sysmon EID 1); "
        "correctly missed the abbreviated -e form, matching the rule's documented "
        "false-negative.",
    },
    "lsass_memory_access.yml": {
        "status": "pass",
        "label": "Passed",
        "detail": "Fired on 3 real public attack samples (mimikatz sekurlsa, LSASS memdump, "
        "babyshark).",
    },
    "guest_account_logon.yml": {
        "status": "pass",
        "label": "Passed",
        "detail": "Fired on a real failed Guest logon (Security EID 4625) generated on a lab host.",
    },
}


def technique_url(tid):
    """T1059.001 -> https://attack.mitre.org/techniques/T1059/001/"""
    if "." in tid:
        main, sub = tid.split(".", 1)
        return f"https://attack.mitre.org/techniques/{main}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tid}/"


def pipeline_for(logsource):
    # security-log rules need the windows pipeline, sysmon rules need the sysmon one
    if (logsource or {}).get("service") == "security":
        return windows_audit_pipeline
    return sysmon_pipeline


def convert_to_splunk(path, logsource):
    try:
        coll = SigmaCollection.from_yaml(open(path, encoding="utf-8").read())
        backend = SplunkBackend(processing_pipeline=pipeline_for(logsource)())
        return backend.convert(coll)[0]
    except Exception as exc:  # don't let one broken rule take down the whole page
        return f"(conversion error: {exc})"


def load_rules():
    rules = []
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "**", "*.yml"), recursive=True)):
        data = yaml.safe_load(open(path, encoding="utf-8").read())
        # tags look like attack.execution or attack.t1059.001 - split tactics from techniques
        tactics, techniques = [], []
        for tag in data.get("tags", []):
            name = tag.split(".", 1)[1] if tag.startswith("attack.") else tag
            if name.startswith("t") and name[1:2].isdigit():
                techniques.append({"id": name.upper(), "url": technique_url(name.upper())})
            else:
                tactics.append(TACTIC_NAMES.get(name, name.title()))
        fname = os.path.basename(path)
        rules.append(
            {
                "file": fname,
                "title": data.get("title"),
                "level": (data.get("level") or "medium").lower(),
                "status": data.get("status"),
                "description": " ".join((data.get("description") or "").split()),
                "tactics": tactics,
                "techniques": techniques,
                "logsource": data.get("logsource", {}),
                "detection_yaml": yaml.safe_dump(
                    data.get("detection", {}), sort_keys=False
                ).strip(),
                "falsepositives": data.get("falsepositives", []),
                "splunk": convert_to_splunk(path, data.get("logsource", {})),
                "test": TEST_RESULTS.get(fname),
            }
        )
    return rules


@app.route("/")
def index():
    rules = load_rules()
    summary = {
        "rules": len(rules),
        "tactics": len({t for r in rules for t in r["tactics"]}),
        "tested": sum(1 for r in rules if r["test"] and r["test"]["status"] == "pass"),
    }
    return render_template("index.html", rules=rules, summary=summary)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
