#!/usr/bin/env python3
"""Pipeline stage runner — deterministic half of the hybrid pipeline.

Usage:
    python run_stage.py ioc    --mode mock      # IOC enrichment
    python run_stage.py triage --mode mock      # log/EVTX triage
    python run_stage.py siem   --mode mock      # SIEM alert digest

Fetches → transforms → writes staging/<stage>-<UTC>.json, then prints the path
on the last stdout line so the Claude-native slash command can read it.

Live mode (--mode live) reuses the same code path; fetchers that need creds/an
endpoint raise NotImplementedError until wired.
"""
import argparse
import sys

import emit
from enrichers import enrich_ioc
from fetchers import ioc_feed, log_source, siem_feed

# Deterministic keyword -> ATT&CK technique hints. Claude refines the narrative;
# this just gives the triage note a first-pass mapping to anchor analysis.
_ATTACK_HINTS = [
    ("frombase64string", "T1027 Obfuscated/Encoded"),
    ("-enc", "T1059.001 PowerShell"),
    ("downloadstring", "T1059.001 PowerShell / T1105 Ingress Tool Transfer"),
    ("iex ", "T1059.001 PowerShell"),
    ("new-object net.webclient", "T1105 Ingress Tool Transfer"),
    ("service installed", "T1543.003 Windows Service"),
    ("eventcode=7045", "T1543.003 Windows Service"),
    ("kerberos service ticket", "T1558.003 Kerberoasting"),
    ("encryption 0x17", "T1558.003 Kerberoasting (RC4)"),
    ("4769", "T1558.003 Kerberoasting"),
    ("logon type 3", "T1021 Remote Services"),
    ("4625", "T1110 Brute Force"),
    ("failed logon", "T1110 Brute Force"),
]

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _map_techniques(text: str) -> list[str]:
    low = text.lower()
    hits = [tech for kw, tech in _ATTACK_HINTS if kw in low]
    # dedupe, preserve order
    seen = set()
    out = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def run_ioc(mode: str) -> tuple[list[dict], dict]:
    live = mode == "live"
    feed = ioc_feed.fetch(mode)
    records = []
    for item in feed:
        rec = enrich_ioc(item["ioc"], live=live)
        rec["feed_source"] = item.get("source", "")
        records.append(rec)
    dispositions = {}
    for r in records:
        dispositions[r["disposition"]] = dispositions.get(r["disposition"], 0) + 1
    worst = "BLOCK" if dispositions.get("BLOCK") else (
        "MONITOR" if dispositions.get("MONITOR") else "INVESTIGATE")
    meta = {"dispositions": dispositions, "verdict": worst}
    return records, meta


def run_triage(mode: str) -> tuple[list[dict], dict]:
    events = log_source.fetch(mode)
    techniques = set()
    for ev in events:
        ev["techniques"] = _map_techniques(ev.get("message", ""))
        techniques.update(ev["techniques"])
    hosts = sorted({ev.get("host", "") for ev in events if ev.get("host")})
    severity = "high" if techniques else "low"
    meta = {
        "techniques": sorted(techniques),
        "hosts": hosts,
        "severity": severity,
        "event_count": len(events),
    }
    return events, meta


def run_siem(mode: str) -> tuple[list[dict], dict]:
    alerts = siem_feed.fetch(mode)
    by_severity = {}
    by_rule = {}
    for a in alerts:
        sev = a.get("severity", "low")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_rule[a["rule"]] = by_rule.get(a["rule"], 0) + 1
    top_severity = max(
        (a.get("severity", "low") for a in alerts),
        key=lambda s: _SEVERITY_RANK.get(s, 0),
        default="low",
    )
    meta = {
        "by_severity": by_severity,
        "by_rule": by_rule,
        "result_count": len(alerts),
        "top_severity": top_severity,
    }
    return alerts, meta


_STAGES = {"ioc": run_ioc, "triage": run_triage, "siem": run_siem}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="OpenElia pipeline stage runner")
    parser.add_argument("stage", choices=sorted(_STAGES))
    parser.add_argument("--mode", choices=["mock", "live"], default="mock")
    args = parser.parse_args(argv)

    records, meta = _STAGES[args.stage](args.mode)
    path = emit.write(args.stage, records, args.mode, meta=meta)

    print(f"stage={args.stage} mode={args.mode} count={len(records)} "
          f"meta={meta}", file=sys.stderr)
    # Last stdout line = staging path (contract with slash commands)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
