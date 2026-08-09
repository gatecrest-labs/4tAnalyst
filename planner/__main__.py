"""
Standalone CLI for the deterministic change planner.

    python -m planner --src 10.1.2.3 --dst 10.9.8.7 --service tcp/8443 \
        --firewall MNHQ-FW01:OT-ADOM [--firewall X:Y ...] \
        [--ticket CHG0012345] [--justification "..."] \
        [--outdir output/] [--json-only]

Runs the same engine the MCP tool exposes — no LLM anywhere in this path.
Exit codes: 0 success, 2 data-source failure (message names the source).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from planner.engine import plan_change, to_report_payload
from planner.models import PlannerDataError, TargetFirewall

_REPO_ROOT = Path(__file__).parent.parent


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m planner", description=__doc__)
    parser.add_argument("--src", required=True,
                        help="Source IP(s)/CIDR(s), comma-separated for a consolidated rule")
    parser.add_argument("--dst", required=True,
                        help="Destination IP(s)/CIDR(s), comma-separated for a consolidated rule")
    parser.add_argument("--service", required=True,
                        help="Port, proto/port, or well-known name; comma-separated "
                             "for multiple (443, tcp/8443, ssh)")
    parser.add_argument("--src-group", default="",
                        help="Name for a source address group (forces grouping)")
    parser.add_argument("--dst-group", default="",
                        help="Name for a destination address group (forces grouping)")
    parser.add_argument("--firewall", action="append", required=True,
                        dest="firewalls", metavar="DEVICE:ADOM",
                        help="Target firewall as DEVICE:ADOM (repeatable)")
    parser.add_argument("--ticket", default="", help="Change ticket ID")
    parser.add_argument("--justification", default="", help="Business justification")
    parser.add_argument("--outdir", default=str(_REPO_ROOT / "output"),
                        help="Directory for report.html/implementation.conf")
    parser.add_argument("--json-only", action="store_true",
                        help="Print the payload JSON; skip HTML/conf rendering")
    args = parser.parse_args(argv)

    targets = []
    for raw in args.firewalls:
        device, sep, adom = raw.partition(":")
        if not sep or not device or not adom:
            parser.error(f"--firewall must be DEVICE:ADOM, got {raw!r}")
        targets.append(TargetFirewall(device=device, adom=adom))
    args.targets = targets
    return args


def _summary(plan) -> str:
    lines = [
        f"Verdict     : {plan.zone_verdict.get('verdict')} "
        f"({', '.join(plan.zone_verdict.get('src_zones', [])) or '?'} -> "
        f"{', '.join(plan.zone_verdict.get('dst_zones', [])) or '?'})",
        f"Plan status : {plan.cli_status}   Risk: {plan.risk_level}",
    ]
    for fw in plan.firewalls:
        lines.append(f"  {fw.firewall}: {fw.status}")
        if fw.insertion:
            lines.append(f"    placement: {fw.insertion.rationale}")
    for w in plan.warnings:
        lines.append(f"  WARNING: {w}")
    lines.append(f"Recommendation: {plan.recommendation}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        plan = plan_change(
            src=args.src, dst=args.dst, service=args.service,
            firewalls=args.targets, justification=args.justification,
            ticket_id=args.ticket,
            src_group=args.src_group, dst_group=args.dst_group,
        )
    except PlannerDataError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    payload = to_report_payload(plan)

    if args.json_only:
        print(json.dumps(payload, indent=2, default=str))
        return 0

    sys.path.insert(0, str(_REPO_ROOT / "scripts"))
    import render_report

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        json.dump(payload, tmp, default=str)
        tmp_path = tmp.name
    rc = render_report.main(["--data", tmp_path, "--outdir", args.outdir])
    if rc != 0:
        return rc

    print()
    print(_summary(plan))
    return 0


if __name__ == "__main__":
    sys.exit(main())
