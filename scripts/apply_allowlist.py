#!/usr/bin/env python3
"""Copy the values in allowlist.yaml into the Sigma rules.

The rules in rules/ ship with placeholder addresses so they validate on their own.
This script writes ready-to-deploy copies to build/rules/ with your real values,
so the alerts always match what Terraform puts in the firewall.

    python3 scripts/apply_allowlist.py
    sigma check build/rules/
    sigma convert -t <your-siem> -p pipelines/gcp_firewall.yml build/rules/

Detection items are matched by name:
    filter_allowlist         -> vpn_ranges + office_ips + bastion_ips
    selection_iot_segment    -> iot.subnet
    filter_iot_allowed       -> iot.allowed_destinations
    selection_decoy          -> decoy.ip
and when decoy.ignore_sources is not empty, the decoy rules get an extra filter.
"""

from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
BUILD = ROOT / "build" / "rules"


def load_allowlist() -> dict:
    data = yaml.safe_load((ROOT / "allowlist.yaml").read_text())
    admin_sources = (
        (data.get("vpn_ranges") or [])
        + (data.get("office_ips") or [])
        + (data.get("bastion_ips") or [])
    )
    if not admin_sources:
        sys.exit("allowlist.yaml: vpn_ranges, office_ips and bastion_ips are all empty")
    return {
        "admin_sources": admin_sources,
        "iot_subnet": data["iot"]["subnet"],
        "iot_allowed": data["iot"]["allowed_destinations"],
        "decoy_ip": data["decoy"]["ip"],
        "decoy_ignore": data["decoy"].get("ignore_sources") or [],
    }


def replace_value(item: dict, value) -> None:
    """Swap the value of the single field inside a detection item, keeping its modifiers."""
    (field,) = item.keys()
    item[field] = value


def apply(rule: dict, allow: dict) -> dict:
    detection = rule.get("detection")
    if not detection:  # correlation rules have no detection block
        return rule

    if "filter_allowlist" in detection:
        replace_value(detection["filter_allowlist"], allow["admin_sources"])
    if "selection_iot_segment" in detection:
        replace_value(detection["selection_iot_segment"], allow["iot_subnet"])
    if "filter_iot_allowed" in detection:
        replace_value(detection["filter_iot_allowed"], allow["iot_allowed"])
    if "selection_decoy" in detection:
        replace_value(detection["selection_decoy"], allow["decoy_ip"])
        # Approved scanners only matter for connections TO the decoy (rules 14 and 15).
        (field,) = detection["selection_decoy"].keys()
        if allow["decoy_ignore"] and field.startswith("dst_ip"):
            detection["filter_decoy_known_scanners"] = {"src_ip|cidr": allow["decoy_ignore"]}
            detection["condition"] = (
                f"({detection['condition']}) and not filter_decoy_known_scanners"
            )
    return rule


def main() -> None:
    allow = load_allowlist()
    BUILD.mkdir(parents=True, exist_ok=True)
    for path in sorted(RULES.glob("*.yml")):
        rule = yaml.safe_load(path.read_text())
        out = BUILD / path.name
        out.write_text(yaml.safe_dump(apply(rule, allow), sort_keys=False, allow_unicode=True))
        print(f"wrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
