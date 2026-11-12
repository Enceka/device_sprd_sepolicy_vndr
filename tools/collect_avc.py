#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
"""Read connected-device SELinux logs, or summarize an existing capture."""

import argparse
import collections
import datetime
import json
import re
import subprocess
from pathlib import Path


AVC = re.compile(r"avc:\s+denied\s+\{([^}]+)\}.*?scontext=(\S+)\s+tcontext=(\S+)\s+tclass=(\S+)")
AUDIT = re.compile(r"audit\([^:()]*:(\d+)\)")
LABEL = re.compile(r"File (\S+) .*incorrect label or no domain transition")


def summarize(directory):
    seen = set()
    groups = collections.Counter()
    samples = collections.defaultdict(set)
    errors = collections.Counter()
    sources = {}
    for name in ("dmesg.txt", "logcat-all.txt"):
        path = directory / name
        if not path.is_file():
            continue
        lines = path.read_text(errors="replace").splitlines()
        denied = [line for line in lines if re.search(r"avc:\s+denied", line)]
        sources[name] = {"lines": len(lines), "avc_lines": len(denied)}
        (directory / f"{path.stem}-avc.txt").write_text("\n".join(denied) + "\n")
        for line in lines:
            label = LABEL.search(line)
            if label:
                errors[label[1]] += 1
        for line in denied:
            match = AVC.search(line)
            if not match:
                continue
            permissions = tuple(sorted(match[1].split()))
            key = (match[2], match[3], match[4], permissions)
            audit = AUDIT.search(line)
            # Same-boot kernel events and auditd carry the same audit serial;
            # auditd replaces the timestamp with 0.0. Inputs must be one boot.
            # Without an ID keep every line; similarity is not proof of duplication.
            identity = (audit[1], key) if audit else None
            if identity is not None:
                if identity in seen:
                    continue
                seen.add(identity)
            groups[key] += 1
            sample = " ".join(re.findall(r'(?:comm|path|name)="[^"]*"', line))
            if sample and len(samples[key]) < 4:
                samples[key].add(sample)
    rows = [{"count": count, "source": key[0], "target": key[1], "class": key[2],
             "permissions": list(key[3]), "samples": sorted(samples[key])}
            for key, count in groups.most_common()]
    report = {"sources": sources, "unique_avc_events": sum(groups.values()),
              "signatures": len(groups), "denials": rows,
              "missing_domain_transitions": dict(sorted(errors.items()))}
    (directory / "summary.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    md = ["# SELinux capture", "", "Same-boot audit serials are deduplicated across dmesg and logcat.",
          "Records without an audit serial are retained individually.", ""]
    for name, counts in sources.items():
        md.append(f"- {name}: {counts['avc_lines']} AVC lines / {counts['lines']} total lines")
    md.extend([f"- Unique parsed AVC events: {report['unique_avc_events']}",
               f"- Distinct permission signatures: {len(groups)}",
               f"- Executables missing an init domain transition: {len(errors)}", "",
               "## Most frequent denials", "",
               "| Events | Source | Target | Class | Permissions |",
               "| ---: | --- | --- | --- | --- |"])
    for row in rows[:40]:
        source = row["source"].split(":")[2]
        target = row["target"].split(":")[2]
        md.append(f"| {row['count']} | {source} | {target} | {row['class']} | {' '.join(row['permissions'])} |")
    md.extend(["", "## Missing domain transitions", ""])
    md.extend(f"- `{path}`" for path in sorted(errors))
    md.extend(["", "This report is evidence for policy review; it does not generate allow rules.", ""])
    (directory / "summary.md").write_text("\n".join(md))
    print(json.dumps({key: value for key, value in report.items() if key != "denials"}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", help="ADB serial; otherwise exactly one device must be connected")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summarize-only", action="store_true", help="read saved logs without accessing ADB")
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if not args.summarize_only:
        serial = args.serial
        if not serial:
            listing = subprocess.run(["adb", "devices"], capture_output=True, text=True,
                                     check=True, timeout=15).stdout
            devices = [line.split()[0] for line in listing.splitlines()[1:]
                       if len(line.split()) >= 2 and line.split()[1] == "device"]
            if len(devices) != 1:
                parser.error("Expected one connected device; specify --serial")
            serial = devices[0]
        commands = {
            "metadata.txt": "id; getenforce; getprop ro.build.version.release; getprop ro.build.type; "
                            "getprop ro.board.platform; getprop ro.boot.selinux; cat /proc/uptime",
            "logcat-all.txt": "logcat -b all -d -v threadtime",
            "dmesg.txt": "dmesg",
            "processes.txt": "ps -AZ",
        }
        status = {"captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "commands": {}}
        for name, command in commands.items():
            result = subprocess.run(["adb", "-s", serial, "shell", command],
                                    capture_output=True, timeout=45)
            (directory / name).write_bytes(result.stdout)
            (directory / f"{name}.stderr").write_bytes(result.stderr)
            status["commands"][name] = result.returncode
        (directory / "capture.json").write_text(json.dumps(status, indent=2) + "\n")
        if all(status["commands"][name] != 0 for name in ("logcat-all.txt", "dmesg.txt")):
            raise SystemExit("Both log sources failed; see saved stderr files")
    summarize(directory)


if __name__ == "__main__":
    main()
