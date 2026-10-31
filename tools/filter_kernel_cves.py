"""Filter kernel CVE candidates using what this firmware actually compiles.

A candidate only leaves the review list on positive evidence: the Linux CNA lists the
version as fixed, or every affected source file exists in the tree and is not compiled.

    python -I tools/filter_kernel_cves.py <cves.json> <kernel-files.json> <records_dir> <output.json>
"""
import json
import posixpath
import re
import sys
from pathlib import Path

WIRELESS_PREFIXES = ("net/mac80211/", "net/wireless/", "drivers/net/wireless/", "include/net/mac80211.h",
                     "include/net/cfg80211.h", "include/uapi/linux/nl80211.h")
# Wi-Fi drivers OpenWrt builds from their own trees, outside backports.
DRIVER_FORKS = {"ath10k-ct": "drivers/net/wireless/ath/ath10k/", "mt76": "drivers/net/wireless/mediatek/mt76/"}
SOURCE_SUFFIXES = (".c", ".h", ".S", ".s")
ACTIVE = ("builtin", "image_module", "header", "wireless_backport")
REVIEW = ("shared_header", "driver_fork", "path_unverified", "no_file_data", "not_linux_cna")


def parse_version(text):
    numbers = re.findall(r"\d+", text.split("-")[0])
    return tuple(int(n) for n in numbers[:3]) + (0,) * (3 - len(numbers[:3]))


def in_range(version, entry):
    start = parse_version(entry["version"])
    if version < start:
        return False
    if "lessThan" in entry:
        return version < parse_version(entry["lessThan"])
    upper = entry.get("lessThanOrEqual")
    if upper is None:
        return version == start
    if upper == "*":
        return True
    if upper.endswith(".*"):
        return version[:2] == parse_version(upper[:-2])[:2]
    return version <= parse_version(upper)


def version_status(record, release):
    """'affected', 'unaffected' or 'unknown' for a version, per the Linux CNA data."""
    version = parse_version(release)
    statuses, known = [], False
    for block in record["containers"]["cna"].get("affected", []):
        if block.get("vendor") != "Linux":
            continue
        entries = [v for v in block.get("versions", []) if v.get("versionType") != "git"]
        if not entries:
            continue
        known = True
        matched = [v["status"] for v in entries if in_range(version, v)]
        statuses.append("unaffected" if "unaffected" in matched else
                        "affected" if "affected" in matched else block.get("defaultStatus", "unknown"))
    if not known:
        return "unknown"
    return "affected" if "affected" in statuses else "unaffected" if "unaffected" in statuses else "unknown"


def affected_files(record):
    files = set()
    for block in record["containers"]["cna"].get("affected", []):
        files.update(block.get("programFiles") or [])
    return sorted(files)


def build_index(inventory):
    """File -> where it is compiled, across vmlinux and every module."""
    index = {"builtin": set(), "builtin_header": set(), "image": {}, "image_header": {}, "optional": {},
             "backports": set(), "forks": {}}
    vmlinux = inventory["vmlinux"]
    index["builtin"].update(vmlinux["units"].get("kernel", []))
    index["builtin_header"].update(vmlinux["headers"].get("kernel", []))
    for name, module in inventory["modules"].items():
        for origin, files in module["units"].items():
            for path in files:
                if not module["in_image"]:
                    if origin == "kernel":
                        index["optional"].setdefault(path, name)
                elif origin == "kernel":
                    index["image"].setdefault(path, name)
                elif origin == "backports":
                    index["backports"].add(path)
                else:
                    index["forks"].setdefault(origin, set()).add(path)
        if module["in_image"]:
            for path in module["headers"].get("kernel", []):
                index["image_header"].setdefault(path, name)
            index["backports"].update(module["headers"].get("backports", []))
            for origin in DRIVER_FORKS:
                if origin in module["headers"]:
                    index["forks"].setdefault(origin, set()).update(module["headers"][origin])
    index["dirs"] = {posixpath.dirname(path) for path in (*index["builtin"], *index["image"])}
    return index


def classify(record, index, tree, kernel_version, backports_version):
    cna = record["containers"]["cna"]
    if record["cveMetadata"].get("assignerShortName") != "Linux":
        return {"category": "not_linux_cna", "files": [], "where": ""}
    files = [f for f in affected_files(record) if f.endswith(SOURCE_SUFFIXES)]
    if not files:
        return {"category": "no_file_data", "files": [], "where": ""}

    wireless = [f for f in files if f.startswith(WIRELESS_PREFIXES)]
    other = [f for f in files if not f.startswith(WIRELESS_PREFIXES)]

    if wireless and not other:
        for origin, built in index["forks"].items():
            if all(f.startswith(DRIVER_FORKS[origin]) for f in wireless) and built.intersection(wireless):
                return {"category": "driver_fork", "files": files, "where": origin}
        compiled = [f for f in wireless if f in index["backports"]]
        if not compiled:
            return {"category": "not_compiled", "files": files, "where": "wireless"}
        if version_status(record, backports_version) == "unaffected":
            return {"category": "fixed_in_version", "files": files, "where": f"backports {backports_version}"}
        return {"category": "wireless_backport", "files": files, "where": f"backports {backports_version}: {compiled[0]}"}

    if version_status(record, kernel_version) == "unaffected":
        return {"category": "fixed_in_version", "files": files, "where": f"kernel {kernel_version}"}

    sources = [f for f in other if not f.endswith(".h")]
    for path in sources:
        if path in index["builtin"]:
            return {"category": "builtin", "files": files, "where": path}
    for path in sources:
        if path in index["image"]:
            return {"category": "image_module", "files": files, "where": f"{index['image'][path]}: {path}"}
    for path in sources:
        if path in index["optional"]:
            return {"category": "optional_module", "files": files, "where": f"{index['optional'][path]}: {path}"}
    # A shared header proves little when the fix's own sources are not compiled.
    header_category = "shared_header" if sources else "header"
    for path in other:
        if path in index["builtin_header"]:
            return {"category": header_category, "files": files, "where": path}
        if path in index["image_header"]:
            return {"category": header_category, "files": files, "where": f"{index['image_header'][path]}: {path}"}
    if any(f not in tree for f in other):
        return {"category": "path_unverified", "files": files, "where": ""}
    # A macro-only header leaves no trace in DWARF, so its absence proves nothing next to compiled code.
    if not sources and any(f.startswith("include/") or posixpath.dirname(f) in index["dirs"] for f in other):
        return {"category": "path_unverified", "files": files, "where": ""}
    return {"category": "not_compiled", "files": files, "where": ""}


def filter_candidates(cves, inventory, records_dir):
    kernel = cves["kernel"]
    index = build_index(inventory)
    tree = set(inventory["tree_paths"])
    backports_version = inventory["backports_version"][0]
    results, tally = [], {}
    for cve in kernel["ids"]:
        record = json.loads((records_dir / f"{cve}.json").read_text(encoding="utf-8"))
        entry = {"cve": cve, **classify(record, index, tree, kernel["version"], backports_version)}
        entry.update(kernel["nvd"].get(cve, {"score": None, "severity": None, "published": ""}))
        descriptions = record["containers"]["cna"].get("descriptions") or [{}]
        lines = [l for l in descriptions[0].get("value", "").splitlines() if l.strip()]
        entry["title"] = (lines[1] if len(lines) > 1 and lines[0].startswith("In the Linux kernel") else lines[0] if lines else "")[:120]
        results.append(entry)
        tally[entry["category"]] = tally.get(entry["category"], 0) + 1
    active = [e for e in results if e["category"] in ACTIVE]
    severity = {}
    for entry in active:
        label = entry["severity"] or "UNSCORED"
        severity[label] = severity.get(label, 0) + 1
    return {
        "version": kernel["version"],
        "backports_version": backports_version,
        "kernel_match": inventory["kernel_match"],
        "total": len(results),
        "tally": tally,
        "active": len(active),
        "active_severity": severity,
        "review": sum(tally.get(c, 0) for c in REVIEW),
        "findings": sorted(results, key=lambda e: (-(e["score"] or 0), e["cve"])),
    }


if __name__ == "__main__":
    cves_path, inventory_path, records_dir, output = sys.argv[1:5]
    result = filter_candidates(
        json.loads(Path(cves_path).read_text()),
        json.loads(Path(inventory_path).read_text()),
        Path(records_dir),
    )
    Path(output).write_text(json.dumps(result, indent=1))
    print(result["version"], result["total"], result["tally"], "active", result["active"], result["active_severity"], "review", result["review"])
