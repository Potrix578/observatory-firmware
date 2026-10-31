"""Build the public site from the reports. Only metadata, hashes and results are published.

Writes index.html, a complete document for any static host that makes no third-party
requests, and page.html, a version without the document wrapper for the private preview.

    python -I tools/build_site.py <site_dir>
"""
import difflib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from diff_report import ACTIVE_CATEGORIES, KEY_PACKAGES, STATUS_LABELS, hardening, is_library, package_key, version

ROOT = Path(__file__).resolve().parent.parent
OPEN_STATUSES = ("likely_present", "possibly_affected")
SEVERE_SCORE = 7.0
OUTSIDE = ("not_compiled", "optional_module", "function_not_compiled")
REVIEW = ("shared_header", "driver_fork", "path_unverified", "no_file_data", "not_linux_cna")
CATEGORY_LABELS = {
    "fixed_in_version": "Corrigido",
    "not_compiled": "Não compilado",
    "optional_module": "Módulo opcional",
    "function_not_compiled": "Função não compilada",
    **{category: "Por rever" for category in REVIEW},
}
FONT_BLOCK = re.compile(r"<!--FONTS-->.*?<!--/FONTS-->\n", re.S)
LOCAL_FONTS = (
    ("Barlow Condensed", 500, "barlow-condensed"), ("Barlow Condensed", 600, "barlow-condensed"),
    ("IBM Plex Sans", 400, "ibm-plex-sans"), ("IBM Plex Sans", 600, "ibm-plex-sans"),
    ("IBM Plex Mono", 400, "ibm-plex-mono"), ("IBM Plex Mono", 500, "ibm-plex-mono"),
)
FONT_FACES = "<style>\n" + "\n".join(
    f'@font-face {{ font-family: "{family}"; font-weight: {weight}; font-display: swap; '
    f'src: url("fonts/{stem}-latin-{weight}-normal.woff2") format("woff2"); }}'
    for family, weight, stem in LOCAL_FONTS
) + "\n</style>\n"
DOCUMENT = """<!doctype html>
<html lang="pt-PT">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="description" content="O que muda em cada router quando o firmware OpenWrt é atualizado.">
{head}
</head>
<body>
{body}
</body>
</html>
"""


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


class Release:
    """One device at one OpenWrt release, with its manual verdicts applied."""

    def __init__(self, folder, release, triage):
        self.release = release
        self.analysis = load(folder / release / "analysis.json")
        self.cves = load(folder / release / "cves.json")
        self.kernel = load(folder / release / "kernel-refined.json")
        self.checks = {name: load(folder / release / f"check-{name}.json") for name in ("filter", "fixed", "functions")}
        self.verdicts = triage.get(release, {}).get("kernel", {})
        self.findings = {f["cve"]: f for f in self.kernel["findings"]}

    def status(self, finding):
        return self.verdicts.get(finding["cve"], {}).get("status", "possibly_affected")

    def is_open(self, finding):
        return finding["category"] in ACTIVE_CATEGORIES and self.status(finding) in OPEN_STATUSES

    def state(self, cve):
        finding = self.findings.get(cve)
        if finding is None:
            return "Não listado"
        if finding["category"] in ACTIVE_CATEGORIES or cve in self.verdicts:
            return STATUS_LABELS[self.status(finding)]
        return CATEGORY_LABELS[finding["category"]]

    def open_ids(self):
        return {cve for cve, finding in self.findings.items() if self.is_open(finding)}

    def split(self):
        """Where the candidates of this release ended up."""
        findings = self.findings.values()
        still_open = sum(self.is_open(f) for f in findings)
        review = sum(f["category"] in REVIEW for f in findings)
        fixed = sum(f["category"] == "fixed_in_version" for f in findings)
        return {
            "total": len(self.findings),
            "fixed": fixed,
            "outside": sum(f["category"] in OUTSIDE for f in findings),
            "reviewed_out": self.kernel["active"] - still_open,
            "review": review,
            "open": still_open,
        }


def severity_counts(release):
    counts = {}
    for finding in release.findings.values():
        if release.is_open(finding):
            label = finding["severity"] or "UNSCORED"
            counts[label] = counts.get(label, 0) + 1
    return counts


def cve_rows(old, new):
    rows = []
    old_open, new_open = old.open_ids(), new.open_ids()
    for cve in sorted(old_open | new_open):
        source = new.findings.get(cve) or old.findings[cve]
        rows.append({
            "cve": cve,
            "score": source["score"],
            "severity": source["severity"],
            "title": source["title"],
            "change": "left" if cve not in new_open else "entered" if cve not in old_open else "stayed",
            "old": old.state(cve),
            "new": new.state(cve),
        })
    return sorted(rows, key=lambda r: (-(r["score"] or 0), r["cve"]))


def reviewed_rows(old, new):
    rows = []
    for cve in sorted(set(old.verdicts) | set(new.verdicts)):
        source = new.findings.get(cve) or old.findings[cve]
        rows.append({
            "cve": cve,
            "score": source["score"],
            "title": source["title"],
            "verdicts": [
                {"release": r.release, "status": STATUS_LABELS[r.verdicts[cve]["status"]], "open": r.verdicts[cve]["status"] in OPEN_STATUSES, "reason": r.verdicts[cve]["reason"]}
                for r in (old, new) if cve in r.verdicts
            ],
        })
    return sorted(rows, key=lambda r: (-(r["score"] or 0), r["cve"]))


def component_rows(old, new):
    rows = {}
    for release in (old, new):
        for finding in release.cves["findings"]:
            entry = rows.setdefault(finding["cve"], {"cve": finding["cve"], "score": finding["score"], "component": finding["component"], "states": {}})
            entry["states"][release.release] = {"label": STATUS_LABELS[finding["status"]], "reason": finding["reason"], "version": finding["version"], "open": finding["status"] in OPEN_STATUSES}
    return sorted(rows.values(), key=lambda r: (-(r["score"] or 0), r["cve"]))


def programs(data):
    return {p for p, f in data["files"].items() if "elf" in f and f["elf"]["type"] != "rel" and not is_library(p)}


def image_changes(old, new):
    old_a, new_a = old.analysis, new.analysis
    old_p, new_p = old_a["packages"], new_a["packages"]
    old_h, new_h = hardening(old_a), hardening(new_a)
    key = []
    for name in KEY_PACKAGES:
        old_key, new_key = package_key(name, old_p), package_key(name, new_p)
        if old_key or new_key:
            key.append({"name": name, "old": old_p.get(old_key, "—"), "new": new_p.get(new_key, "—")})
    configs = []
    for path in sorted(set(old_a["configs"]) | set(new_a["configs"])):
        diff = list(difflib.unified_diff(
            old_a["configs"].get(path, "").splitlines(), new_a["configs"].get(path, "").splitlines(),
            old.release, new.release, lineterm="", n=2,
        ))
        configs.append({"path": path, "diff": "\n".join(diff)})
    return {
        "map": [
            {"release": r.release, "bytes": r.analysis["bytes"], "kernel": r.analysis["rootfs_offset"], "rootfs": r.analysis["rootfs_bytes"]}
            for r in (old, new)
        ],
        "facts": [
            {"label": "Kernel", "old": old.kernel["version"], "new": new.kernel["version"]},
            {"label": "Wi-Fi (backports)", "old": old.kernel["backports_version"], "new": new.kernel["backports_version"]},
            {"label": "Gestor de pacotes", "old": old_a["package_manager"], "new": new_a["package_manager"]},
            {"label": "Pacotes instalados", "old": len(old_p), "new": len(new_p)},
            {"label": "Programas PIE", "old": f"{old_h['pie']} de {old_h['programs']}", "new": f"{new_h['pie']} de {new_h['programs']}"},
            {"label": "Marcados NX", "old": f"{old_h['nx']} de {old_h['userland']}", "new": f"{new_h['nx']} de {new_h['userland']}"},
            {"label": "Full RELRO", "old": f"{old_h['full_relro']} de {old_h['userland']}", "new": f"{new_h['full_relro']} de {new_h['userland']}"},
            {"label": "Com canário de pilha", "old": f"{old_h['canary']} de {old_h['userland']}", "new": f"{new_h['canary']} de {new_h['userland']}"},
            {"label": "Ficheiros setuid ou setgid", "old": sum(1 for f in old_a["files"].values() if f.get("setuid")), "new": sum(1 for f in new_a["files"].values() if f.get("setuid"))},
            {"label": "Candidatos a segredos", "old": len(old_a["secret_candidates"]), "new": len(new_a["secret_candidates"])},
        ],
        "key_packages": key,
        "packages_added": sorted(set(new_p) - set(old_p)),
        "packages_removed": sorted(set(old_p) - set(new_p)),
        "packages_changed": sum(1 for p in set(old_p) & set(new_p) if old_p[p] != new_p[p]),
        "services_added": sorted(set(new_a["services"]) - set(old_a["services"])),
        "services_removed": sorted(set(old_a["services"]) - set(new_a["services"])),
        "programs_added": sorted(programs(new_a) - programs(old_a)),
        "programs_removed": sorted(programs(old_a) - programs(new_a)),
        "configs": configs,
    }


def verification(old, new):
    releases = (old, new)
    return {
        "shift": [r.kernel["kernel_match"]["banner_shift_bytes"] for r in releases],
        "kernel_confirmed": all(r.kernel["kernel_match"]["banner_at_debug_address"] for r in releases),
        "fixed_total": sum(r.checks["fixed"]["total"] for r in releases),
        "fixed_by_tool": sum(r.checks["fixed"]["tool"] for r in releases),
        "fixed_by_hand": sorted({c for r in releases for c in r.checks["fixed"]["by_hand"]}),
        "fixed_unresolved": sorted({c for r in releases for c in r.checks["fixed"]["unresolved"]}),
        "rules_checked": sum(r.checks["filter"]["checked"] for r in releases),
        "rules_disabled": sum(r.checks["filter"]["disabled"] for r in releases),
        "rule_exceptions": sorted({p for r in releases for p in r.checks["filter"]["contradictions"]}),
        "controls_ok": all(all(r.checks["filter"]["controls"].values()) for r in releases),
        "functions_retired": sum(r.checks["functions"]["retired"] for r in releases),
        "functions_proved": sum(r.checks["functions"]["proved"] for r in releases),
        "provenance": [{"release": r.release, "image": r.analysis["image"], "sha256": r.analysis["sha256"]} for r in releases],
        "consulted": min(r.cves["consulted"] for r in releases),
    }


def device_pair(device, profile):
    reports = sorted((ROOT / "reports" / device).glob("*_to_*.md"))
    if not reports:
        return None
    old_release, new_release = re.fullmatch(r"(.+)_to_(.+)\.md", reports[-1].name).groups()
    triage_path = ROOT / "data" / "triage" / f"{device}.json"
    triage = load(triage_path) if triage_path.exists() else {}
    folder = ROOT / "reports" / device
    old, new = Release(folder, old_release, triage), Release(folder, new_release, triage)
    rows = cve_rows(old, new)
    changes = {name: [r for r in rows if r["change"] == name] for name in ("left", "entered", "stayed")}
    return {
        "id": device,
        "name": profile["name"],
        "target": profile["target"],
        "old": old_release,
        "new": new_release,
        "kernels": [old.kernel["version"], new.kernel["version"]],
        "splits": [{"release": r.release, **r.split()} for r in (old, new)],
        "severity": [severity_counts(old), severity_counts(new)],
        "counts": {name: len(items) for name, items in changes.items()},
        "severe": {name: sum((r["score"] or 0) >= SEVERE_SCORE for r in items) for name, items in changes.items()},
        "likely": [r for r in reviewed_rows(old, new) if any(v["open"] for v in r["verdicts"])],
        "cves": rows,
        "reviewed": reviewed_rows(old, new),
        "components": component_rows(old, new),
        "image": image_changes(old, new),
        "verification": verification(old, new),
    }, (old, new)


def differences(pairs):
    """Reviewed CVEs whose verdict depends on the device, within one release."""
    found = {}
    for index, (first_id, first) in enumerate(pairs):
        for second_id, second in pairs[index + 1:]:
            for left, right in zip(first, second):
                for cve in sorted(set(left.verdicts) & set(right.verdicts)):
                    a, b = left.verdicts[cve], right.verdicts[cve]
                    if a["reason"] != b["reason"] and cve not in found:
                        found[cve] = {
                            "cve": cve,
                            "score": left.findings[cve]["score"],
                            "title": left.findings[cve]["title"],
                            "release": left.release,
                            "verdicts": [
                                {"device": device_id, "status": STATUS_LABELS[verdict["status"]], "reason": verdict["reason"]}
                                for device_id, verdict in ((first_id, a), (second_id, b))
                            ],
                        }
    return sorted(found.values(), key=lambda r: (-(r["score"] or 0), r["cve"]))


if __name__ == "__main__":
    site = Path(sys.argv[1])
    site.mkdir(exist_ok=True)
    devices, pairs = [], []
    for device, profile in load(ROOT / "data" / "devices.json").items():
        built = device_pair(device, profile)
        if built:
            devices.append(built[0])
            pairs.append((device, built[1]))
    payload = {
        "devices": devices,
        "differences": differences(pairs),
        "consulted": min(d["verification"]["consulted"] for d in devices),
    }
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    page = (Path(__file__).parent / "site_template.html").read_text(encoding="utf-8").replace("/*DATA*/null", data)
    head, body = page.split("<!--HEAD-END-->", 1)
    (site / "page.html").write_text(head + body, encoding="utf-8")
    (site / "index.html").write_text(DOCUMENT.format(head=FONT_BLOCK.sub(FONT_FACES, head), body=body), encoding="utf-8")
    print(len(devices), "devices,", len(payload["differences"]), "device-dependent verdicts,", len(page), "bytes")
