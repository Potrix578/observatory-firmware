"""Markdown diff report between two analyze_firmware.py results.

    python -I tools/diff_report.py <device_name> <old_dir> <new_dir> <triage.json> <report.md>
"""
import difflib
import json
import re
import sys
from pathlib import Path

ROOT_LABELS = {"empty": "empty", "locked": "locked", "hash": "set", None: "unknown"}
STATUS_LABELS = {
    "likely_present": "Likely present",
    "possibly_affected": "To confirm",
    "no_security_impact": "Present, no impact",
    "unused": "Unused code",
    "not_applicable": "Not applicable",
    "fixed": "Fixed",
}
STATUS_ORDER = list(STATUS_LABELS)
ACTIVE_CATEGORIES = ("builtin", "image_module", "header", "wireless_backport")
OPEN_STATUSES = ("likely_present", "possibly_affected")
REVIEW_SCORE = 8.0
KEY_PACKAGES = [
    "kernel", "busybox", "dropbear", "dnsmasq", "uhttpd", "firewall4", "nftables-json",
    "wpad-basic-mbedtls", "libmbedtls21", "libustream-mbedtls", "ca-bundle", "musl",
    "libc", "opkg", "apk-mbedtls",
]


def version(data):
    return re.search(r"DISTRIB_RELEASE='([^']+)'", data["release"]).group(1)


def is_library(path):
    return ".so" in path.rsplit("/", 1)[1]


def hardening(data):
    elfs = {p: f["elf"] for p, f in data["files"].items() if "elf" in f}
    programs = {p: e for p, e in elfs.items() if e["type"] != "rel" and not is_library(p)}
    libraries = {p: e for p, e in elfs.items() if e["type"] != "rel" and is_library(p)}
    userland = {**programs, **libraries}
    return {
        "programs": len(programs),
        "libraries": len(libraries),
        "kernel_modules": len(elfs) - len(userland),
        "pie": sum(e["type"] == "dyn" for e in programs.values()),
        "non_pie": sorted(p for p, e in programs.items() if e["type"] == "exec"),
        "nx": sum(e["nx"] for e in userland.values()),
        "full_relro": sum(e["relro"] and e["bind_now"] for e in userland.values()),
        "canary": sum(e["canary"] for e in userland.values()),
        "userland": len(userland),
    }


def package_key(name, packages):
    """Library packages embed an ABI suffix, so match on the unversioned stem too."""
    if name in packages:
        return name
    stem = re.sub(r"\d+$", "", name)
    return next((p for p in packages if re.fullmatch(re.escape(stem) + r"\d*", p)), None)


def bullets(values):
    return ", ".join(f"`{v}`" for v in values) if values else "none"


def findings_table(cves):
    rows = ["| CVE | Component | CVSS | Status | Basis |", "| --- | --- | --- | --- | --- |"]
    ordered = sorted(cves["findings"], key=lambda f: (STATUS_ORDER.index(f["status"]), -(f["score"] or 0), f["cve"]))
    for finding in ordered:
        score = finding["score"] if finding["score"] is not None else "—"
        rows.append(
            f"| {finding['cve']} | {finding['component']} {finding['version']} | {score} "
            f"| {STATUS_LABELS[finding['status']]} | {finding['reason']} |"
        )
    return rows


def code_list(paths):
    return ", ".join(f"`{p}`" for p in paths) if paths else "none"


def vulnerability_section(old_cves, new_cves, old_kernel, new_kernel, checks, triage, old_v, new_v):
    out = [
        "## Vulnerabilities",
        "",
        f"Candidates by version in NVD and OSV, consulted on {min(old_cves['consulted'], new_cves['consulted'])}. Manual classification, where it exists, uses patches, commits and image bytes.",
        "",
        f"| Status | {old_v} | {new_v} |",
        "| --- | --- | --- |",
    ]
    for status in STATUS_ORDER:
        counts = [sum(f["status"] == status for f in c["findings"]) for c in (old_cves, new_cves)]
        if any(counts):
            out.append(f"| {STATUS_LABELS[status]} | {counts[0]} | {counts[1]} |")
    out.append(f"| **Total candidates** | **{len(old_cves['findings'])}** | **{len(new_cves['findings'])}** |")
    for release, cves in ((old_v, old_cves), (new_v, new_cves)):
        out += ["", f"### OpenWrt {release}", "", *findings_table(cves)]
    return out + kernel_section(old_kernel, new_kernel, checks, triage, old_v, new_v)


def kernel_section(old_k, new_k, checks, triage, old_v, new_v):
    verdicts = {
        old_k["version"]: triage.get(old_v, {}).get("kernel", {}),
        new_k["version"]: triage.get(new_v, {}).get("kernel", {}),
    }

    def funnel(label, field):
        return f"| {label} | {field(old_k)} | {field(new_k)} |"

    def tally(*categories):
        return lambda k: sum(k["tally"].get(c, 0) for c in categories)

    def status(k, finding):
        return verdicts[k["version"]].get(finding["cve"], {}).get("status", "possibly_affected")

    def active(k):
        return [f for f in k["findings"] if f["category"] in ACTIVE_CATEGORIES]

    def still_open(k):
        return [f for f in active(k) if status(k, f) in OPEN_STATUSES]

    def severity(label):
        return lambda k: sum((f["severity"] or "UNSCORED") == label for f in still_open(k))

    out = [
        "",
        "### Kernel",
        "",
        "Each candidate was compared with the compiled files and functions, listed in the official `kernel-debug` DWARF, and with the fixed versions published by the Linux CNA.",
        "A candidate only leaves the list on positive evidence. Cases without evidence stay in \"To review\". If the fix changes a struct, or the change cannot be located in the code, the CVE stays open.",
        "",
        f"| Stage | {old_k['version']} | {new_k['version']} |",
        "| --- | --- | --- |",
        funnel("Initial candidates (NVD + OSV)", lambda k: k["total"]),
        funnel("Fixed in this version, or never present", tally("fixed_in_version")),
        funnel("Code not compiled", tally("not_compiled")),
        funnel("Only in an optional module, outside the image", tally("optional_module")),
        funnel("File compiled, but not the changed function", tally("function_not_compiled")),
        funnel("To review, not enough evidence", lambda k: k["review"]),
        funnel("Compiled, before manual review", lambda k: k["active"]),
        funnel("Removed by manual review", lambda k: len(active(k)) - len(still_open(k))),
        funnel("**Open after review**", lambda k: f"**{len(still_open(k))}**"),
        funnel("Open critical (CVSS)", severity("CRITICAL")),
        funnel("Open high (CVSS)", severity("HIGH")),
        funnel("Open medium (CVSS)", severity("MEDIUM")),
        funnel("Open without a score", severity("UNSCORED")),
        "",
        "\"Open\" means the file is compiled and the fix was not demonstrated. It does not mean the flaw is exploitable on this router.",
        f"Manual review covered open CVEs with a CVSS of {REVIEW_SCORE} or higher. The rest follow the automatic classification.",
        "The difference between versions is a signal, not a measure of risk: it also depends on what was recorded for each series.",
        "",
        "**Removed by the function filter:**",
        "",
        "| Version | CVE | CVSS | Code changed by the fix, absent from this build |",
        "| --- | --- | --- | --- |",
    ]
    for release, data in ((old_v, old_k), (new_v, new_k)):
        for finding in data["findings"]:
            if finding["category"] == "function_not_compiled":
                out.append(f"| {release} | {finding['cve']} | {finding['score'] or '—'} | `{finding['where']}` |")
    out.append("")
    for release, data in ((old_v, old_k), (new_v, new_k)):
        rows = [f for f in data["findings"] if f["category"] in (*ACTIVE_CATEGORIES, "driver_fork") and (f["score"] or 0) >= REVIEW_SCORE]
        out += [
            f"**Manual review of {release}:**",
            "",
            "| CVE | CVSS | Status | Basis |",
            "| --- | --- | --- | --- |",
        ]
        for finding in rows:
            reason = verdicts[data["version"]].get(finding["cve"], {}).get("reason", "No manual review.")
            out.append(f"| {finding['cve']} | {finding['score']} | {STATUS_LABELS[status(data, finding)]} | {reason} |")
        out.append("")
    old_c, new_c = checks
    banners = [k["kernel_match"]["banner_at_debug_address"] for k in (old_k, new_k)]
    unresolved = old_c["fixed"]["unresolved"] + new_c["fixed"]["unresolved"]
    by_hand = sorted(set(old_c["fixed"]["by_hand"] + new_c["fixed"]["by_hand"]))
    failed = [path for c in (old_c, new_c) for path, passed in c["filter"]["controls"].items() if not passed]
    controls = sorted({path for c in (old_c, new_c) for path in c["filter"]["controls"]})
    exceptions = sorted(set(old_c["filter"]["contradictions"] + new_c["filter"]["contradictions"]))
    old_f, new_f = old_c["functions"], new_c["functions"]
    out += [
        "**How this was validated:**",
        "",
        f"- **Right kernel:** {'in both versions, the image `init_uts_ns` is at the address given by the debug symbols' if all(banners) else 'the image kernel was not confirmed against the debug symbols in all versions'} ({old_k['version']} and {new_k['version']}). `linux_banner` is off by {old_k['kernel_match']['banner_shift_bytes']} and {new_k['kernel_match']['banner_shift_bytes']} bytes.{' This offset is not explained, so the evidence is weaker than an exact address.' if old_k['kernel_match']['banner_shift_bytes'] or new_k['kernel_match']['banner_shift_bytes'] else ''}",
        f"- **\"Fixed\" verdicts on compiled code:** {old_c['fixed']['total']} on {old_k['version']} and {new_c['fixed']['total']} on {new_k['version']}. The tool confirmed {old_c['fixed']['tool']} and {new_c['fixed']['tool']} in the real code. By hand: {code_list(by_hand)}. To confirm: {code_list(unresolved)}.",
        f"- **\"Not compiled\" code:** of the direct Makefile rules, {old_c['filter']['disabled']} of {old_c['filter']['checked']} and {new_c['filter']['disabled']} of {new_c['filter']['checked']} have the option off in the real `.config`. Exceptions: {code_list(exceptions)}.",
        f"- **Controls:** {code_list(controls)}. {'All landed in the expected category.' if not failed else 'Failed: ' + code_list(sorted(set(failed))) + '.'}",
        f"- **Function filter:** {old_f['proved']} of {old_f['retired']} and {new_f['proved']} of {new_f['retired']} removals confirmed outside the DWARF: the change is in a module outside the image, or in a function with no symbol behind an option that is off in the real `.config`.",
        f"- **Functions in compiled files:** {old_f['present']} and {new_f['present']} are in the DWARF, {old_f['absent_guarded']} and {new_f['absent_guarded']} sit behind disabled options, and {old_f['absent_unexplained']} and {new_f['absent_unexplained']} leave no trace in the binary and have no identified option. Another {old_f['absent_with_symbol']} and {new_f['absent_with_symbol']} have a symbol with the same name, from another file or from assembly. A name present in another DWARF file counts as compiled.",
        "",
    ]
    return out


def report(device, old, new, old_cves, new_cves, old_kernel, new_kernel, checks, triage):
    old_v, new_v = version(old), version(new)
    old_h, new_h = hardening(old), hardening(new)
    old_p, new_p = old["packages"], new["packages"]
    added = sorted(set(new_p) - set(old_p))
    removed = sorted(set(old_p) - set(new_p))
    changed = sorted(p for p in set(old_p) & set(new_p) if old_p[p] != new_p[p])
    old_programs = {p for p, f in old["files"].items() if "elf" in f and f["elf"]["type"] != "rel" and not is_library(p)}
    new_programs = {p for p, f in new["files"].items() if "elf" in f and f["elf"]["type"] != "rel" and not is_library(p)}

    out = [
        f"# {device}: OpenWrt {old_v} → {new_v}",
        "",
        "Static analysis of the official `sysupgrade` images. No firmware code was run.",
        "",
        "## Summary",
        "",
        "| Measure | " + old_v + " | " + new_v + " |",
        "| --- | --- | --- |",
        f"| Kernel | `{old['kernel_image']}` | `{new['kernel_image']}` |",
        f"| Package manager | {old['package_manager']} | {new['package_manager']} |",
        f"| Image size | {old['bytes']:,} bytes | {new['bytes']:,} bytes |",
        f"| Installed packages | {len(old_p)} | {len(new_p)} |",
        f"| File entries | {len(old['files'])} | {len(new['files'])} |",
        f"| PIE programs | {old_h['pie']} of {old_h['programs']} | {new_h['pie']} of {new_h['programs']} |",
        f"| Marked NX | {old_h['nx']} of {old_h['userland']} | {new_h['nx']} of {new_h['userland']} |",
        f"| Full RELRO | {old_h['full_relro']} of {old_h['userland']} | {new_h['full_relro']} of {new_h['userland']} |",
        f"| With stack canary | {old_h['canary']} of {old_h['userland']} | {new_h['canary']} of {new_h['userland']} |",
        f"| Setuid/setgid files | {sum(1 for f in old['files'].values() if f.get('setuid'))} | {sum(1 for f in new['files'].values() if f.get('setuid'))} |",
        f"| Secret candidates | {len(old['secret_candidates'])} | {len(new['secret_candidates'])} |",
        f"| Default `root` password | {ROOT_LABELS[old['accounts'].get('root')]} | {ROOT_LABELS[new['accounts'].get('root')]} |",
        "",
        "## Main components",
        "",
        "| Package | " + old_v + " | " + new_v + " |",
        "| --- | --- | --- |",
    ]
    for name in KEY_PACKAGES:
        old_key, new_key = package_key(name, old_p), package_key(name, new_p)
        if old_key or new_key:
            out.append(f"| {name} | {old_p.get(old_key, '—')} | {new_p.get(new_key, '—')} |")

    out += [
        "",
        "## Packages",
        "",
        f"{len(added)} added, {len(removed)} removed and {len(changed)} with a changed version.",
        "",
        f"- **Added:** {bullets(added)}",
        f"- **Removed:** {bullets(removed)}",
        "",
        "## Services and programs",
        "",
        f"- **Service scripts added:** {bullets(sorted(set(new['services']) - set(old['services'])))}",
        f"- **Service scripts removed:** {bullets(sorted(set(old['services']) - set(new['services'])))}",
        f"- **Autostart added:** {bullets(sorted(set(new['enabled_services']) - set(old['enabled_services'])))}",
        f"- **Autostart removed:** {bullets(sorted(set(old['enabled_services']) - set(new['enabled_services'])))}",
        f"- **Programs added:** {bullets(sorted(new_programs - old_programs))}",
        f"- **Programs removed:** {bullets(sorted(old_programs - new_programs))}",
        f"- **Programs without PIE in {new_v}:** {bullets(new_h['non_pie'])}",
        "",
        "## Default settings",
        "",
    ]
    for path in sorted(set(old["configs"]) | set(new["configs"])):
        diff = list(difflib.unified_diff(
            old["configs"].get(path, "").splitlines(), new["configs"].get(path, "").splitlines(),
            old_v, new_v, lineterm="", n=3,
        ))
        out.append(f"**`{path}`:** " + ("no changes." if not diff else ""))
        if diff:
            out += ["", "```diff", *diff, "```"]
        out.append("")

    out += vulnerability_section(old_cves, new_cves, old_kernel, new_kernel, checks, triage, old_v, new_v)
    out += [
        "## Limits of this analysis",
        "",
        "- The comparison covers the configuration shipped in the image, not what runs on an already configured router.",
        "- `NX` is the ELF flag. It does not prove that the processor enforces it on this device.",
        "- A missing canary means the binary does not reference `__stack_chk_fail`, which can happen when no function needs protection.",
        "- A kernel CVE stays open if a function changed by the fix is compiled, or if the change cannot be mapped to a function. This does not prove that the function is reachable or that the feature is active.",
        "- The function filter does not cover Wi-Fi or changes to structs and macros. Those CVEs stay open.",
        "- A macro-only header leaves no trace in DWARF. When it sits next to compiled code, the CVE stays in \"To review\".",
        "- Fixed versions come from the Linux CNA. Confirmation in the code used the official kernel, without the patches OpenWrt applies to it.",
        "- Wi-Fi uses backports. Its verdicts follow the backports version and were only confirmed in the code where the manual review says so. Drivers with their own tree, such as ath10k-ct and mt76, stay in \"To review\".",
        "- Manual review assessed the configuration shipped in the image. A CVE marked \"Unused code\" counts again if the feature is enabled.",
        "- Optional modules are outside the count, but count once installed.",
        "- Vulnerability statuses come from static analysis: no flaw was tested on a device.",
        "- The hostapd/wpad packages use dated snapshots with no comparable upstream version, so they were not correlated.",
        "- Installing extra packages can make components marked as not applicable or unused relevant.",
        "",
        "## Provenance",
        "",
        f"- `{old['image']}`: SHA-256 `{old['sha256']}`",
        f"- `{new['image']}`: SHA-256 `{new['sha256']}`",
    ]
    return "\n".join(out) + "\n"


def load(folder, name):
    return json.loads((Path(folder) / name).read_text(encoding="utf-8"))


if __name__ == "__main__":
    device, old_dir, new_dir, triage_path, output = sys.argv[1:6]
    folders = (old_dir, new_dir)
    checks = [{name: load(f, f"check-{name}.json") for name in ("filter", "fixed", "functions")} for f in folders]
    triage = json.loads(Path(triage_path).read_text(encoding="utf-8")) if Path(triage_path).exists() else {}
    analyses, cves, kernels = ([load(f, name) for f in folders] for name in ("analysis.json", "cves.json", "kernel-refined.json"))
    Path(output).write_text(report(device, *analyses, *cves, *kernels, checks, triage), encoding="utf-8")
