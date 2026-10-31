"""Run the whole analysis for one device between two OpenWrt releases.

A step runs only when its output is missing or older than its inputs, so a second run
is cheap. CVE sources are refreshed by the tools themselves once their cache expires.

    python tools/observatory.py <device> <old_release> <new_release>
"""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
FIRMWARE = ROOT / "firmware"
REPORTS = ROOT / "reports"
CACHE = REPORTS / "cache"


def step(tool, output, inputs, *arguments):
    """Run a tool unless its output is newer than the tool and every input."""
    script = TOOLS / tool
    sources = [script, *map(Path, inputs)]
    if output.exists() and output.stat().st_mtime >= max(p.stat().st_mtime for p in sources if p.exists()):
        return
    started = time.time()
    print(f"-- {tool} -> {output.relative_to(ROOT)}", flush=True)
    subprocess.run([sys.executable, "-I", str(script), *map(str, arguments)], check=True, cwd=ROOT)
    print(f"   {time.time() - started:.0f} s", flush=True)


def analyse(device, target, release, triage):
    subprocess.run([sys.executable, "-I", str(TOOLS / "fetch_firmware.py"), device, target, release, str(FIRMWARE)], check=True, cwd=ROOT)
    fetched = json.loads((FIRMWARE / target.replace("/", "_") / release / f"fetched-{device}.json").read_text())
    folder = REPORTS / device / release
    folder.mkdir(parents=True, exist_ok=True)
    analysis, cves = folder / "analysis.json", folder / "cves.json"
    files, filtered, refined = folder / "kernel-files.json", folder / "kernel-filtered.json", folder / "kernel-refined.json"
    records, patches = CACHE / "cve-records", CACHE / "cve-patches"

    step("analyze_firmware.py", analysis, [fetched["image"]], fetched["image"], fetched["manifest"], analysis)
    step("correlate_cves.py", cves, [analysis, triage], analysis, fetched["openwrt_source"], CACHE / "cve-cache", cves, triage)
    step("fetch_cve_records.py", folder / "records.done", [cves], records, cves, folder / "records.done")
    step("kernel_inventory.py", files, [analysis, fetched["debug"]], analysis, fetched["image"], fetched["debug"], fetched["linux"], fetched["config"], files)
    step("filter_kernel_cves.py", filtered, [cves, files, folder / "records.done"], cves, files, records, filtered)
    step("refine_kernel_functions.py", refined, [filtered, files], filtered, files, records, fetched["linux"], patches, refined)

    by_hand = ROOT / "data" / "fixed-by-hand.json"
    step("validate_kernel_filter.py", folder / "check-filter.json", [filtered, files], filtered, files, fetched["linux"], folder / "check-filter.json")
    step("validate_fixed_versions.py", folder / "check-fixed.json", [filtered, files, by_hand], filtered, records, fetched["linux"], files, patches, by_hand, folder / "check-fixed.json")
    step("validate_function_filter.py", folder / "check-functions.json", [refined, files, TOOLS / "refine_kernel_functions.py"], refined, files, fetched["linux"], fetched["debug"], folder / "check-functions.json")
    return folder


if __name__ == "__main__":
    device, old, new = sys.argv[1:4]
    profile = json.loads((ROOT / "data" / "devices.json").read_text(encoding="utf-8"))[device]
    triage = ROOT / "data" / "triage" / f"{device}.json"
    folders = [analyse(device, profile["target"], release, triage) for release in (old, new)]
    report = REPORTS / device / f"{old}_to_{new}.md"
    inputs = [triage, *[folder / name for folder in folders for name in ("cves.json", "kernel-refined.json", "check-filter.json", "check-fixed.json", "check-functions.json")]]
    step("diff_report.py", report, inputs, profile["name"], *folders, triage, report)
    site = ROOT / "site"
    step("build_site.py", site / "index.html", [report, TOOLS / "site_template.html", TOOLS / "diff_report.py"], site)
    print(report)
