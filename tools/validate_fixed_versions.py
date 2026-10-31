"""Check 'fixed_in_version' verdicts on compiled code against the real kernel source.

A wrong verdict only hides a real bug when the file is compiled, so all of those are
tested. If the bug was introduced after this branch, the vulnerable code must be absent.
If it was fixed here, one of the fix commits listed for the CVE must have its added lines
in the tree. Verdicts the tool cannot settle fall back to data/fixed-by-hand.json.

    python -I tools/validate_fixed_versions.py <filtered.json> <records_dir> <linux.tar.xz> <kernel-files.json> <patch_cache> <fixed-by-hand.json> <output.json>
"""
import json
import re
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

PATCH_URL = "https://github.com/gregkh/linux/commit/{}.patch"
USER_AGENT = "firmware-observatory-poc"
MIN_LINE_LENGTH = 16
FIXED_SHARE = 0.6
ABSENT_SHARE = 0.5


def parse_version(text):
    numbers = re.findall(r"\d+", text.split("-")[0])
    return tuple(int(n) for n in numbers[:3]) + (0,) * (3 - len(numbers[:3]))


def first_affected(record):
    """Lowest version the CNA marks as the start of the affected range."""
    starts = []
    for block in record["containers"]["cna"].get("affected", []):
        if block.get("vendor") == "Linux":
            for version in block.get("versions", []):
                if version.get("versionType") != "git" and version.get("status") == "affected":
                    starts.append(parse_version(version["version"]))
    return min(starts) if starts else None


def fix_commits(record):
    commits = []
    for block in record["containers"]["cna"].get("affected", []):
        for version in block.get("versions", []):
            if version.get("versionType") == "git" and version.get("lessThan"):
                commits.append(version["lessThan"])
    return list(dict.fromkeys(commits))


def fetch_patch(commit, cache):
    path = cache / f"{commit}.patch"
    if path.exists():
        return path.read_text(encoding="utf-8")
    request = urllib.request.Request(PATCH_URL.format(commit), headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            text = response.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError):
        return None
    time.sleep(0.3)
    path.write_text(text, encoding="utf-8")
    return text


def patch_lines(patch):
    """Per-file added lines, removed lines and all vulnerable-side lines."""
    added, removed, old_side, current = {}, {}, {}, None
    for line in patch.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
        elif line.startswith(("--- ", "diff ", "index ")) or current is None:
            continue
        elif line[:1] in ("+", "-", " "):
            text = line[1:].strip()
            if len(text) < MIN_LINE_LENGTH or text.startswith(("/*", "*", "//")):
                continue
            if line[0] == "+":
                added.setdefault(current, []).append(text)
            else:
                old_side.setdefault(current, []).append(text)
                if line[0] == "-":
                    removed.setdefault(current, []).append(text)
    return added, removed, old_side


def post_images(patch):
    """Each hunk as it reads after the patch, the strongest check for moved or short lines."""
    images, current, lines = [], None, None
    for line in patch.split("\n---\n", 1)[-1].splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
        elif line.startswith("@@"):
            lines = []
            images.append((current, lines))
        elif lines is not None and line[:1] in (" ", "+") and not line.startswith("+++"):
            lines.append(line[1:])
    return [(path, "\n".join(body)) for path, body in images]


def fix_is_applied(added, removed, hunks, contents):
    """Every hunk reads as patched, or the added or removed lines show the same."""
    if hunks and all(body in contents.get(path, "") for path, body in hunks):
        return True
    if added:
        return share(added, contents) >= FIXED_SHARE
    return bool(removed) and share(removed, contents) < ABSENT_SHARE


def share(lines, contents):
    total = found = 0
    for path, items in lines.items():
        text = contents.get(path, "")
        total += len(items)
        found += sum(item in text for item in items)
    return found / total if total else 0.0


if __name__ == "__main__":
    filtered = json.loads(Path(sys.argv[1]).read_text())
    records = Path(sys.argv[2])
    inventory = json.loads(Path(sys.argv[4]).read_text())
    patch_cache = Path(sys.argv[5])
    patch_cache.mkdir(exist_ok=True)
    by_hand = json.loads(Path(sys.argv[6]).read_text(encoding="utf-8")).get(filtered["version"], {})
    kernel = parse_version(filtered["version"])
    compiled = set(inventory["vmlinux"]["units"].get("kernel", []))
    for module in inventory["modules"].values():
        if module["in_image"]:
            compiled.update(module["units"].get("kernel", []))
    fixed = [
        f for f in filtered["findings"]
        if f["category"] == "fixed_in_version" and f["where"].startswith("kernel") and compiled.intersection(f["files"])
    ]

    plans = {}
    for entry in fixed:
        record = json.loads((records / f"{entry['cve']}.json").read_text(encoding="utf-8"))
        start = first_affected(record)
        patches = []
        for commit in fix_commits(record):
            text = fetch_patch(commit, patch_cache)
            if text and "+++ b/" in text:
                patches.append((commit, *patch_lines(text), post_images(text)))
        introduced_later = start is not None and start > kernel
        plans[entry["cve"]] = (introduced_later, patches)

    wanted = {path for _, patches in plans.values() for patch in patches for path, _ in patch[4]}
    contents = {}
    with tarfile.open(sys.argv[3], "r:xz") as tree:
        for member in tree:
            path = member.name.split("/", 1)[1] if "/" in member.name else ""
            if member.isfile() and path in wanted:
                contents[path] = tree.extractfile(member).read().decode("utf-8", "replace")

    tally = {"fixed_confirmed": 0, "absent_confirmed": 0}
    unresolved = []
    for cve, (introduced_later, patches) in plans.items():
        best_old = max((share(old, contents) for _, _, _, old, _ in patches), default=0.0)
        if any(fix_is_applied(added, removed, hunks, contents) for _, added, removed, _, hunks in patches):
            tally["fixed_confirmed"] += 1
        elif introduced_later and best_old < ABSENT_SHARE:
            tally["absent_confirmed"] += 1
        else:
            unresolved.append({
                "cve": cve,
                "claim": "introduced_later" if introduced_later else "fixed",
                "patches": [
                    {
                        "commit": commit[:10],
                        "added": round(share(added, contents), 2),
                        "removed": round(share(removed, contents), 2),
                        "files": sorted(old)[:2],
                    }
                    for commit, added, removed, old, _ in patches
                ],
            })
    print(filtered["version"], "fixed verdicts", len(fixed), tally, "unresolved", len(unresolved))
    for item in unresolved:
        print(" ", item["cve"], item["claim"], item["patches"][:6])
    Path(sys.argv[7]).write_text(json.dumps({
        "total": len(fixed),
        "tool": sum(tally.values()),
        "by_hand": [item["cve"] for item in unresolved if item["cve"] in by_hand],
        "unresolved": [item["cve"] for item in unresolved if item["cve"] not in by_hand],
    }, indent=1))
