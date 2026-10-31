"""Independent checks of filter_kernel_cves.py using kernel Makefiles and the real .config.

    python -I tools/validate_kernel_filter.py <filtered.json> <kernel-files.json> <linux.tar.xz> <output.json>
"""
import json
import posixpath
import random
import re
import sys
import tarfile
from pathlib import Path


def makefiles(linux_tar, directories):
    found = {}
    with tarfile.open(linux_tar, "r:xz") as tree:
        for member in tree:
            path = member.name.split("/", 1)[1] if "/" in member.name else ""
            if member.isfile() and posixpath.basename(path) in ("Makefile", "Kbuild"):
                directory = posixpath.dirname(path)
                if directory in directories:
                    text = tree.extractfile(member).read().decode("utf-8", "replace")
                    found[directory] = found.get(directory, "") + "\n" + text.replace("\\\n", " ")
    return found


def config_for(path, text):
    """CONFIG symbol that directly builds this object, or None for indirect rules."""
    stem = posixpath.basename(path).rsplit(".", 1)[0]
    match = re.search(rf"^obj-\$\((CONFIG_\w+)\)\s*[+:]?=[^\n]*\b{re.escape(stem)}\.o\b", text, re.M)
    return match.group(1) if match else None


if __name__ == "__main__":
    filtered = json.loads(Path(sys.argv[1]).read_text())
    inventory = json.loads(Path(sys.argv[2]).read_text())
    config = inventory["config"]
    excluded = [f for f in filtered["findings"] if f["category"] == "not_compiled"]
    files = sorted({p for f in excluded for p in f["files"] if p.endswith(".c")})
    texts = makefiles(sys.argv[3], {posixpath.dirname(p) for p in files})

    checked = disabled = modular = builtin = indirect = 0
    contradictions = []
    for path in files:
        symbol = config_for(path, texts.get(posixpath.dirname(path), ""))
        if symbol is None:
            indirect += 1
            continue
        checked += 1
        value = config.get(symbol)
        if value == "y":
            builtin += 1
            contradictions.append((path, symbol, value))
        elif value == "m":
            modular += 1
            contradictions.append((path, symbol, value))
        else:
            disabled += 1

    print(filtered["version"], "excluded CVEs", len(excluded), "files", len(files))
    print(" direct rule checked", checked, "disabled", disabled, "=y", builtin, "=m", modular, "indirect", indirect)
    print(" contradictions", contradictions[:15])

    sample = random.Random(20261031).sample(excluded, min(12, len(excluded)))
    print(" sample excluded:")
    for entry in sample:
        print("  ", entry["cve"], entry["score"], entry["files"][:2], entry["title"][:60])

    controls = {
        "net/ipv4/tcp_input.c": "builtin", "net/core/dev.c": "builtin", "net/netfilter/nf_tables_api.c": "image_module",
        "arch/x86/kvm/x86.c": "not_compiled",
    }
    seen = {}
    for path, expected in controls.items():
        hits = [f for f in filtered["findings"] if f["files"] and path in f["files"] and f["category"] != "fixed_in_version"]
        seen[path] = sorted({f["category"] for f in hits})
        print(" control", path, "expected", expected, "seen", seen[path], len(hits))
    Path(sys.argv[4]).write_text(json.dumps({
        "checked": checked,
        "disabled": disabled,
        "indirect": indirect,
        "contradictions": [path for path, _, _ in contradictions],
        "controls": {path: categories == [controls[path]] for path, categories in seen.items() if categories},
    }, indent=1))
