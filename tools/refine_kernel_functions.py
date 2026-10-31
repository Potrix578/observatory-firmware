"""Retire kernel CVEs whose fix only edits code this build does not contain.

Each open candidate's fix is mapped to the functions it edits, using the commit that best
matches this tree. A candidate leaves the list only when every edit that matters lands in
a file or function absent from the official DWARF, and at least one edit does. Anything
unclear, such as a changed struct or a hunk that cannot be located, keeps it open.

    python -I tools/refine_kernel_functions.py <filtered.json> <kernel-files.json> <records_dir> <linux.tar.xz> <patch_cache> <output.json>
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
ACTIVE = ("builtin", "image_module", "header", "wireless_backport")
# Wi-Fi comes from backports, whose source is not in this tree.
CHECKED = ("builtin", "image_module", "header")
NOT_BUILT = ("tools/", "samples/", "scripts/", "Documentation/")
ATTRIBUTES = {
    "__attribute__", "__section", "__aligned", "__printf", "__scanf", "__acquires", "__releases", "__must_hold",
    "__cond_lock", "__alloc_size", "typeof", "__typeof__",
}
TOKEN = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)


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


def parse_patch(text):
    """Per-file hunks of a patch, each a list of (mark, line)."""
    files, current, hunk = {}, None, None
    for line in text.split("\n---\n", 1)[-1].splitlines():
        if line.startswith("diff --git "):
            current, hunk = None, None
        elif line.startswith("+++ b/"):
            current = line[6:]
            files[current] = []
        elif line.startswith("@@") and current:
            hunk = []
            files[current].append(hunk)
        elif hunk is not None and line[:1] in (" ", "+", "-") and not line.startswith(("--- ", "+++ ")):
            hunk.append((line[0], line[1:]))
    return files


def blank_tokens(match):
    return re.sub(r"[^\n]", " ", match.group(0))


def function_name(head):
    """Name in a function definition's head, or None if this block is not a function."""
    if "=" in head or "(" not in head:
        return None
    for name in re.findall(r"(\w+)\s*\(", head):
        if name not in ATTRIBUTES:
            return name
    return None


def blocks(text):
    """Top-level brace blocks of a C file, as (head_line, open_line, close_line, name)."""
    found, depth, head, head_line, open_line, name = [], 0, "", None, None, None
    saved, in_directive = [], False
    for number, line in enumerate(TOKEN.sub(blank_tokens, text).split("\n")):
        stripped = line.strip()
        if in_directive or stripped.startswith("#"):
            directive = re.match(r"#\s*(if|else|elif|endif)", stripped)
            if not in_directive and directive:
                # Both sides of an #if may open the same brace, so each starts from the same depth.
                if directive.group(1) == "if":
                    saved.append(depth)
                elif saved and directive.group(1) == "endif":
                    saved.pop()
                elif saved:
                    depth = saved[-1]
            in_directive = stripped.endswith("\\")
            continue
        for char in line:
            if char == "{":
                if depth == 0:
                    open_line, name = number, function_name(head)
                depth += 1
            elif char == "}":
                depth = max(depth - 1, 0)
                if depth == 0:
                    found.append((head_line if head_line is not None else open_line, open_line, number, name))
                    head, head_line = "", None
            elif char == ";" and depth == 0:
                head, head_line = "", None
            elif depth == 0:
                head += char
                if head_line is None and not char.isspace():
                    head_line = number
        if depth == 0:
            head += " "
    return found


def locate(hunk, text):
    """Tree line of the hunk's first old-side line, trimming context if the tree differs."""
    marks = [mark for mark, _ in hunk if mark != "+"]
    old = [line for mark, line in hunk if mark != "+"]
    front, back = 0, len(old)
    while back > front:
        needle = "\n" + "\n".join(old[front:back]) + "\n"
        if text.count(needle) == 1:
            return text[:text.find(needle) + 1].count("\n") - 1 - front
        if back - front < 3 or marks[front] != " " or marks[back - 1] != " ":
            return None
        front, back = front + 1, back - 1
    return None


def edits_of(hunk, start):
    """Groups of adjacent edits as (first_old_line, removed, added)."""
    groups, position, removed, added = [], start, [], []
    first = position
    for mark, text in hunk:
        if mark == " ":
            if removed or added:
                groups.append((first, removed, added))
                removed, added = [], []
            position += 1
            first = position
        elif mark == "-":
            removed.append(text)
            position += 1
        else:
            added.append(text)
    if removed or added:
        groups.append((first, removed, added))
    return groups


def is_code(line):
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith(("/*", "*", "//"))


def scope_of(first, removed, table):
    """('function', name), ('data', None) or ('top', None) for one group of edits."""
    last = first + len(removed) - 1
    for head, opening, closing, name in table:
        if removed:
            inside = head <= last and first <= closing
        else:
            inside = opening < first <= closing
        if inside:
            return ("function", name) if name else ("data", None)
    return ("top", None)


def added_inside_macro(added):
    """The scanner skips #define bodies, so indented code outside a block belongs to one."""
    code = [line for line in added if is_code(line)]
    return bool(code) and code[0][0].isspace()


def plain_function(name):
    return re.fullmatch(r"[a-z_][a-z0-9_]*", name) is not None


def judge(patch, compiled, functions, sources):
    """Where one fix's edits land in this build."""
    result = {"compiled": set(), "absent": set(), "unresolved": set(), "located": 0, "hunks": 0}
    for path, hunks in patch.items():
        if not path.endswith((".c", ".h", ".S", ".s")) or path.startswith(NOT_BUILT):
            continue
        if path not in compiled:
            # Assembly and macro-only headers leave no trace in DWARF, so only a .c file proves absence.
            if path.endswith(".c") and path in sources["tree"]:
                result["absent"].add(path)
            else:
                result["unresolved"].add(path)
            continue
        text = sources["text"].get(path)
        if text is None:
            result["unresolved"].add(path)
            continue
        table = blocks(text)
        wrapped = "\n" + text + "\n"
        for hunk in hunks:
            result["hunks"] += 1
            start = locate(hunk, wrapped)
            if start is None:
                result["unresolved"].add(path)
                continue
            result["located"] += 1
            for first, removed, added in edits_of(hunk, start):
                if not any(is_code(line) for line in removed + added):
                    continue
                kind, name = scope_of(first, removed, table)
                if kind == "function":
                    if not plain_function(name):
                        result["unresolved"].add(f"{path}:{name}")
                    elif name in functions:
                        result["compiled"].add(f"{path}:{name}")
                    else:
                        result["absent"].add(f"{path}:{name}")
                elif kind == "data" or removed or added_inside_macro(added):
                    result["unresolved"].add(f"{path}:<dados>")
                # A new top-level item changes nothing by itself: an edit elsewhere must use it.
    return result


if __name__ == "__main__":
    filtered_path, inventory_path, records_dir, linux_tar, cache_dir, output = sys.argv[1:7]
    filtered = json.loads(Path(filtered_path).read_text())
    inventory = json.loads(Path(inventory_path).read_text())
    records, cache = Path(records_dir), Path(cache_dir)
    cache.mkdir(exist_ok=True)

    compiled = set(inventory["vmlinux"]["units"].get("kernel", [])) | set(inventory["vmlinux"]["headers"].get("kernel", []))
    # Names are pooled across files because OpenWrt patches move functions, as with at803x.c.
    functions = {name for names in inventory["vmlinux"]["functions"].get("kernel", {}).values() for name in names}
    for module in inventory["modules"].values():
        if module["in_image"]:
            compiled.update(module["units"].get("kernel", []), module["headers"].get("kernel", []))
            functions.update(name for names in module["functions"].get("kernel", {}).values() for name in names)

    candidates = [f for f in filtered["findings"] if f["category"] in CHECKED]
    patches = {}
    for finding in candidates:
        record = json.loads((records / f"{finding['cve']}.json").read_text(encoding="utf-8"))
        texts = {commit: fetch_patch(commit, cache) for commit in fix_commits(record)}
        patches[finding["cve"]] = {commit: parse_patch(text) for commit, text in texts.items() if text}

    wanted = {path for found in patches.values() for patch in found.values() for path in patch}
    sources = {"tree": set(inventory["tree_paths"]), "text": {}}
    with tarfile.open(linux_tar, "r:xz") as tree:
        for member in tree:
            path = member.name.split("/", 1)[1] if "/" in member.name else ""
            if member.isfile() and path in wanted:
                sources["text"][path] = tree.extractfile(member).read().decode("utf-8", "replace")

    for finding in candidates:
        verdicts = [(judge(patch, compiled, functions, sources), commit) for commit, patch in patches[finding["cve"]].items()]
        if not verdicts:
            finding["edits"] = {"unresolved": ["sem patch"]}
            continue
        # A commit that skips the compiled files proves nothing while another one touches them.
        best, commit = max(verdicts, key=lambda item: (item[0]["hunks"] > 0, item[0]["located"] / max(item[0]["hunks"], 1), item[0]["located"]))
        finding["edits"] = {
            "commit": commit[:12],
            "hunks": f"{best['located']}/{best['hunks']}",
            **{key: sorted(best[key]) for key in ("compiled", "absent", "unresolved")},
        }
        if best["absent"] and not best["compiled"] and not best["unresolved"]:
            finding["category"] = "function_not_compiled"
            finding["where"] = sorted(best["absent"])[0]

    tally, severity = {}, {}
    for finding in filtered["findings"]:
        tally[finding["category"]] = tally.get(finding["category"], 0) + 1
        if finding["category"] in ACTIVE:
            label = finding["severity"] or "UNSCORED"
            severity[label] = severity.get(label, 0) + 1
    filtered.update(tally=tally, active=sum(tally.get(c, 0) for c in ACTIVE), active_severity=severity)
    Path(output).write_text(json.dumps(filtered, indent=1))

    outcome = {"compiled": 0, "unresolved": 0, "no_edits": 0}
    for finding in candidates:
        edits = finding["edits"]
        if finding["category"] != "function_not_compiled":
            outcome["compiled" if edits.get("compiled") else "unresolved" if edits.get("unresolved") else "no_edits"] += 1
    print(filtered["version"], "checked", len(candidates), "retired", tally.get("function_not_compiled", 0), outcome, "active", filtered["active"], severity)
