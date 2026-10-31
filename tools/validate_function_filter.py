"""Check function_not_compiled verdicts without the DWARF index they came from.

Each absent function must have no symbol in the build and sit under a preprocessor
condition that the real .config turns off. The same test runs over every function of the
compiled files, to measure how often the source scanner and the DWARF index disagree.

    python -I tools/validate_function_filter.py <refined.json> <kernel-files.json> <linux.tar.xz> <kernel-debug.tar.zst> <output.json>
"""
import io
import json
import re
import sys
import tarfile
from pathlib import Path

from elftools.elf.elffile import ELFFile

sys.path.insert(0, str(Path(__file__).parent))
from refine_kernel_functions import TOKEN, blank_tokens, blocks, plain_function

MACRO = re.compile(r"\b(?:IS_ENABLED|IS_BUILTIN|IS_REACHABLE|IS_MODULE|defined)\s*\(?\s*(CONFIG_\w+)\s*\)?")


def condition(expression, config):
    """True or False for an #if expression over CONFIG options, None if it depends on anything else."""
    text = MACRO.sub(lambda m: "1" if m.group(1) in config else "0", expression)
    text = re.sub(r"\bCONFIG_\w+", lambda m: "1" if m.group(0) in config else "0", text)
    if re.search(r"[A-Za-z_]", text):
        return None
    text = text.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    try:
        return bool(eval(text, {"__builtins__": {}}))
    except (SyntaxError, TypeError):
        return None


def guards(text):
    """For each line, the (expression, wanted) conditions of its enclosing #if blocks."""
    stack, per_line, pending = [], [], ""
    for line in TOKEN.sub(blank_tokens, text).split("\n"):
        per_line.append(tuple(item for frame in stack for item in frame))
        stripped = (pending + line.strip()).rstrip("\\")
        if line.rstrip().endswith("\\"):
            pending = stripped + " "
            continue
        pending = ""
        match = re.match(r"#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)", stripped)
        if not match:
            continue
        word, rest = match.group(1), match.group(2).strip()
        if word == "ifdef":
            stack.append([(f"defined({rest})", True)])
        elif word == "ifndef":
            stack.append([(f"defined({rest})", False)])
        elif word == "if":
            stack.append([(rest, True)])
        elif stack and word == "endif":
            stack.pop()
        elif stack:
            passed = [(expression, not wanted) if wanted else (expression, wanted) for expression, wanted in stack[-1]]
            stack[-1] = passed + ([(rest, True)] if word == "elif" else [])
    return per_line


def switched_off(conditions, config):
    return any(condition(expression, config) is (not wanted) for expression, wanted in conditions)


def elf_symbols(tar_path, modules):
    names = set()
    with tarfile.open(tar_path, "r:zst") as tree:
        for member in tree:
            base = member.name.rsplit("/", 1)[-1]
            if member.isfile() and (base == "vmlinux" or base in modules):
                table = ELFFile(io.BytesIO(tree.extractfile(member).read())).get_section_by_name(".symtab")
                names.update(s.name for s in table.iter_symbols() if s["st_shndx"] != "SHN_UNDEF")
    return names


if __name__ == "__main__":
    refined = json.loads(Path(sys.argv[1]).read_text())
    inventory = json.loads(Path(sys.argv[2]).read_text())
    config = inventory["config"]
    image = {name for name, module in inventory["modules"].items() if module["in_image"]}
    symbols = elf_symbols(sys.argv[4], image)

    compiled = set(inventory["vmlinux"]["units"].get("kernel", []))
    functions = {path: set(names) for path, names in inventory["vmlinux"]["functions"].get("kernel", {}).items()}
    for name in image:
        compiled.update(inventory["modules"][name]["units"].get("kernel", []))
        for path, names in inventory["modules"][name]["functions"].get("kernel", {}).items():
            functions.setdefault(path, set()).update(names)

    retired = [f for f in refined["findings"] if f["category"] == "function_not_compiled"]
    edited = {item.rsplit(":", 1)[0] for f in retired for item in f["edits"]["absent"]}
    sources = {}
    with tarfile.open(sys.argv[3], "r:xz") as tree:
        for member in tree:
            path = member.name.split("/", 1)[1] if "/" in member.name else ""
            if member.isfile() and path in edited or member.isfile() and path.endswith(".c") and path in compiled:
                sources[path] = tree.extractfile(member).read().decode("utf-8", "replace")

    tally = {"present": 0, "absent_guarded": 0, "absent_unexplained": 0, "absent_with_symbol": 0}
    unexplained = []
    for path, text in sources.items():
        if path not in compiled:
            continue
        per_line = guards(text)
        for head, _, _, name in blocks(text):
            if not name or not plain_function(name):
                continue
            if name in functions.get(path, ()):
                tally["present"] += 1
            elif switched_off(per_line[head], config):
                tally["absent_guarded"] += 1
            elif name in symbols:
                tally["absent_with_symbol"] += 1
                unexplained.append(f"{path}:{name} (tem símbolo)")
            else:
                tally["absent_unexplained"] += 1
                unexplained.append(f"{path}:{name}")
    print(refined["version"], "scanner vs DWARF", tally)
    print(" sample", unexplained[:30])

    proved = 0
    for finding in retired:
        print(" ", finding["cve"], finding["score"], finding["title"][:70])
        confirmed = True
        for item in finding["edits"]["absent"]:
            if ":" not in item:
                confirmed &= item not in compiled
                print("     file", item, "compiled" if item in compiled else "not compiled")
                continue
            path, name = item.rsplit(":", 1)
            text = sources[path]
            head = next(b[0] for b in blocks(text) if b[3] == name)
            conditions = guards(text)[head]
            states = [(expression, wanted, condition(expression, config)) for expression, wanted in conditions]
            off = switched_off(conditions, config)
            confirmed &= off and name not in symbols
            print("     func", item, "symbol" if name in symbols else "no symbol", "off" if off else "NOT PROVEN", states)
        proved += confirmed
    Path(sys.argv[5]).write_text(json.dumps({"retired": len(retired), "proved": proved, **tally}, indent=1))
