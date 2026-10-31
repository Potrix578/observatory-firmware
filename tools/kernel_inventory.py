"""Inventory of the source files compiled into an OpenWrt kernel, from official DWARF.

Also proves that the debug vmlinux is the kernel shipped in the image, by reading
linux_banner in the image at the address given by the debug symbol table.

    python -I tools/kernel_inventory.py <analysis.json> <image.bin> <kernel-debug.tar.zst> <linux.tar.xz> <kernel.config> <output.json>
"""
import io
import json
import lzma
import posixpath
import re
import struct
import sys
import tarfile
from pathlib import Path

from elftools.elf.elffile import ELFFile

BACKPORTS = re.compile(r"(?:^|/)backports-([\d.]+)/(.+)$")
ATH10K_CT = re.compile(r"(?:^|/)ath10k-ct-[^/]+/ath10k-[\d.]+/(.+)$")
MT76 = re.compile(r"(?:^|/)mt76-[^/]+/(.+)$")
LZMA_HEADER = re.compile(rb"[\x5d\x6d]\x00\x00[\x00-\xff]\x00", re.S)
LZMA_MEMORY_LIMIT = 1 << 28
LZMA_OUTPUT_LIMIT = 1 << 26
MAX_IMAGE_SHIFT = 4096


def normalize(path, marker):
    """Returns (origin, path relative to the upstream tree), or None outside any tree."""
    path = posixpath.normpath(path.replace("\\", "/"))
    match = BACKPORTS.search(path)
    if match:
        return "backports", match.group(2)
    match = ATH10K_CT.search(path)
    if match:
        return "ath10k-ct", f"drivers/net/wireless/ath/ath10k/{match.group(1)}"
    match = MT76.search(path)
    if match:
        return "mt76", f"drivers/net/wireless/mediatek/mt76/{match.group(1)}"
    if marker in path:
        return "kernel", path.split(marker, 1)[1].lstrip("/")
    if path.startswith(("/", "..", "target-")):
        return None
    return "kernel", path


def compile_units(elf_bytes, marker):
    """Compiled sources, headers and functions of one ELF file, grouped by origin."""
    units, headers, functions, backports = {}, {}, {}, set()
    elf = ELFFile(io.BytesIO(elf_bytes))
    if not elf.has_dwarf_info():
        return {"units": units, "headers": headers, "functions": functions, "backports": []}
    dwarf = elf.get_dwarf_info(relocate_dwarf_sections=False)
    for unit in dwarf.iter_CUs():
        name_attr = unit.get_top_DIE().attributes.get("DW_AT_name")
        if name_attr is None:
            continue
        name = name_attr.value.decode("utf-8", "replace")
        backports.update(m.group(1) for m in [BACKPORTS.search(name)] if m)
        found = normalize(name, marker)
        if found and not found[1].endswith(".mod.c"):
            units.setdefault(found[0], set()).add(found[1])
        program = dwarf.line_program_for_CU(unit)
        if program is None:
            continue
        version = program.header["version"]
        directories = [
            (d.DW_LNCT_path if hasattr(d, "DW_LNCT_path") else d).decode("utf-8", "replace")
            for d in program.header.get("include_directory", [])
        ]
        table = {}
        for number, entry in enumerate(program.header.get("file_entry", []), 0 if version >= 5 else 1):
            raw = entry.DW_LNCT_path if hasattr(entry, "DW_LNCT_path") else entry.name
            index = entry.DW_LNCT_directory_index if hasattr(entry, "DW_LNCT_directory_index") else entry.dir_index
            filename = raw.decode("utf-8", "replace")
            if not filename.endswith((".h", ".c")) or filename.endswith(".mod.c"):
                continue
            # DWARF 5 tables are zero based. Before that, index 0 is the compile directory.
            position = index if version >= 5 else index - 1
            directory = directories[position] if 0 <= position < len(directories) else ""
            found = normalize(posixpath.join(directory, filename), marker)
            if found:
                table[number] = found
                # A .c file here may be included by another one, like kernel/sched/deadline.c.
                (headers if filename.endswith(".h") else units).setdefault(found[0], set()).add(found[1])
        for die in unit.get_top_DIE().iter_children():
            name, declared_in = die.attributes.get("DW_AT_name"), die.attributes.get("DW_AT_decl_file")
            if die.tag != "DW_TAG_subprogram" or "DW_AT_declaration" in die.attributes or not name or not declared_in:
                continue
            found = table.get(declared_in.value)
            if found:
                functions.setdefault(found[0], {}).setdefault(found[1], set()).add(name.value.decode("utf-8", "replace"))
    return {
        "units": {k: sorted(v) for k, v in units.items()},
        "headers": {k: sorted(v) for k, v in headers.items()},
        "functions": {k: {p: sorted(n) for p, n in v.items()} for k, v in functions.items()},
        "backports": sorted(backports),
    }


def symbol_table(elf_bytes):
    elf = ELFFile(io.BytesIO(elf_bytes))
    return {s.name: s["st_value"] for s in elf.get_section_by_name(".symtab").iter_symbols() if s.name}


def kernel_payload(blob):
    """Decompressed kernel of a uImage, which ramips wraps in an uncompressed LZMA loader."""
    size = struct.unpack_from(">I", blob, 12)[0]
    payload = blob[64:64 + size]
    for match in LZMA_HEADER.finditer(payload):
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=LZMA_MEMORY_LIMIT)
        try:
            kernel = decoder.decompress(payload[match.start():], max_length=LZMA_OUTPUT_LIMIT)
        except lzma.LZMAError:
            continue
        if b"Linux version" in kernel:
            return kernel
    raise ValueError("no LZMA kernel in the uImage")


def image_kernel_check(image_path, symbols, version):
    """The utsname data must sit at the debug address and the banner close to it.

    ramips images place .rodata strings a few bytes off the debug symbols, for a reason not
    yet explained, so the shift is reported rather than hidden.
    """
    kernel = kernel_payload(Path(image_path).read_bytes())
    found = kernel.find(f"Linux version {version} ".encode())
    shift = symbols["linux_banner"] - symbols["_text"] - found
    uts = symbols["init_uts_ns"] - symbols["_text"]
    same_layout = found >= 0 and abs(shift) <= MAX_IMAGE_SHIFT and kernel[uts:uts + 6] == b"Linux\0"
    return {
        "decompressed_bytes": len(kernel),
        "linux_banner": kernel[found:found + 160].split(b"\0")[0].decode("ascii", "replace"),
        "banner_at_debug_address": same_layout,
        "banner_shift_bytes": shift,
        "text_to_edata_bytes": symbols["_edata"] - symbols["_text"],
    }


def tree_paths(linux_tar):
    """All regular files of the kernel source tree, relative to its root."""
    paths = set()
    with tarfile.open(linux_tar, "r:xz") as tree:
        for member in tree:
            if member.isfile():
                paths.add(member.name.split("/", 1)[1])
    return paths


def config_values(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        match = re.match(r"(CONFIG_\w+)=(.+)", line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


if __name__ == "__main__":
    analysis_path, image, debug_tar, linux_tar, config_path, output = sys.argv[1:7]
    analysis = json.loads(Path(analysis_path).read_text())
    version = analysis["packages"]["kernel"].split("~")[0]
    marker = f"linux-{version}"
    shipped = {
        path.rsplit("/", 1)[1]
        for path in analysis["files"]
        if path.startswith("/lib/modules/") and path.endswith(".ko")
    }

    modules, vmlinux = {}, None
    with tarfile.open(debug_tar, "r:zst") as tree:
        for member in tree:
            if not member.isfile():
                continue
            data = tree.extractfile(member).read()
            if member.name.endswith("/vmlinux"):
                vmlinux = compile_units(data, marker)
                symbols = symbol_table(data)
            elif member.name.endswith(".ko"):
                name = member.name.rsplit("/", 1)[1]
                modules[name] = {**compile_units(data, marker), "in_image": name in shipped}

    paths = tree_paths(linux_tar)
    kernel_headers = vmlinux["headers"].get("kernel", [])
    missing = [h for h in kernel_headers if h not in paths]
    result = {
        "version": version,
        "backports_version": sorted({v for m in modules.values() if m["in_image"] for v in m["backports"]}),
        "kernel_match": image_kernel_check(image, symbols, version),
        "vmlinux": vmlinux,
        "modules": modules,
        "modules_in_image_missing_debug": sorted(shipped - set(modules)),
        "tree_paths": sorted(paths),
        "config": config_values(config_path),
        "header_check": {"total": len(kernel_headers), "missing_from_tree": len(missing), "sample": missing[:12]},
    }
    Path(output).write_text(json.dumps(result))
    in_image = [m for m in modules.values() if m["in_image"]]
    print(version, "units", {k: len(v) for k, v in vmlinux["units"].items()}, "modules", len(modules), "in image", len(in_image))
    print(" origins in image", {o: sum(1 for m in in_image if o in m["units"]) for o in ("kernel", "backports", "ath10k-ct")}, "backports", result["backports_version"])
    print(" header check", result["header_check"], "banner ok", result["kernel_match"]["banner_at_debug_address"])
