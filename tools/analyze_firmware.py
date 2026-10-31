"""Static firmware analysis for OpenWrt sysupgrade images.

The image is read in memory: nothing from it is executed or written to disk.

    python -I tools/analyze_firmware.py <image.bin> <manifest> <output.json>
"""
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from PySquashfsImage import SquashFsImage

PT_DYNAMIC, PT_GNU_STACK, PT_GNU_RELRO = 2, 0x6474E551, 0x6474E552
DT_NEEDED, DT_STRTAB, DT_FLAGS, DT_FLAGS_1, DT_BIND_NOW = 1, 5, 30, 0x6FFFFFFB, 24
SECRET_PATTERNS = {
    # A PEM body is required: TLS libraries ship the bare header strings.
    "private_key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----\r?\n[A-Za-z0-9+/]{40}"),
    # A shadow-style line is required: musl ships a crypt self-test hash.
    "password_hash": re.compile(rb"(?m)^[a-z_][a-z0-9_-]*:\$(?:1|5|6|y)\$[./A-Za-z0-9$]{8,}"),
}


def uimage_name(blob):
    """Name field of the legacy uImage header, which carries the kernel version."""
    if blob[:4] != b"\x27\x05\x19\x56":
        return None
    return blob[32:64].split(b"\0")[0].decode("ascii", "replace")


def parse_elf(data):
    """Hardening facts from ELF headers. Returns None if data is not an ELF file."""
    if data[:4] != b"\x7fELF":
        return None
    if data[4] != 1:
        raise ValueError("64-bit ELF files are not supported yet")
    end = ">" if data[5] == 2 else "<"
    e_type = struct.unpack_from(end + "H", data, 16)[0]
    e_phoff = struct.unpack_from(end + "I", data, 28)[0]
    e_phentsize, e_phnum = struct.unpack_from(end + "HH", data, 42)
    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, _, p_filesz, _, p_flags, _ = struct.unpack_from(end + "8I", data, off)
        segments.append((p_type, p_offset, p_vaddr, p_filesz, p_flags))

    def vaddr_to_offset(addr):
        for p_type, p_offset, p_vaddr, p_filesz, _ in segments:
            if p_type == 1 and p_vaddr <= addr < p_vaddr + p_filesz:
                return p_offset + addr - p_vaddr
        return None

    tags = []
    for p_type, p_offset, _, p_filesz, _ in segments:
        if p_type == PT_DYNAMIC:
            for pos in range(p_offset, p_offset + p_filesz, 8):
                tag, value = struct.unpack_from(end + "II", data, pos)
                if tag == 0:
                    break
                tags.append((tag, value))

    strtab = next((vaddr_to_offset(v) for t, v in tags if t == DT_STRTAB), None)
    needed = []
    if strtab is not None:
        for tag, value in tags:
            if tag == DT_NEEDED:
                raw = data[strtab + value:data.index(b"\0", strtab + value)]
                needed.append(raw.decode("ascii", "replace"))

    stack = [s for s in segments if s[0] == PT_GNU_STACK]
    bind_now = any(
        t == DT_BIND_NOW or (t == DT_FLAGS and v & 8) or (t == DT_FLAGS_1 and v & 1)
        for t, v in tags
    )
    return {
        "type": {1: "rel", 2: "exec", 3: "dyn"}.get(e_type, str(e_type)),
        "nx": bool(stack) and not stack[0][4] & 1,
        "relro": any(s[0] == PT_GNU_RELRO for s in segments),
        "bind_now": bind_now,
        "canary": b"__stack_chk_fail" in data,
        "needed": sorted(needed),
    }


def parse_opkg(text):
    packages = {}
    for block in text.split("\n\n"):
        fields = dict(re.findall(r"^(Package|Version): (.+)$", block, re.M))
        if "Package" in fields and "Version" in fields:
            packages[fields["Package"]] = fields["Version"]
    return packages


def parse_apk(text):
    packages = {}
    for block in text.split("\n\n"):
        fields = dict(re.findall(r"^([PV]):(.+)$", block, re.M))
        if "P" in fields and "V" in fields:
            packages[fields["P"]] = fields["V"]
    return packages


def parse_manifest(text):
    packages = {}
    for line in text.splitlines():
        if " - " in line:
            name, version = line.split(" - ", 1)
            packages[name.strip()] = version.strip()
    return packages


def analyze(image_path, manifest_path):
    blob = Path(image_path).read_bytes()
    offset = blob.find(b"hsqs")
    files, secrets, wanted = {}, [], {}
    config_paths = (
        "/etc/openwrt_release", "/etc/shadow", "/etc/config/firewall",
        "/etc/config/dropbear", "/etc/config/uhttpd", "/etc/config/system",
        "/usr/lib/opkg/status", "/lib/apk/db/installed",
    )
    with SquashFsImage.from_file(image_path, offset=offset) as image:
        items = list(image)
        for item in items:
            if item.is_dir:
                continue
            path = item.path
            if item.is_symlink:
                files[path] = {"kind": "symlink", "target": item.readlink()}
                continue
            if not item.is_file:
                files[path] = {"kind": "special", "mode": item.filemode}
                continue
            data = item.read_bytes()
            entry = {
                "kind": "file",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "mode": item.filemode,
                "setuid": bool(item.mode & 0o6000),
            }
            elf = parse_elf(data)
            if elf:
                entry["elf"] = elf
            for label, pattern in SECRET_PATTERNS.items():
                if pattern.search(data):
                    secrets.append({"path": path, "type": label})
            if path in config_paths:
                wanted[path] = data.decode("utf-8", "replace")
            files[path] = entry

    if "/usr/lib/opkg/status" in wanted:
        manager, packages = "opkg", parse_opkg(wanted["/usr/lib/opkg/status"])
    else:
        manager, packages = "apk", parse_apk(wanted.get("/lib/apk/db/installed", ""))

    shadow = {}
    for line in wanted.get("/etc/shadow", "").splitlines():
        parts = line.split(":")
        if len(parts) > 1:
            field = parts[1]
            shadow[parts[0]] = "empty" if field == "" else "locked" if field[0] in "*!x" else "hash"

    return {
        "image": Path(image_path).name,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "bytes": len(blob),
        "kernel_image": uimage_name(blob),
        "rootfs_offset": offset,
        "rootfs_bytes": len(blob) - offset,
        "release": wanted.get("/etc/openwrt_release", ""),
        "package_manager": manager,
        "packages": packages,
        "manifest": parse_manifest(Path(manifest_path).read_text()),
        "files": files,
        "services": sorted(p.rsplit("/", 1)[1] for p in files if p.startswith("/etc/init.d/")),
        "enabled_services": sorted(p.rsplit("/", 1)[1] for p in files if p.startswith("/etc/rc.d/S")),
        "accounts": shadow,
        "secret_candidates": secrets,
        "configs": {k: v for k, v in wanted.items() if k.startswith("/etc/config/")},
    }


if __name__ == "__main__":
    result = analyze(sys.argv[1], sys.argv[2])
    Path(sys.argv[3]).write_text(json.dumps(result, indent=1, sort_keys=True))
    print(result["image"], len(result["files"]), "files,", len(result["packages"]), "packages")
