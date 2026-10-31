"""Download one device's OpenWrt release and verify it against the published hashes.

Writes fetched.json next to the files, with the paths the other tools need. Images are
kept locally for analysis and must not be redistributed.

    python -I tools/fetch_firmware.py <device> <target> <release> <firmware_dir>
"""
import gzip
import hashlib
import io
import json
import re
import shutil
import sys
import tarfile
import urllib.request
import zlib
from pathlib import Path

BASE_URL = "https://downloads.openwrt.org/releases/{release}/targets/{target}"
KERNEL_URL = "https://cdn.kernel.org/pub/linux/kernel/v{major}.x/linux-{version}.tar.xz"
SOURCE_URL = "https://github.com/openwrt/openwrt/archive/refs/tags/v{release}.tar.gz"
USER_AGENT = "firmware-observatory-poc"


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url, path, expected=None):
    if path.exists() and (expected is None or sha256(path) == expected):
        return path
    partial = path.with_name(path.name + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response, open(partial, "wb") as output:
        shutil.copyfileobj(response, output, 1 << 20)
    if expected is not None and sha256(partial) != expected:
        partial.unlink()
        raise RuntimeError(f"hash mismatch: {url}")
    partial.replace(path)
    return path


def package_blobs(data):
    """Payloads of an .apk (v3, deflate) or .ipk (nested tar.gz) package."""
    if data[:4] == b"ADBd":
        yield zlib.decompress(data[4:], -15)
        return
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as outer:
        inner = outer.extractfile(next(m for m in outer if m.name.endswith("data.tar.gz"))).read()
    with tarfile.open(fileobj=io.BytesIO(inner), mode="r:gz") as tree:
        for member in tree:
            if member.isfile():
                yield tree.extractfile(member).read()


def embedded_config(package):
    """The kernel .config that kmod-ikconfig stores between its two markers."""
    for blob in package_blobs(package.read_bytes()):
        start, end = blob.find(b"IKCFG_ST"), blob.find(b"IKCFG_ED")
        if start >= 0 and end > start:
            return gzip.decompress(blob[start + 8:end]).decode("utf-8", "replace")
    raise RuntimeError(f"no embedded config in {package}")


def kernel_hash(source_tar, version):
    """The kernel tarball hash pinned by this OpenWrt release."""
    series = ".".join(version.split(".")[:2])
    pattern = re.compile(rf"LINUX_KERNEL_HASH-{re.escape(version)}\s*=\s*(\w+)|^\s*{re.escape(version.split('.')[-1])}\s*=\s*(\w+)", re.M)
    with tarfile.open(source_tar) as tree:
        for member in tree:
            name = member.name.split("/", 1)[-1]
            if member.isfile() and name in (f"include/kernel-{series}", f"target/linux/generic/kernel-{series}"):
                text = tree.extractfile(member).read().decode("utf-8", "replace")
                match = pattern.search(text)
                if match and text.count(f"LINUX_VERSION-{series}"):
                    return match.group(1) or match.group(2)
    raise RuntimeError(f"no pinned hash for linux-{version}")


if __name__ == "__main__":
    device, target, release, firmware_dir = sys.argv[1:5]
    root = Path(firmware_dir)
    folder, sources = root / target.replace("/", "_") / release, root / "sources"
    folder.mkdir(parents=True, exist_ok=True)
    sources.mkdir(parents=True, exist_ok=True)
    base = BASE_URL.format(release=release, target=target)

    sums_path = download(f"{base}/sha256sums", folder / "sha256sums.new")
    sums_path.replace(folder / "sha256sums")
    hashes = {name: value for value, name in re.findall(r"^(\w{64}) \*(\S+)$", (folder / "sha256sums").read_text(), re.M)}
    request = urllib.request.Request(f"{base}/profiles.json", headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        profiles = json.load(response)

    image = next(i for i in profiles["profiles"][device]["images"] if i["type"] == "sysupgrade")
    kernel = profiles["linux_kernel"]["version"]
    manifest = f"openwrt-{release}-{target.replace('/', '-')}.manifest"
    ikconfig = next(name for name in hashes if re.search(r"^kmods/.*/kmod-ikconfig[_-]", name))

    download(f"{base}/{image['name']}", folder / image["name"], image["sha256"])
    download(f"{base}/{manifest}", folder / manifest, hashes[manifest])
    download(f"{base}/config.buildinfo", folder / "config.buildinfo", hashes["config.buildinfo"])
    debug = download(f"{base}/kernel-debug.tar.zst", folder / "kernel-debug.tar.zst", hashes["kernel-debug.tar.zst"])
    package = download(f"{base}/{ikconfig}", folder / ikconfig.rsplit("/", 1)[1], hashes[ikconfig])
    config = folder / "kernel.config"
    config.write_text(embedded_config(package), encoding="utf-8")

    source = download(SOURCE_URL.format(release=release), sources / f"openwrt-{release}.tar.gz")
    linux = download(
        KERNEL_URL.format(major=kernel.split(".")[0], version=kernel),
        sources / f"linux-{kernel}.tar.xz",
        kernel_hash(source, kernel),
    )
    manifest_path = folder / manifest
    (folder / f"fetched-{device}.json").write_text(json.dumps({
        "image": str(folder / image["name"]),
        "manifest": str(manifest_path),
        "debug": str(debug),
        "config": str(config),
        "linux": str(linux),
        "openwrt_source": str(source),
        "kernel": kernel,
    }, indent=1))
    print(device, release, "kernel", kernel, "verified")
