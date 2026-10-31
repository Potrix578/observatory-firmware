"""Correlate an analyze_firmware.py result with NVD, OSV and the OpenWrt source tree.

A match means the upstream version is listed as affected. It does not prove the
device is vulnerable: see the status values written to the output.

    python -I tools/correlate_cves.py <analysis.json> <openwrt-src.tar.gz> <cache_dir> <output.json> <triage.json>
"""
import hashlib
import json
import re
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/query"
KERNEL_REPO = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
NVD_DELAY_SECONDS = 7
MAX_CACHE_DAYS = 7
USER_AGENT = "firmware-observatory-poc"

# package -> (component, CPE product strings, OSV git repository, version -> git tag)
COMPONENTS = {
    "busybox": ("busybox", ["busybox:busybox"], None, None),
    "dropbear": ("dropbear", ["dropbear_ssh_project:dropbear_ssh"],
                 "https://github.com/mkj/dropbear", lambda v: f"DROPBEAR_{v}"),
    "dnsmasq": ("dnsmasq", ["thekelleys:dnsmasq"], None, None),
    "libmbedtls21": ("mbedtls", ["arm:mbed_tls", "arm:mbedtls"],
                     "https://github.com/Mbed-TLS/mbedtls", lambda v: f"v{v}"),
    "libc": ("musl", ["musl-libc:musl"], None, None),
    "zlib": ("zlib", ["zlib:zlib", "gnu:zlib"], "https://github.com/madler/zlib", lambda v: f"v{v}"),
    "nftables-json": ("nftables", ["netfilter:nftables"], None, None),
    "libnftnl11": ("libnftnl", ["netfilter:libnftnl"], None, None),
    "libmnl0": ("libmnl", ["netfilter:libmnl"], None, None),
    "jansson4": ("jansson", ["jansson_project:jansson", "digip:jansson"],
                 "https://github.com/akheron/jansson", lambda v: f"v{v}"),
    "libjson-c5": ("json-c", ["json-c_project:json-c", "json-c:json-c"], None, None),
    "ppp": ("ppp", ["samba:ppp", "point-to-point_protocol_project:point-to-point_protocol"], None, None),
}


CONSULTED = set()


def upstream_version(version):
    return re.sub(r"-r\d+$", "", version)


def is_fresh(path):
    return path.exists() and time.time() - path.stat().st_mtime < MAX_CACHE_DAYS * 86400


def fetch_json(request, cache_path):
    if is_fresh(cache_path):
        CONSULTED.add(time.strftime("%Y-%m-%d", time.gmtime(cache_path.stat().st_mtime)))
        return json.loads(cache_path.read_text())
    CONSULTED.add(time.strftime("%Y-%m-%d", time.gmtime()))
    for attempt in range(6):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                data = json.load(response)
            cache_path.write_text(json.dumps(data))
            return data
        except urllib.error.HTTPError as error:
            if error.code == 404:
                data = {"totalResults": 0, "vulnerabilities": [], "vulns": []}
                cache_path.write_text(json.dumps(data))
                return data
            if error.code not in (403, 429, 500, 502, 503, 504):
                raise
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(NVD_DELAY_SECONDS * (attempt + 1))
    raise RuntimeError(f"source unavailable: {request.full_url}")


def cache_file(cache, key):
    return cache / (hashlib.sha256(key.encode()).hexdigest()[:24] + ".json")


def query_nvd(cpe, cache):
    records, start = [], 0
    while True:
        query = urllib.parse.urlencode({"virtualMatchString": cpe, "startIndex": start}, safe=":*")
        url = f"{NVD_URL}?{query}"
        path = cache_file(cache, url)
        cached = is_fresh(path)
        data = fetch_json(urllib.request.Request(url, headers={"User-Agent": USER_AGENT}), path)
        if not cached:
            time.sleep(NVD_DELAY_SECONDS)
        records += data.get("vulnerabilities", [])
        start += data.get("resultsPerPage", 0) or len(data.get("vulnerabilities", []))
        if not data.get("resultsPerPage") or start >= data.get("totalResults", 0):
            return records


def query_osv(package, version, cache):
    records, token = [], None
    while True:
        body = {"package": package, "version": version}
        if token:
            body["page_token"] = token
        encoded = json.dumps(body, sort_keys=True).encode()
        path = cache_file(cache, encoded.decode())
        data = fetch_json(urllib.request.Request(OSV_URL, encoded, {"Content-Type": "application/json"}), path)
        records += data.get("vulns", [])
        token = data.get("next_page_token")
        if not token:
            return records


def nvd_fields(record):
    cve = record["cve"]
    metrics = cve.get("metrics", {})
    score, severity = None, None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0]
            score = data["cvssData"].get("baseScore")
            severity = data["cvssData"].get("baseSeverity") or data.get("baseSeverity")
            break
    summary = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    return {
        "published": cve.get("published", "")[:10],
        "score": score,
        "severity": severity,
        "summary": summary[:300],
        "disputed": "disputed" in summary.lower() or cve.get("vulnStatus") == "Rejected",
    }


def source_mentions(tarball):
    """CVE ids mentioned in package, toolchain and kernel-generic files of the OpenWrt tree."""
    mentions = {}
    with tarfile.open(tarball) as tree:
        for member in tree:
            path = member.name.split("/", 1)[-1]
            if not member.isfile() or not path.startswith(("package/", "toolchain/", "target/linux/generic/")):
                continue
            text = tree.extractfile(member).read().decode("utf-8", "replace")
            for cve in set(re.findall(r"CVE-\d{4}-\d{4,}", path + "\n" + text)):
                mentions.setdefault(cve, []).append(path)
    return mentions


def correlate(analysis, tarball, cache, triage_rules):
    packages = analysis["packages"]
    mentions = source_mentions(tarball)
    release = re.search(r"DISTRIB_RELEASE='([^']+)'", analysis["release"]).group(1)
    findings, queried = {}, []

    def add(cve, component, version, source, fields=None):
        entry = findings.setdefault(cve, {
            "cve": cve, "component": component, "version": version, "sources": [],
            "published": "", "score": None, "severity": None, "summary": "", "disputed": False,
        })
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if fields:
            entry.update(fields)

    for package, (component, cpes, repo, tag) in COMPONENTS.items():
        if package not in packages:
            continue
        version = upstream_version(packages[package])
        queried.append({"component": component, "version": version})
        for product in cpes:
            part = f"cpe:2.3:a:{product}:{version}"
            for record in query_nvd(part, cache):
                add(record["cve"]["id"], component, version, "nvd", nvd_fields(record))
        if repo:
            for record in query_osv({"name": repo, "ecosystem": "GIT"}, tag(version), cache):
                cve = next((a for a in [record["id"], *record.get("aliases", [])] if a.startswith("CVE-")), record["id"])
                add(cve, component, version, "osv")

    for record in query_nvd(f"cpe:2.3:o:openwrt:openwrt:{release}", cache):
        add(record["cve"]["id"], "openwrt", release, "nvd", nvd_fields(record))
    queried.append({"component": "openwrt", "version": release})

    kernel_version = packages["kernel"].split("~")[0]
    kernel_osv = {
        next((a for a in [r["id"], *r.get("aliases", [])] if a.startswith("CVE-")), r["id"])
        for r in query_osv({"name": KERNEL_REPO, "ecosystem": "GIT"}, f"v{kernel_version}", cache)
    }
    kernel_nvd = {
        r["cve"]["id"]: nvd_fields(r)
        for r in query_nvd(f"cpe:2.3:o:linux:linux_kernel:{kernel_version}", cache)
    }
    kernel_ids = sorted(kernel_osv | set(kernel_nvd))
    kernel_severity = {}
    for fields in kernel_nvd.values():
        label = fields["severity"] or "UNSCORED"
        kernel_severity[label] = kernel_severity.get(label, 0) + 1

    triage = triage_rules.get(release, {}).get("components", {})
    for entry in findings.values():
        entry["openwrt_files"] = sorted(mentions.get(entry["cve"], []))
        verdict = triage.get(entry["cve"], {})
        entry["status"] = verdict.get("status", "possibly_affected")
        entry["reason"] = verdict.get("reason", "No manual review.")

    return {
        "release": release,
        "consulted": min(CONSULTED),
        "queried": queried,
        "not_queried": [
            "wpad-basic-mbedtls/hostapd (date snapshot, no upstream release version)",
            "OpenWrt's own projects (only via the openwrt CPE)",
        ],
        "kernel": {
            "version": kernel_version,
            "candidates": len(kernel_ids),
            "osv_candidates": len(kernel_osv),
            "nvd_candidates": len(kernel_nvd),
            "nvd_severity": kernel_severity,
            "mentioned_in_openwrt_source": sorted(c for c in kernel_ids if c in mentions),
            "ids": kernel_ids,
            "nvd": {
                c: {"score": f["score"], "severity": f["severity"], "published": f["published"]}
                for c, f in kernel_nvd.items()
            },
        },
        "findings": sorted(findings.values(), key=lambda f: (-(f["score"] or 0), f["cve"])),
    }


if __name__ == "__main__":
    analysis_path, tarball, cache_dir, output, triage_path = sys.argv[1:6]
    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    # A device without manual review has every finding as "To confirm".
    rules = json.loads(Path(triage_path).read_text(encoding="utf-8")) if Path(triage_path).exists() else {}
    result = correlate(json.loads(Path(analysis_path).read_text()), tarball, cache, rules)
    Path(output).write_text(json.dumps(result, indent=1))
    print(result["release"], len(result["findings"]), "findings,", result["kernel"]["candidates"], "kernel candidates")
