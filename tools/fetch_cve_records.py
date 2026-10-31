"""Cache CVE List records for kernel candidates, which carry the affected source files.

    python -I tools/fetch_cve_records.py <cache_dir> <cves.json> <done_marker>
"""
import concurrent.futures
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
USER_AGENT = "firmware-observatory-poc"
MAX_CACHE_DAYS = 7


def fetch(cve, cache):
    path = cache / f"{cve}.json"
    if path.exists() and time.time() - path.stat().st_mtime < MAX_CACHE_DAYS * 86400:
        return "cached"
    year, number = cve.split("-")[1:]
    url = f"{BASE_URL}/{year}/{number[:-3]}xxx/{cve}.json"
    for attempt in range(5):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=60) as response:
                path.write_bytes(response.read())
            return "fetched"
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return "missing"
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(2 * (attempt + 1))
    return "failed"


if __name__ == "__main__":
    cache = Path(sys.argv[1])
    cache.mkdir(parents=True, exist_ok=True)
    ids = sorted(json.loads(Path(sys.argv[2]).read_text())["kernel"]["ids"])
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda c: (c, fetch(c, cache)), ids))
    tally = {}
    for _, status in results:
        tally[status] = tally.get(status, 0) + 1
    print(len(ids), tally, [c for c, s in results if s in ("missing", "failed")][:20])
    Path(sys.argv[3]).write_text(json.dumps(tally))
