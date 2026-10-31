# Firmware Observatory

Compares two OpenWrt versions for a router and shows what changed: packages, services, hardening and open vulnerabilities. No firmware code is run.

Live site: <https://potrix578.github.io/observatory-firmware/>

## Setup

Requires Python 3.14 or later, for its native zstd support.

```bash
python -m venv .venv
```

```bash
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run

```bash
.venv\Scripts\python.exe -I tools/observatory.py tplink_archer-c7-v5 24.10.8 25.12.6
```

The report is written to `reports/<device>/<old>_to_<new>.md`. A second run only repeats the steps whose inputs changed. CVE sources are refreshed after 7 days.

The command also updates the site in `site/`. `index.html` is a single page that works on any static host, and it can be rebuilt with:

```bash
.venv\Scripts\python.exe -I tools/build_site.py site
```

## Adding a router

Add its name and OpenWrt target to `data/devices.json`. The target must publish `kernel-debug.tar.zst` and `kmod-ikconfig`. For now, only 32-bit `sysupgrade` images with uImage and SquashFS are supported.

## Manual review

Verdicts live in `data/triage/<device>.json`, by version:

- `components`: programs outside the kernel.
- `kernel`: kernel CVEs.

A verdict only applies to the device it was reviewed on, because many depend on the build. `data/fixed-by-hand.json` holds code confirmations by kernel version, and those apply to any router with that kernel.

## Publishing

The site is published to GitHub Pages by `.github/workflows/pages.yml` whenever `site/` changes on the `main` branch. In Settings, Pages, choose GitHub Actions as the source.

The site makes no third-party requests: the fonts are in `site/fonts`, with their licenses.

## Redistribution

Images, kernel archives, caches and intermediate results stay out of Git. Publish only metadata, hashes and results.

## Data

This product uses data from the NVD API but is not endorsed or certified by the NVD. It also uses data from OSV and the CVE List.

## License

The code is under the MIT license: see `LICENSE`. The fonts in `site/fonts` keep their own licenses, and third-party data follows the terms of its sources.
