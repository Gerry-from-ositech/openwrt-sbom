# Packages.manifest Metadata Analysis

## File Locations

Packages.manifest files are found in two locations:

| Location | Purpose |
|----------|---------|
| `bin/targets/<target>/<subtarget>/packages/Packages.manifest` | Target-specific packages (kernel modules, base system) |
| `bin/packages/<arch>/<feed>/Packages.manifest` | Feed packages (base, luci, packages, routing, telephony, vendor) |

## Format

RFC 822 key:value format, same as IPK control files. Packages separated by blank lines.

**Example entry:**
```
Package: curl
Version: 7.83.1-1
Depends: libc, libcurl4
Source: package/network/utils/curl
SourceName: curl
License: MIT
LicenseFiles: COPYING
Section: net
SourceDateEpoch: 1708485017
CPE-ID: cpe:/a:haxx:libcurl
Maintainer: Imre Kaloz <kaloz@openwrt.org>
Architecture: aarch64_cortex-a53
Installed-Size: 91443
Filename: curl_7.83.1-1_aarch64_cortex-a53.ipk
Size: 92187
SHA256sum: 8a7f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
Description:  A client-side URL transfer utility
```

---

## Package Distribution

| Manifest Location | Package Count | CPE-IDs |
|-------------------|---------------|---------|
| targets/.../packages/ | 165 | 11 |
| packages/.../base/ | 137 | 29 |
| packages/.../packages/ | 75 | 37 |
| packages/.../luci/ | 11 | 0 |
| packages/.../mtk_openwrt_feed/ | 5 | 0 |
| packages/.../routing/ | 0 | 0 |
| packages/.../telephony/ | 0 | 0 |
| **Total** | **393** | **77** |

---

## Field Presence Summary (393 packages)

| Field | Count | % | Notes |
|-------|-------|---|-------|
| Package | 393 | 100% | Canonical package name |
| Version | 393 | 100% | Upstream version + package release |
| Source | 393 | 100% | Build tree path to package Makefile |
| SourceName | 393 | 100% | Logical source package (differs for sub-packages) |
| Section | 393 | 100% | Category classification |
| SourceDateEpoch | 393 | 100% | Unix timestamp of source |
| Architecture | 393 | 100% | `aarch64_cortex-a53` or `all` |
| Installed-Size | 393 | 100% | Uncompressed size in bytes |
| Filename | 393 | 100% | IPK filename |
| Size | 393 | 100% | Compressed IPK size in bytes |
| SHA256sum | 393 | 100% | SHA-256 hash of IPK file |
| Description | 393 | 100% | Human-readable description |
| Depends | 391 | 99.5% | Runtime dependencies |
| License | 336 | 85.5% | SPDX or legacy license identifier |
| Maintainer | 173 | 44.0% | Package maintainer email |
| LicenseFiles | 92 | 23.4% | Paths to license files within package |
| CPE-ID | 77 | 19.6% | CPE 2.2 URI for vulnerability tracking |
| Provides | 64 | 16.3% | Virtual package aliases |
| ABIVersion | 50 | 12.7% | Library ABI version suffix |
| Require-User | 8 | 2.0% | Required system users/groups |
| Essential | 7 | 1.8% | Package is essential for system operation |
| Status | 5 | 1.3% | Toolchain packages only |
| Conflicts | 5 | 1.3% | Package conflicts |
| Alternatives | 5 | 1.3% | Symlink alternatives system |

---

## Fields Unique to Packages.manifest (not in IPK control)

| Field | Purpose | Example |
|-------|---------|---------|
| Filename | IPK filename for download | `curl_7.83.1-1_aarch64_cortex-a53.ipk` |
| Size | Compressed IPK file size | `92187` |
| SHA256sum | IPK file hash | `8a7f3b2c1d4e5f6a...` |

These enable package verification without extracting IPK archives.

---

## Section Categories

| Section | Count | Description |
|---------|-------|-------------|
| kernel | 138 | Kernel modules (kmod-*) |
| libs | 90 | Shared libraries |
| net | 51 | Networking tools and services |
| utils | 36 | Utilities |
| base | 22 | Base system packages |
| MTK Properties | 18 | MediaTek vendor packages |
| Ositech | 15 | Ositech custom packages |
| luci | 8 | LuCI web interface |
| lang | 5 | Language runtime/libs |
| application | 5 | Applications |

---

## License Variations (Top 10)

| License | Count |
|---------|-------|
| GPL-2.0 | 190 |
| MIT | 22 |
| ISC | 17 |
| LGPL-2.1-or-later | 12 |
| GPL-2.0-or-later | 12 |
| BSD-3-Clause | 12 |
| LGPL-2.1 | 11 |
| GPL-2.0-only | 6 |
| Apache-2.0 | 6 |
| GPLv2 | 5 |

57 packages (14.5%) have no License field.

---

## Special Package Types

### Toolchain Packages
Packages with `Status: unknown hold not-installed`:
- libatomic1, libgcc1, libpthread, librt, libstdcpp6

These are built into the rootfs directly, not installed as packages.

### Kernel Modules (kmod-*)
- 138 packages with `Section: kernel`
- All have `Depends: kernel (=5.4.213-1-<build_hash>)`
- No CPE-ID (inherit kernel's CVE exposure)

### Essential Packages
7 packages marked `Essential: yes` (busybox, opkg, toolchain libs)

---

## Packages.manifest vs IPK Control

| Field | IPK Control | Packages.manifest |
|-------|-------------|-------------------|
| Filename | No | **Yes** |
| Size | No | **Yes** |
| SHA256sum | No | **Yes** |
| Status | No | **Yes** (toolchain only) |
| All other fields | Yes | Yes |

---

## What Packages.manifest Does NOT Provide

- PKG_HASH (source tarball hash) - must come from Makefile
- Upstream source URL - must come from Makefile
- Patch list - must come from build directory
- Full CPE for 81% of packages missing it
