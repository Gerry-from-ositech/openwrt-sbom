# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenWrt Metadata Extractor - A 3-phase pipeline that extracts package metadata from OpenWrt firmware builds and generates CycloneDX v1.6 SBOMs for vulnerability management.

## Pipeline Architecture

```
Phase 1: metadata_extractor.py → data.json (raw metadata from IPK files)
Phase 2: analyze_metadata.py   → enhanced_metadata.json (normalized, grouped)
Phase 3: generate_cyclonedx_sbom.py → sbom.json (CycloneDX v1.6)


**Key Principle:**  Each phase is standalone - consumes only the previous phase's output. Outputs are immutable.

Once created the SBOM is the immutable single source of truth for the project
Data can be extracted in order to feed the Vulnerability Managment scanner
 
Export:  dump_components_to_csv.py  → sbom_packages.csv (database-ready)
```


## Commands

```bash
# Full pipeline (run from project directory)
python3 metadata_extractor.py              # Phase 1: Extract from OpenWrt build
python3 analyze_metadata.py                # Phase 2: Enhance and normalize
python3 generate_cyclonedx_sbom.py         # Phase 3: Generate SBOM
python3 dump_components_to_csv.py          # Export: CSV for database import

# With options
python3 analyze_metadata.py --compress     # Output gzipped JSON
python3 generate_cyclonedx_sbom.py --pretty  # Pretty-print SBOM
python3 dump_components_to_csv.py -o custom.csv  # Custom output file

# Verification utility
python3 lookup_package.py                  # Interactive package lookup
python3 lookup_package.py <package_name>   # Direct lookup
python3 lookup_package.py --trace <name>   # Show search logic details
```

## Configuration

`config.json` defines the OpenWrt build location and project detail:
```json
{
    "openwrt_build_root": "OpenWRT21.02-Z8106",
    "project_name": "Explorer II - OpenWRT21.02-Z8106",
    "project_release": "z8106-v1.0.8.sub1-sysupgrade.bin"
}
```

The build root is relative to the parent directory of this project.

## Key Technical Details

### CPE Handling

**CPE sources (in priority order):**
1. IPK control file `CPE-ID` field
2. Package Makefile `PKG_CPE_ID` variable
3. `KNOWN_METADATA` dictionary (NVD-validated fallbacks)

**CPE version flow:**
- Phase 1: Extracts CPE with wildcard version (`cpe:2.3:a:sqlite:sqlite:*:...`)
- Phase 2: Computes `openwrt:version_upstream` from package version
- Phase 3: Updates CPE version field using upstream version (`cpe:2.3:a:sqlite:sqlite:3330000:...`)

**CPE inheritance:**
- `kmod-*` packages automatically inherit Linux kernel CPE in Phase 2
- Binary artifacts inherit CPE from their source component
- All CPEs normalized to CPE 2.3 format

### Version Normalization (analyze_metadata.py)
- Separates upstream version from OpenWrt release designation
- Handles variants: `2017.3.23-1-fuseext` → upstream `2017.3.23`
- CPE version uses normalized upstream version only

### Component Grouping
- Binary packages grouped by source path into source components
- Multiple artifacts (e.g., `libncurses6`, `terminfo`) share parent CPE
- `openwrt:source_component` property links binaries to source

### OpenWrt-Specific SBOM Properties
- `openwrt:release` - OpenWrt release version (e.g., "21.02") for CVE correlation
- `openwrt:depends` - Runtime dependencies (informational, see note below)
- `openwrt:patched_cves` - CVEs fixed by patches (for triage filtering)
- `openwrt:patches` - Applied patch filenames
- `openwrt:static_libs` - Statically linked libraries
- `openwrt:source_component` - Parent source package name
- `openwrt:provides` - Virtual package names this component provides
- `openwrt:version_upstream` - Upstream version (used in CPE)
- `openwrt:release_designation` - Package rebuild number (e.g., "-1" suffix)

### OpenWrt Release Detection

The `openwrt:release` property is extracted from `include/version.mk` in the build tree:
```makefile
VERSION_NUMBER:=$(if $(VERSION_NUMBER),$(VERSION_NUMBER),21.02-SNAPSHOT)
```

This enables vulnerability scanners to correlate packages (especially LuCI) with OpenWrt release-based CVEs. For example, CVE-2023-24182 uses `cpe:2.3:a:openwrt:openwrt:22.03.3` rather than individual package versions.

### Patched CVE Extraction

The `openwrt:patched_cves` property is automatically extracted from patch filenames in the build tree. OpenWrt maintainers conventionally name security patches with the CVE ID they fix.

**Source location:** `{source_path}/patches/` directory for each package

**Example (libexpat):**
```
feeds/packages/libs/expat/patches/
├── CVE-2021-45960.patch
├── CVE-2021-46143.patch
├── CVE-2022-22822.patch
└── ... (10 CVE patches)
```

**Extraction pattern:** `CVE-\d{4}-\d+` matches filenames like:
- `CVE-2022-37434.patch`
- `006-fix-CVE-2022-37434.patch`
- `102-CVE-2018-16301.patch`

**Triage value:** When a vulnerability scanner reports a CVE against a package, check `openwrt:patched_cves` to determine if it's already backported. For example, libexpat 2.2.10 in this build has 10 CVEs patched despite the older upstream version.

### Dependency Resolution

**Important:** The SBOM contains two representations of dependencies:

1. **CycloneDX `dependencies` section** (use this for dependency graphs)
   - Fully resolved - all references point to actual components
   - Virtual package names resolved to real package names
   - Uses bom-ref format: `pkg:opkg/libsqlite3-0@3330000-1`

2. **`openwrt:depends` property** (informational only)
   - Preserves original IPK control file dependency strings
   - May contain unresolved virtual package names (e.g., `libsqlite3` instead of `libsqlite3-0`)
   - May contain version constraints (e.g., `kernel (=5.4.213-1-...)`)

Virtual package mappings (e.g., `libsqlite3` → `libsqlite3-0`) are stored in `enhanced_metadata.json` under `virtual_packages` and are used during Phase 3 to build the resolved CycloneDX dependency graph.

## Dependencies

```
cyclonedx-python-lib
packageurl-python
```

## Output Files

| File | Description |
|------|-------------|
| `data.json` | Raw extracted metadata (~383 packages), includes `openwrt_release` |
| `enhanced_metadata.json` | Normalized with source grouping (~194 components) |
| `ExplorerII-OpenWRT21.02-Z8106_SBOM.json` | CycloneDX v1.6 SBOM (~383 binary components) |
| `sbom_packages.csv` | Deduplicated packages with CPE group info |

### CSV Export Format (dump_components_to_csv.py)

**sbom_packages.csv columns:**
```
pkgname,version,licenses,cpe,patched_cves,cpe_group
```

| Column | Description |
|--------|-------------|
| `pkgname` | Package name |
| `version` | Package version |
| `licenses` | SPDX license expression |
| `cpe` | CPE identifier (or "unknown") |
| `patched_cves` | Comma-separated CVE IDs already patched (quoted if multiple) |
| `cpe_group` | Related packages sharing the same CPE (quoted, comma-separated) |

**Example:**
```csv
libexpat,2.2.10-2,MIT,cpe:2.3:a:libexpat:expat:2.2.10:*:*:*:*:*:*:*,"CVE-2021-45960,CVE-2022-25315,...",
zlib,1.2.11-6,Zlib,cpe:2.3:a:gnu:zlib:1.2.11:*:*:*:*:*:*:*,CVE-2022-37434,
libncurses6,6.2-1,MIT,cpe:2.3:a:gnu:ncurses:6.2:*:*:*:*:*:*:*,,"libncurses6,terminfo"
```

## Utilities

### sbom_browser.py

Interactive CLI utility for browsing CycloneDX SBOMs:

```bash
python3 sbom_browser.py                    # Use default SBOM
python3 sbom_browser.py custom_sbom.json   # Use custom file
```

**Commands:**
- `list <pkgname> full` - Show full CycloneDX component structure (pprint)
- `list * full` - Show full structure for ALL packages
- `list * field1,field2,...` - List ALL packages with specified fields
- `list pkgnames [field1,field2,...]` - List sorted packages with optional fields
- `info` - Show SBOM metadata
- `search <pattern>` - Find packages by name
- `fields` - List available CycloneDX and OpenWrt fields
- `q` - Quit

**Examples:**
```
> list pkgnames version,cpe
> list * version,cpe
> list * openwrt:patched_cves,openwrt:source_component
> list luci-base full
> search sqlite
```

### no_linux_metadata.py

Utility to filter kernel components from metadata for testing:

```bash
python3 no_linux_metadata.py                        # Filter data.json → no_linux_data.json
python3 no_linux_metadata.py -i input.json -o out.json  # Custom files
```

Filters out components with `section: "kernel"` or names starting with `kmod-`.

### lookup_package.py

Interactive utility for verifying packages through the pipeline:

```
Package> sqlite3-cli
----------------------------------------------------------------------
Package: sqlite3-cli
----------------------------------------------------------------------
Status:  INCLUDED in firmware image

Version:      3330000-1
IPK CPE:      cpe:2.3:a:sqlite:sqlite:*:*:*:*:*:*:*:*
CPE Source:   ipk
SBOM CPE:     cpe:2.3:a:sqlite:sqlite:3330000:*:*:*:*:*:*:*
              ^ version '3330000' added in Phase 3
```

**Interactive commands:**
- `<package_name>` - Look up a package, shows both IPK and SBOM CPE
- `list` - List all installed packages
- `step` / `s` - Step through SBOM packages for verification
- `step *` / `s *` - Auto-step through all packages until failure
- `quit` / `q` - Exit

**Key features:**
- Shows IPK CPE (Phase 1) vs SBOM CPE (final) side-by-side
- Highlights when version is added during Phase 3
- Detects CPE inheritance from source components
- Validates SBOM against actual IPK files

## KNOWN_METADATA

The `KNOWN_METADATA` dictionary in `metadata_extractor.py` provides CPEs for packages that don't have `PKG_CPE_ID` in their IPK or Makefile. CPEs are NVD-validated.

**Key entries include:**
- `musl`, `libc`, `libpthread`, `librt` → `musl-libc:musl`
- `gcc`, `libgcc1`, `libatomic1`, `libstdcpp6` → `gnu:gcc`
- `busybox` → `busybox:busybox`
- `sqlite3-cli`, `libsqlite3-0` → `sqlite:sqlite`
- `gpsd`, `gps_daemon` → `gpsd_project:gpsd`
- `ipset`, `libipset13` → `netfilter:ipset`
- `libncurses6`, `terminfo` → `gnu:ncurses`
- `attr`, `libattr` → `attr_project:attr`

CPEs stored in CPE 2.2 URI format are auto-converted to CPE 2.3 at runtime.
