# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenWrt Metadata Extractor - A 3-phase pipeline that extracts package metadata from OpenWrt firmware builds and generates CycloneDX v1.6 SBOMs for vulnerability management.

## Pipeline Architecture

```
Phase 1: metadata_extractor.py → data.json (raw metadata from IPK files)
Phase 2: analyze_metadata.py   → enhanced_metadata.json (normalized, grouped)
Phase 3: generate_cyclonedx_sbom.py → sbom.json (CycloneDX v1.6)
Export:  dump_components_to_csv.py  → components.csv (database-ready)
```

**Key Principle:** Each phase is standalone - consumes only the previous phase's output. Outputs are immutable.

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
```

## Configuration

`config.json` defines the OpenWrt build location:
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
- CPEs extracted from IPK control files or package Makefiles (`PKG_CPE_ID`)
- Fallback to `KNOWN_METADATA` dict in metadata_extractor.py for common packages
- All CPEs normalized to CPE 2.3 format
- `kmod-*` packages automatically inherit Linux kernel CPE

### Version Normalization (analyze_metadata.py)
- Separates upstream version from OpenWrt release designation
- Handles variants: `2017.3.23-1-fuseext` → upstream `2017.3.23`
- CPE version uses normalized upstream version only

### Component Grouping
- Binary packages grouped by source path into source components
- Multiple artifacts (e.g., `libncurses6`, `terminfo`) share parent CPE
- `openwrt:source_component` property links binaries to source

### OpenWrt-Specific SBOM Properties
- `openwrt:depends` - Runtime dependencies
- `openwrt:patched_cves` - CVEs fixed by patches (for triage filtering)
- `openwrt:patches` - Applied patch filenames
- `openwrt:static_libs` - Statically linked libraries
- `openwrt:source_component` - Parent source package name

## Dependencies

```
cyclonedx-python-lib
packageurl-python
```

## Output Files

| File | Description |
|------|-------------|
| `data.json` | Raw extracted metadata (~400 packages) |
| `enhanced_metadata.json` | Normalized with source grouping (~190 components) |
| `sbom.json` | CycloneDX v1.6 SBOM (~380 binary components) |
| `components.csv` | Deduplicated list for database import (~210 entries) |
