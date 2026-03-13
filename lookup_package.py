#!/usr/bin/env python3
"""
lookup_package.py — OpenWrt package lookup utility.

Determines if a package with the specified name is built and included
in the final binary firmware. Shows version and CPE information if found.

Usage:
    python3 lookup_package.py                  # Interactive mode
    python3 lookup_package.py <package_name>   # Direct lookup
    python3 lookup_package.py --trace <name>   # Show search logic details

Interactive commands:
    <package_name>  - Look up a package
    list            - List all installed packages
    list cpe        - List unique CPEs from SBOM
    step / s        - Step through SBOM packages for verification
    step * / s *    - Auto-step through all packages until failure
    quit / q        - Exit the utility
"""

import argparse
import json
import sys
from pathlib import Path

# Import functions from metadata_extractor
from metadata_extractor import (
    CONFIG_FILE,
    load_config,
    build_paths,
    find_image_manifest,
    parse_image_manifest,
    find_ipk_files,
    extract_ipk_metadata,
)

# Default SBOM file
DEFAULT_SBOM_FILE = "ExplorerII-OpenWRT21.02-Z8106_SBOM.json"


def load_sbom_packages(sbom_path: Path) -> list[dict]:
    """
    Load packages from CycloneDX SBOM file.

    Filters to include only packages with valid CPEs.
    Excludes 'linux' and packages starting with 'kmod-'.

    Returns list of dicts with: name, version, cpe, source_component
    """
    if not sbom_path.exists():
        print(f"Warning: SBOM file not found: {sbom_path}")
        return []

    with open(sbom_path, 'r') as f:
        data = json.load(f)

    packages = []
    for comp in data.get('components', []):
        name = comp.get('name', '')
        version = comp.get('version', '')
        cpe = comp.get('cpe')

        # Skip if no CPE
        if not cpe:
            continue

        # Skip linux and kmod-* packages
        if name == 'linux' or name.startswith('kmod-'):
            continue

        # Extract source_component from properties
        source_component = None
        for prop in comp.get('properties', []):
            if prop.get('name') == 'openwrt:source_component':
                source_component = prop.get('value')
                break

        packages.append({
            'name': name,
            'version': version,
            'cpe': cpe,
            'source_component': source_component,
        })

    # Sort by name for consistent ordering
    packages.sort(key=lambda x: x['name'])
    return packages


def load_sbom_by_name(sbom_path: Path) -> dict[str, dict]:
    """
    Load SBOM packages indexed by name for quick lookup.

    Returns dict mapping package name to {version, cpe, source_component}.
    """
    if not sbom_path.exists():
        return {}

    with open(sbom_path, 'r') as f:
        data = json.load(f)

    packages = {}
    for comp in data.get('components', []):
        name = comp.get('name', '')
        if not name:
            continue

        # Extract source_component from properties
        source_component = None
        for prop in comp.get('properties', []):
            if prop.get('name') == 'openwrt:source_component':
                source_component = prop.get('value')
                break

        packages[name] = {
            'version': comp.get('version', ''),
            'cpe': comp.get('cpe'),
            'source_component': source_component,
        }

    return packages


class PackageLookup:
    """Package lookup engine for OpenWrt builds."""

    def __init__(self, trace: bool = False, sbom_file: str = None):
        self.trace = trace
        self.config = None
        self.paths = None
        self.installed_packages = set()
        self.manifest_path = None
        self.ipk_files = []
        self.ipk_by_name = {}
        self.sbom_packages = []  # Packages loaded from SBOM (for step verification)
        self.sbom_by_name = {}   # SBOM packages indexed by name (for quick lookup)
        self.step_index = -1  # Current index for step command (-1 = not started)
        self.sbom_file = sbom_file
        self._initialize()

    def _log(self, msg: str, indent: int = 0) -> None:
        """Print trace message if tracing is enabled."""
        if self.trace:
            prefix = "  " * indent
            print(f"[TRACE] {prefix}{msg}")

    def _initialize(self) -> None:
        """Initialize paths and load manifest data."""
        self._log("Loading configuration from config.json")
        self.config = load_config(CONFIG_FILE)
        self._log(f"Project: {self.config['project_name']}")
        self._log(f"Build root: {self.config['openwrt_build_root']}")

        self._log("Building OpenWrt paths")
        self.paths = build_paths(self.config)

        # Verify build root exists
        if not self.paths["build_root"].exists():
            print(f"ERROR: OpenWrt build root not found: {self.paths['build_root']}")
            sys.exit(1)
        self._log(f"Build root verified: {self.paths['build_root']}")

        # Find and parse image manifest
        self._log("Searching for firmware image manifest")
        self.manifest_path = find_image_manifest(self.paths)
        if self.manifest_path:
            self._log(f"Found manifest: {self.manifest_path.name}")
            self.installed_packages = parse_image_manifest(self.manifest_path)
            self._log(f"Loaded {len(self.installed_packages)} installed packages from manifest")
        else:
            self._log("WARNING: No firmware image manifest found")
            print("Warning: No firmware image manifest found - cannot determine installed packages")

        # Find all IPK files
        self._log("Scanning for IPK files")
        self.ipk_files = find_ipk_files(self.paths)
        self._log(f"Found {len(self.ipk_files)} IPK files")

        # Build name -> IPK metadata mapping by extracting from each IPK
        # This uses the same approach as extract_all_ipk_metadata() in metadata_extractor.py
        self._log("Extracting metadata from IPK files to build package index...")
        for ipk_path in self.ipk_files:
            metadata = extract_ipk_metadata(ipk_path, self.paths["build_root"])
            if metadata and "package" in metadata:
                pkg_name = metadata["package"]
                self.ipk_by_name[pkg_name] = {
                    "path": ipk_path,
                    "metadata": metadata,
                }
                self._log(f"Indexed: {pkg_name}", indent=1)

        self._log(f"Indexed {len(self.ipk_by_name)} packages")

        # Load SBOM packages for step verification and lookup
        sbom_path = self.paths["project_dir"] / (self.sbom_file or DEFAULT_SBOM_FILE)
        self._log(f"Loading SBOM from {sbom_path}")
        self.sbom_packages = load_sbom_packages(sbom_path)
        self.sbom_by_name = load_sbom_by_name(sbom_path)
        self._log(f"Loaded {len(self.sbom_packages)} packages with CPEs from SBOM")
        self._log(f"Indexed {len(self.sbom_by_name)} total SBOM packages by name")

    def print_summary(self) -> None:
        """Print environment summary."""
        print("=" * 70)
        print(f"Project: {self.config['project_name']}")
        print(f"Release: {self.config.get('project_release', 'N/A')}")
        print("=" * 70)
        print(f"Build root:        {self.paths['build_root']}")
        print(f"Image manifest:    {self.manifest_path.name if self.manifest_path else 'NOT FOUND'}")
        print(f"Packages in image: {len(self.installed_packages)}")
        print(f"IPK files built:   {len(self.ipk_files)}")
        print(f"SBOM packages:     {len(self.sbom_packages)} (with CPEs, excl. linux/kmod-*)")
        print("=" * 70)

    def _compare_cpes(self, ipk_cpe: str, sbom_cpe: str) -> tuple[bool, str]:
        """
        Compare IPK CPE with SBOM CPE, allowing valid Phase 3 normalizations.

        Phase 3 may enhance a CPE by:
        - Adding a specific version where IPK has wildcard (*)

        Returns:
            (match: bool, reason: str) - reason explains mismatch if any
        """
        if ipk_cpe == sbom_cpe:
            return True, "exact match"

        if not ipk_cpe or not sbom_cpe:
            return False, "one CPE is missing"

        # Parse CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_ed:tgt_sw:tgt_hw:other
        ipk_parts = ipk_cpe.split(':')
        sbom_parts = sbom_cpe.split(':')

        # Both should have same structure
        if len(ipk_parts) != len(sbom_parts):
            return False, f"different CPE structure: IPK has {len(ipk_parts)} parts, SBOM has {len(sbom_parts)}"

        # Compare each component
        mismatches = []
        for i, (ipk_val, sbom_val) in enumerate(zip(ipk_parts, sbom_parts)):
            if ipk_val == sbom_val:
                continue
            # Allow SBOM to be more specific where IPK has wildcard
            if ipk_val == '*' and sbom_val != '*':
                # This is valid Phase 3 normalization (e.g., adding version)
                continue
            # Any other difference is a real mismatch
            field_names = ['cpe', 'version', 'part', 'vendor', 'product', 'version',
                           'update', 'edition', 'language', 'sw_edition', 'target_sw', 'target_hw', 'other']
            field_name = field_names[i] if i < len(field_names) else f"field_{i}"
            mismatches.append(f"{field_name}: IPK='{ipk_val}' vs SBOM='{sbom_val}'")

        if mismatches:
            return False, "; ".join(mismatches)

        return True, "match (SBOM has normalized version)"

    def verify_sbom_package(self, sbom_pkg: dict) -> dict:
        """
        Verify a package from SBOM against the actual build.

        Returns dict with verification results:
            - name, version, cpe: from SBOM
            - found: package exists in build
            - installed: package is in firmware image
            - version_match: SBOM version matches IPK version
            - cpe_match: SBOM CPE matches IPK CPE
            - cpe_annotation: explanation if CPE was added/inherited in pipeline
            - errors: list of verification errors
        """
        name = sbom_pkg['name']
        sbom_version = sbom_pkg['version']
        sbom_cpe = sbom_pkg['cpe']
        source_component = sbom_pkg.get('source_component')

        result = {
            'name': name,
            'sbom_version': sbom_version,
            'sbom_cpe': sbom_cpe,
            'found': False,
            'installed': False,
            'version_match': False,
            'cpe_match': False,
            'cpe_annotation': None,
            'ipk_version': None,
            'ipk_cpe': None,
            'errors': [],
        }

        # Check if package is in firmware manifest
        result['installed'] = name in self.installed_packages

        # Look up package in IPK index
        pkg_entry = self.ipk_by_name.get(name)

        if not pkg_entry:
            result['errors'].append(f"Package '{name}' not found in IPK index")
            return result

        result['found'] = True
        metadata = pkg_entry['metadata']
        result['ipk_version'] = metadata.get('version')
        result['ipk_cpe'] = metadata.get('cpe_id')

        # Verify package is installed
        if not result['installed']:
            result['errors'].append(f"Package '{name}' is NOT in firmware image")

        # Verify version matches
        if result['ipk_version'] == sbom_version:
            result['version_match'] = True
        else:
            result['errors'].append(
                f"Version mismatch: SBOM='{sbom_version}' vs IPK='{result['ipk_version']}'"
            )

        # Verify CPE matches (allowing pipeline normalization and inheritance)
        cpe_match, cpe_reason = self._compare_cpes(result['ipk_cpe'], sbom_cpe)
        if cpe_match:
            result['cpe_match'] = True
        elif result['ipk_cpe'] is None and sbom_cpe:
            # IPK has no CPE but SBOM does - check if it's legitimate inheritance
            # Check if the CPE is a Linux kernel CPE
            is_kernel_cpe = sbom_cpe and 'linux:linux_kernel' in sbom_cpe

            if name.startswith('kmod-') or is_kernel_cpe:
                # Kernel module or kernel CPE - inherited from Linux kernel in Phase 2
                result['cpe_match'] = True
                result['cpe_annotation'] = "CPE inherited from Linux kernel in Phase 2"
            elif source_component and source_component != name:
                # CPE inherited from source component in Phase 2/3
                result['cpe_match'] = True
                result['cpe_annotation'] = f"CPE inherited from source component '{source_component}'"
            else:
                # Unknown source - flag as error
                result['errors'].append(
                    f"CPE mismatch: SBOM has CPE but IPK has none (source_component={source_component})"
                )
        else:
            result['errors'].append(
                f"CPE mismatch: {cpe_reason}"
            )

        return result

    def step_verify(self) -> bool:
        """
        Perform step verification on the next SBOM package.

        Returns True to continue stepping, False to stop.
        """
        if not self.sbom_packages:
            print("No SBOM packages loaded for verification.")
            return False

        # First time: start at index 0
        if self.step_index < 0:
            self.step_index = 0

        if self.step_index >= len(self.sbom_packages):
            print(f"\nAll {len(self.sbom_packages)} packages verified.")
            self.step_index = -1
            return False

        sbom_pkg = self.sbom_packages[self.step_index]
        print(f"\n[{self.step_index + 1}/{len(self.sbom_packages)}] Verifying: {sbom_pkg['name']}")
        print("-" * 60)
        print(f"SBOM Version: {sbom_pkg['version']}")
        print(f"SBOM CPE:     {sbom_pkg['cpe']}")
        print("-" * 60)

        result = self.verify_sbom_package(sbom_pkg)

        # Display verification results
        status_found = "PASS" if result['found'] else "FAIL"
        status_installed = "PASS" if result['installed'] else "FAIL"
        status_version = "PASS" if result['version_match'] else "FAIL"
        status_cpe = "PASS" if result['cpe_match'] else "FAIL"

        print(f"Package found:    [{status_found}]")
        print(f"In firmware:      [{status_installed}]")
        print(f"Version match:    [{status_version}]", end="")
        if result['ipk_version'] and not result['version_match']:
            print(f"  (IPK: {result['ipk_version']})")
        else:
            print()
        print(f"CPE match:        [{status_cpe}]", end="")
        if result.get('cpe_annotation'):
            # CPE was inherited/added in pipeline - show annotation
            print(f"  {result['cpe_annotation']}")
        elif result['ipk_cpe'] and not result['cpe_match']:
            print(f"  (IPK: {result['ipk_cpe']})")
        else:
            print()

        # If any errors, stop
        if result['errors']:
            print()
            print("VERIFICATION FAILED:")
            for err in result['errors']:
                print(f"  - {err}")
            print()
            print(f"Stopped at package {self.step_index + 1} of {len(self.sbom_packages)}")
            return False

        print()
        print("All checks PASSED")

        # Prompt for next
        self.step_index += 1
        if self.step_index >= len(self.sbom_packages):
            print(f"\nAll {len(self.sbom_packages)} packages verified successfully!")
            self.step_index = -1
            return False

        return True

    def lookup(self, package_name: str) -> dict:
        """
        Look up a package and return detailed information.

        Returns dict with:
            - found: bool - whether package exists at all
            - installed: bool - whether package is in firmware image
            - version: str - package version (if found)
            - cpe_id: str - CPE identifier (if available)
            - source: str - source path in build tree
            - ipk_path: Path - path to IPK file
            - proof: str - explanation for status
        """
        result = {
            "package": package_name,
            "found": False,
            "installed": False,
            "version": None,
            "cpe_id": None,
            "cpe_source": None,
            "sbom_cpe": None,  # Final CPE from SBOM (with version filled in)
            "source": None,
            "ipk_path": None,
            "proof": None,
            "search_locations": [],
        }

        self._log(f"Looking up package: {package_name}")

        # Step 1: Check if package is in the firmware manifest
        self._log("Step 1: Checking firmware image manifest", indent=1)
        in_manifest = package_name in self.installed_packages

        if in_manifest:
            self._log(f"Package '{package_name}' IS in firmware manifest", indent=2)
            result["installed"] = True
        else:
            self._log(f"Package '{package_name}' is NOT in firmware manifest", indent=2)
            result["search_locations"].append(
                f"Firmware manifest ({self.manifest_path.name if self.manifest_path else 'not found'}): NOT PRESENT"
            )

        # Step 2: Look for the package in our index (extracted from IPK control files)
        self._log("Step 2: Searching package index", indent=1)

        pkg_entry = self.ipk_by_name.get(package_name)

        if pkg_entry:
            ipk_path = pkg_entry["path"]
            metadata = pkg_entry["metadata"]

            self._log(f"Found IPK: {ipk_path.name}", indent=2)
            result["found"] = True
            result["ipk_path"] = str(ipk_path)

            # Use the already-extracted metadata
            result["version"] = metadata.get("version")
            result["source"] = metadata.get("source")
            result["cpe_id"] = metadata.get("cpe_id")
            result["cpe_source"] = metadata.get("cpe_source", "ipk") if metadata.get("cpe_id") else None
            result["license"] = metadata.get("license")
            result["section"] = metadata.get("section")
            result["depends"] = metadata.get("depends", [])
            result["description"] = metadata.get("description")

            self._log(f"Version: {result['version']}", indent=3)
            self._log(f"Source: {result['source']}", indent=3)
            if result["cpe_id"]:
                self._log(f"CPE: {result['cpe_id']} (from {result['cpe_source']})", indent=3)
            else:
                self._log("CPE: Not available", indent=3)

            # Look up SBOM CPE (final CPE with version filled in)
            sbom_entry = self.sbom_by_name.get(package_name)
            if sbom_entry and sbom_entry.get('cpe'):
                result["sbom_cpe"] = sbom_entry['cpe']
                self._log(f"SBOM CPE: {result['sbom_cpe']}", indent=3)
            else:
                self._log("SBOM CPE: Not available", indent=3)
        else:
            self._log(f"No IPK file found for '{package_name}'", indent=2)

            # Check for similar package names in our index
            similar = [name for name in self.ipk_by_name.keys()
                       if package_name.lower() in name.lower()]
            if similar:
                self._log(f"Similar packages in index: {similar[:5]}", indent=2)
                result["search_locations"].append(
                    f"Similar packages found: {', '.join(sorted(similar)[:5])}"
                )

        # Step 3: Check if package source exists in feeds/packages
        self._log("Step 3: Checking package source directories", indent=1)

        source_locations = [
            self.paths["build_root"] / "package",
            self.paths["build_root"] / "feeds" / "packages",
            self.paths["build_root"] / "feeds" / "luci",
            self.paths["build_root"] / "feeds" / "mtk_openwrt_feed",
        ]

        for loc in source_locations:
            if loc.exists():
                # Look for package directory
                for pkg_dir in loc.rglob(package_name):
                    if pkg_dir.is_dir() and (pkg_dir / "Makefile").exists():
                        self._log(f"Found source at: {pkg_dir.relative_to(self.paths['build_root'])}", indent=2)
                        result["search_locations"].append(
                            f"Source found: {pkg_dir.relative_to(self.paths['build_root'])}"
                        )
                        if not result["found"]:
                            result["proof"] = f"Package source exists at {pkg_dir.relative_to(self.paths['build_root'])} but was not built (not selected in .config)"

        # Generate proof/explanation
        if result["installed"] and result["found"]:
            result["proof"] = f"Package '{package_name}' is BUILT and INSTALLED in the firmware image"
        elif result["found"] and not result["installed"]:
            result["proof"] = f"Package '{package_name}' is BUILT (IPK exists) but NOT installed in firmware image"
        elif not result["found"] and not result["proof"]:
            result["proof"] = f"Package '{package_name}' was NOT BUILT - no IPK file found"

        return result

    def display_result(self, result: dict) -> None:
        """Display lookup result in a formatted way."""
        print()
        print("-" * 70)
        print(f"Package: {result['package']}")
        print("-" * 70)

        if result["installed"]:
            print(f"Status:  INCLUDED in firmware image")
        elif result["found"]:
            print(f"Status:  BUILT but NOT included in firmware")
        else:
            print(f"Status:  NOT FOUND")

        print()

        if result["found"]:
            print(f"Version:      {result.get('version', 'N/A')}")
            print(f"License:      {result.get('license', 'N/A')}")
            print(f"Section:      {result.get('section', 'N/A')}")

            # Show both IPK CPE (Phase 1) and SBOM CPE (Final)
            ipk_cpe = result.get("cpe_id")
            sbom_cpe = result.get("sbom_cpe")

            if ipk_cpe or sbom_cpe:
                if ipk_cpe:
                    print(f"IPK CPE:      {ipk_cpe}")
                    print(f"CPE Source:   {result.get('cpe_source', 'N/A')}")
                else:
                    print(f"IPK CPE:      (none - added in pipeline)")

                if sbom_cpe:
                    print(f"SBOM CPE:     {sbom_cpe}")
                    # Highlight if version was added
                    if ipk_cpe and sbom_cpe != ipk_cpe:
                        ipk_parts = ipk_cpe.split(':')
                        sbom_parts = sbom_cpe.split(':')
                        if len(ipk_parts) > 5 and len(sbom_parts) > 5:
                            if ipk_parts[5] == '*' and sbom_parts[5] != '*':
                                print(f"              ^ version '{sbom_parts[5]}' added in Phase 3")
                else:
                    print(f"SBOM CPE:     Not in SBOM")
            else:
                print(f"CPE:          Not available")

            if result.get("source"):
                print(f"Source Path:  {result['source']}")

            if result.get("depends"):
                deps = result["depends"]
                if isinstance(deps, list) and deps:
                    print(f"Dependencies: {', '.join(deps[:5])}")
                    if len(deps) > 5:
                        print(f"              ... and {len(deps) - 5} more")

            if result.get("description"):
                desc = result["description"]
                if len(desc) > 80:
                    desc = desc[:77] + "..."
                print(f"Description:  {desc}")

            print(f"IPK File:     {result.get('ipk_path', 'N/A')}")

        print()
        print(f"Proof: {result['proof']}")

        if result.get("search_locations"):
            print()
            print("Search details:")
            for loc in result["search_locations"]:
                print(f"  - {loc}")

        print("-" * 70)


def interactive_mode(lookup: PackageLookup) -> None:
    """Run interactive package lookup loop."""
    lookup.print_summary()

    print("\nEnter package name to lookup (or 'quit' to exit):")

    stepping = False  # True when in step mode
    auto_mode = False  # True when in auto mode (step *)

    while True:
        try:
            if stepping:
                if auto_mode:
                    # Auto mode: continue without prompting
                    if lookup.step_verify():
                        continue
                    else:
                        # Verification failed or completed - stop auto mode
                        auto_mode = False
                        stepping = False
                        print("\nAuto mode stopped.")
                        continue
                else:
                    user_input = input("\n  [N]ext / [*](auto mode)/[Q]uit stepping> ").strip().lower()
                    if user_input in ('n', 'next', ''):
                        if lookup.step_verify():
                            continue
                        else:
                            stepping = False
                            continue
                    elif user_input == '*':
                        # Enable auto mode
                        auto_mode = True
                        print("Auto mode enabled - running until failure or completion...")
                        if lookup.step_verify():
                            continue
                        else:
                            # Verification failed or completed
                            auto_mode = False
                            stepping = False
                            print("\nAuto mode stopped.")
                            continue
                    elif user_input in ('q', 'quit', 'stop'):
                        print("Stopped stepping.")
                        stepping = False
                        auto_mode = False
                        lookup.step_index = -1
                        continue
                    else:
                        print("Enter 'n' for next, '*' for auto mode, or 'q' to quit stepping.")
                        continue
            else:
                package_name = input("\nPackage> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not package_name:
            continue

        if package_name.lower() in ("quit", "exit", "q"):
            print("Exiting.")
            break

        # Handle special commands
        if package_name.lower() == "list" or package_name.lower().startswith("list "):
            parts = package_name.split()
            if len(parts) == 1:
                # Just "list" - show all installed packages
                print(f"\nInstalled packages ({len(lookup.installed_packages)}):")
                for pkg in sorted(lookup.installed_packages):
                    print(f"  {pkg}")
            elif len(parts) == 2 and parts[1].lower() == "cpe":
                # "list cpe" - show unique CPEs with package names
                cpe_to_packages = {}
                for pkg_name, pkg_data in lookup.sbom_by_name.items():
                    cpe = pkg_data.get('cpe')
                    if cpe:
                        if cpe not in cpe_to_packages:
                            cpe_to_packages[cpe] = []
                        cpe_to_packages[cpe].append(pkg_name)
                print(f"\nUnique CPEs ({len(cpe_to_packages)}):")
                for cpe in sorted(cpe_to_packages.keys()):
                    packages = sorted(cpe_to_packages[cpe])
                    print(f"  {cpe}")
                    print(f"    -> {', '.join(packages)}")
            else:
                print("Usage: list [cpe]")
            continue

        if package_name.lower() == "help":
            print("\nCommands:")
            print("  <package_name>  - Look up a package")
            print("  list            - List all installed packages")
            print("  list cpe        - List unique CPEs from SBOM")
            print("  step / s [N]    - Step through SBOM packages (optionally start at Nth)")
            print("  step * / s *    - Auto-step through all packages until failure")
            print("  quit / q        - Exit the utility")
            continue

        # Handle step command (with optional starting index or auto mode)
        # Format: "step", "s", "step 30", "s 30", "step *", "s *"
        parts = package_name.split()
        if parts and parts[0].lower() in ("step", "s"):
            start_auto = False
            if len(parts) > 1:
                if parts[1] == '*':
                    # Start in auto mode
                    start_auto = True
                    lookup.step_index = -1  # Reset to start
                else:
                    try:
                        # User specifies 1-based index, convert to 0-based
                        start_index = int(parts[1]) - 1
                        if start_index < 0:
                            print(f"Index must be >= 1")
                            continue
                        if start_index >= len(lookup.sbom_packages):
                            print(f"Index {parts[1]} out of range (max: {len(lookup.sbom_packages)})")
                            continue
                        lookup.step_index = start_index
                    except ValueError:
                        print(f"Invalid index: {parts[1]}")
                        continue
            else:
                lookup.step_index = -1  # Reset to start (will become 0 in step_verify)

            if start_auto:
                print("Auto mode enabled - running until failure or completion...")
                auto_mode = True

            if lookup.step_verify():
                stepping = True
            else:
                auto_mode = False  # Reset if verification immediately failed/completed
            continue

        # Perform lookup
        result = lookup.lookup(package_name)
        lookup.display_result(result)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Look up OpenWrt packages in the build environment.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 lookup_package.py                # Interactive mode
  python3 lookup_package.py curl           # Look up 'curl' package
  python3 lookup_package.py --trace curl   # Show detailed search logic

In interactive mode:
  - Type a package name to look it up
  - Type 'list' to see all installed packages
  - Type 'list cpe' to see unique CPEs from SBOM
  - Type 'step' or 's' to verify SBOM packages against build
  - Type 'quit' to exit
"""
    )
    parser.add_argument(
        "package",
        nargs="?",
        help="Package name to look up (omit for interactive mode)"
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Show detailed search logic"
    )

    args = parser.parse_args()

    # Initialize lookup engine
    lookup = PackageLookup(trace=args.trace)

    if args.package:
        # Direct lookup mode
        lookup.print_summary()
        result = lookup.lookup(args.package)
        lookup.display_result(result)
    else:
        # Interactive mode
        interactive_mode(lookup)


if __name__ == "__main__":
    main()
