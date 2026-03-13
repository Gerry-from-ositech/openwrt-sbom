#!/usr/bin/env python3
"""
Dump SBOM components to CSV format.

Reads sbom.json and extracts package data to sbom_packages.csv.
For components sharing the same CPE, only the primary component is included
in the CSV output, with related package names in the cpe_group column.

Output columns: pkgname,version,licenses,cpe,patched_cves,cpe_group

Usage:
    python3 dump_components_to_csv.py [OPTIONS]

Options:
    --input, -i FILE    Input SBOM file (default: sbom.json)
    --output, -o FILE   Output CSV file (default: sbom_packages.csv)
    
    
The extracted data in the sbom_packages.csv file can be mapped to tables in the project database

"pkgname,version,licenses,cpe"  ->  Table packages        pkgname,version,licenses,cpe,0,
"pkgname,,,,patched_cves"       ->  Table patched_cves    pkgname,patched_cves
"pkgname,,,,,,cpe_group"        ->  Table cpe_groups      pkgname,pkg_list
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path
from pprint import pprint


def extract_license(component: dict) -> str:
    """Extract license string from component."""
    licenses = component.get("licenses", [])
    if not licenses:
        return "unknown"

    # CycloneDX can have license expressions or license objects
    license_strs = []
    for lic in licenses:
        if "expression" in lic:
            license_strs.append(lic["expression"])
        elif "license" in lic:
            lic_obj = lic["license"]
            if "id" in lic_obj:
                license_strs.append(lic_obj["id"])
            elif "name" in lic_obj:
                license_strs.append(lic_obj["name"])

    if not license_strs:
        return "unknown"

    return " AND ".join(license_strs)


def extract_patched_cves(component: dict) -> str:
    """Extract patched CVEs from component properties."""
    props = component.get("properties", [])
    for prop in props:
        if prop.get("name") == "openwrt:patched_cves":
            return prop.get("value", "")
    return ""


def get_primary_component(components: list[dict], is_kernel_group: bool = False) -> dict:
    """
    Get the primary component from a list of components sharing the same CPE.

    Primary is determined by:
    1. For kernel groups: the "kernel" component (not kmod-*)
    2. Component with role=primary in properties
    3. Otherwise, first non-kmod alphabetically by name
    """
    # For kernel groups, prefer the actual kernel component
    if is_kernel_group:
        for comp in components:
            name = comp.get("name", "")
            if name == "kernel":
                return comp
        # If no "kernel" component, prefer non-kmod component
        non_kmod = [c for c in components if not c.get("name", "").startswith("kmod-")]
        if non_kmod:
            return sorted(non_kmod, key=lambda c: c.get("name", ""))[0]

    # Check for explicit primary role
    for comp in components:
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        if props.get("openwrt:role") == "primary":
            return comp

    # Fall back to first alphabetically (prefer non-kmod)
    non_kmod = [c for c in components if not c.get("name", "").startswith("kmod-")]
    if non_kmod:
        return sorted(non_kmod, key=lambda c: c.get("name", ""))[0]

    return sorted(components, key=lambda c: c.get("name", ""))[0]


def find_kernel_cpe(components: list[dict]) -> tuple[str, str | None]:
    """
    Find the Linux kernel CPE and version from components.

    Returns: (cpe, version) tuple
    """
    # Look for explicit linux_kernel CPE
    for comp in components:
        cpe = comp.get("cpe", "")
        if "linux_kernel" in cpe.lower():
            return cpe, comp.get("version")

    # Look for component named "kernel" and extract its version
    for comp in components:
        name = comp.get("name", "")
        if name == "kernel":
            version = comp.get("version", "")
            # Extract kernel version (e.g., "5.4.213-1-..." -> "5.4.213")
            if version:
                base_version = version.split("-")[0]
                cpe = f"cpe:2.3:o:linux:linux_kernel:{base_version}:*:*:*:*:*:*:*"
                return cpe, version

    return None, None


def dump_components_to_csv(input_path: Path, output_path: Path) -> int:
    """
    Dump SBOM components to CSV.

    Returns: 0 on success, non-zero on error
    """
    # Load SBOM
    print(f"Loading SBOM from {input_path}")
    with open(input_path, 'r') as f:
        sbom = json.load(f)

    components = sbom.get("components", [])
    print(f"Total components: {len(components)}")

    # Find Linux kernel CPE for kmod-* components
    kernel_cpe, kernel_version = find_kernel_cpe(components)
    if kernel_cpe:
        print(f"Kernel CPE: {kernel_cpe}")
        if kernel_version:
            print(f"Kernel version: {kernel_version}")
    else:
        # Use a default kernel CPE pattern if not found
        kernel_cpe = "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
        print(f"Kernel CPE not found, using default: {kernel_cpe}")

    # Group components by CPE (kmod-* components use kernel CPE)
    cpe_groups = defaultdict(list)
    no_cpe_components = []

    for comp in components:
        name = comp.get("name", "")
        cpe = comp.get("cpe")

        # kmod-* components and "kernel" share the kernel CPE
        if name.startswith("kmod-") or name == "kernel":
            cpe_groups[kernel_cpe].append(comp)
        elif cpe:
            cpe_groups[cpe].append(comp)
        else:
            no_cpe_components.append(comp)

    # Build main component dict and duplicate CPE dict
    component_dict = {}  # name -> (version, license, cpe, patched_cves, cpe_group)
    duplicate_cpes = {}  # cpe -> [name1, name2, ...]

    # Process components with CPE
    for cpe, comps in cpe_groups.items():
        is_kernel = (cpe == kernel_cpe)
        if len(comps) > 1:
            # Multiple components share this CPE - track as duplicates
            group_names = sorted([c.get("name", "unknown") for c in comps])
            duplicate_cpes[cpe] = group_names
            # Only include primary component in main dict
            primary = get_primary_component(comps, is_kernel_group=is_kernel)
            name = primary.get("name", "unknown")
            version = primary.get("version", "unknown")
            license_str = extract_license(primary)
            patched_cves = extract_patched_cves(primary)
            # cpe_group contains all related package names (including primary)
            cpe_group = ",".join(group_names)
            component_dict[name] = (version, license_str, cpe, patched_cves, cpe_group)
        else:
            # Single component with this CPE - no cpe_group
            comp = comps[0]
            name = comp.get("name", "unknown")
            version = comp.get("version", "unknown")
            license_str = extract_license(comp)
            patched_cves = extract_patched_cves(comp)
            component_dict[name] = (version, license_str, cpe, patched_cves, "")

    # Process components without CPE
    for comp in no_cpe_components:
        name = comp.get("name", "unknown")
        version = comp.get("version", "unknown")
        license_str = extract_license(comp)
        patched_cves = extract_patched_cves(comp)
        cpe = "unknown"
        component_dict[name] = (version, license_str, cpe, patched_cves, "")

    # Sort by name (alphabetically ascending)
    sorted_names = sorted(component_dict.keys())

    # Write CSV
    print(f"\nWriting CSV to {output_path}")
    with open(output_path, 'w') as f:
        # Header
        f.write("pkgname,version,licenses,cpe,patched_cves,cpe_group\n")

        # Data rows
        for name in sorted_names:
            version, license_str, cpe, patched_cves, cpe_group = component_dict[name]
            # Quote patched_cves if it contains commas
            if patched_cves and ',' in patched_cves:
                patched_cves = f'"{patched_cves}"'
            # Quote cpe_group if it contains commas
            if cpe_group and ',' in cpe_group:
                cpe_group = f'"{cpe_group}"'
            f.write(f"{name},{version},{license_str},{cpe},{patched_cves},{cpe_group}\n")

    print(f"Wrote {len(sorted_names)} components to CSV")

    # Print statistics
    print(f"\nStatistics:")
    print(f"  Total unique CPEs: {len(cpe_groups)}")
    print(f"  CPEs with single component: {len(cpe_groups) - len(duplicate_cpes)}")
    print(f"  CPEs with multiple components: {len(duplicate_cpes)}")
    print(f"  Components in shared CPE groups: {sum(len(v) for v in duplicate_cpes.values())}")
    print(f"  Components without CPE: {len(no_cpe_components)}")

    # Print duplicate CPEs dict
    print(f"\nDuplicate CPEs (components sharing same CPE):")
    pprint(duplicate_cpes)

    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Dump SBOM components to CSV format.'
    )
    parser.add_argument(
        '--input', '-i',
        type=Path,
        default=None,
        help='Input SBOM file (default: sbom.json in script directory)'
    )
    parser.add_argument(
        '--output', '-o',
        type=Path,
        default=None,
        help='Output CSV file (default: sbom_packages.csv in script directory)'
    )
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    input_path = args.input or (script_dir / 'sbom.json')
    output_path = args.output or (script_dir / 'sbom_packages.csv')

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        print("Please run generate_cyclonedx_sbom.py first to generate sbom.json")
        return 1

    return dump_components_to_csv(input_path, output_path)


if __name__ == '__main__':
    exit(main())
