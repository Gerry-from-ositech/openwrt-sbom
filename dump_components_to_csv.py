#!/usr/bin/env python3
"""
Dump SBOM components to CSV format.

Reads sbom.json and extracts package data (name, version, licenses, cpe).
For components sharing the same CPE, only the primary component is included
in the CSV output. Duplicate CPE mappings are printed separately.

Usage:
    python3 dump_components_to_csv.py [OPTIONS]

Options:
    --input, -i FILE    Input SBOM file (default: sbom.json)
    --output, -o FILE   Output CSV file (default: components.csv)
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


def write_duplicate_cpes_csv(duplicate_cpes: dict, output_path: Path, kernel_cpe: str) -> None:
    """
    Write duplicate CPEs to a CSV file.

    Args:
        duplicate_cpes: dict mapping CPE -> list of package names
        output_path: path to write CSV file
        kernel_cpe: kernel CPE to exclude from output
    """
    with open(output_path, 'w') as f:
        f.write("cpe_id,pkglist\n")
        for cpe in sorted(duplicate_cpes.keys()):
            # Skip the Linux kernel CPE
            if cpe == kernel_cpe:
                continue
            pkg_list = ",".join(duplicate_cpes[cpe])
            # Quote the pkglist since it contains commas
            f.write(f'{cpe},"{pkg_list}"\n')


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
    component_dict = {}  # name -> "version,license,cpe"
    duplicate_cpes = {}  # cpe -> [name1, name2, ...]

    # Process components with CPE
    for cpe, comps in cpe_groups.items():
        is_kernel = (cpe == kernel_cpe)
        if len(comps) > 1:
            # Multiple components share this CPE - track as duplicates
            duplicate_cpes[cpe] = sorted([c.get("name", "unknown") for c in comps])
            # Only include primary component in main dict
            primary = get_primary_component(comps, is_kernel_group=is_kernel)
            name = primary.get("name", "unknown")
            version = primary.get("version", "unknown")
            license_str = extract_license(primary)
            component_dict[name] = f"{version},{license_str},{cpe}"
        else:
            # Single component with this CPE
            comp = comps[0]
            name = comp.get("name", "unknown")
            version = comp.get("version", "unknown")
            license_str = extract_license(comp)
            component_dict[name] = f"{version},{license_str},{cpe}"

    # Process components without CPE
    for comp in no_cpe_components:
        name = comp.get("name", "unknown")
        version = comp.get("version", "unknown")
        license_str = extract_license(comp)
        cpe = "unknown"
        component_dict[name] = f"{version},{license_str},{cpe}"

    # Sort by name (alphabetically ascending)
    sorted_names = sorted(component_dict.keys())

    # Write CSV
    print(f"\nWriting CSV to {output_path}")
    with open(output_path, 'w') as f:
        # Header
        f.write("pkgname,version,licenses,cpe,flag,comment\n")

        # Data rows
        for name in sorted_names:
            csv_values = component_dict[name]
            version, license_str, cpe = csv_values.split(",", 2)
            f.write(f"{name},{version},{license_str},{cpe},0,\n")

    print(f"Wrote {len(sorted_names)} components to CSV")

    # Write duplicate CPEs CSV (excluding kernel CPE)
    dup_cpes_path = output_path.parent / "duplicate_cpes.csv"
    write_duplicate_cpes_csv(duplicate_cpes, dup_cpes_path, kernel_cpe)
    # Count non-kernel duplicate CPEs
    non_kernel_dups = {k: v for k, v in duplicate_cpes.items() if k != kernel_cpe}
    print(f"Wrote {len(non_kernel_dups)} duplicate CPE entries to {dup_cpes_path}")

    # Print statistics
    print(f"\nStatistics:")
    print(f"  Components with unique CPE: {len(cpe_groups) - len(duplicate_cpes)}")
    print(f"  Components with shared CPE: {sum(len(v) for v in duplicate_cpes.values())}")
    print(f"  Components without CPE: {len(no_cpe_components)}")
    print(f"  Unique CPEs with multiple components: {len(duplicate_cpes)}")

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
        help='Output CSV file (default: components.csv in script directory)'
    )
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    input_path = args.input or (script_dir / 'sbom.json')
    output_path = args.output or (script_dir / 'components.csv')

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        print("Please run generate_cyclonedx_sbom.py first to generate sbom.json")
        return 1

    return dump_components_to_csv(input_path, output_path)


if __name__ == '__main__':
    exit(main())
