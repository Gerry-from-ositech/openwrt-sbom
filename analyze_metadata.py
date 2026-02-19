#!/usr/bin/env python3
"""
Analyze extracted OpenWRT metadata and produce CycloneDX-aligned output.

Features:
1. Source-based components (grouped by upstream source)
2. Binary artifacts listed under each source component
3. Virtual package mappings (provides relationships)
4. Normalized versions (upstream vs release designation)

Input: data.json (from metadata_extractor.py)
Output: enhanced_metadata.json (or .json.gz with --compress)

Usage:
    python3 analyze_metadata.py [--compress]
"""

import argparse
import gzip
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional


def normalize_version(version_str: str) -> tuple[str, Optional[str]]:
    """
    Extract upstream version and OpenWRT release designation.

    Returns: (upstream_version, release_designation)
    """
    if not version_str:
        return (version_str, None)

    # Git prefix: git-<version>-<hash>
    git_match = re.match(r'^git-(.+?)-([a-f0-9]+)$', version_str)
    if git_match:
        return (git_match.group(1), None)

    # Version with .git- embedded: 2.4.8.git-2020-10-03-3
    git_embedded = re.match(r'^([\d.]+)\.git-[\d-]+-(\d+)$', version_str)
    if git_embedded:
        return (git_embedded.group(1), git_embedded.group(2))

    # Date-commit format: 2021-05-16-b14c4688-2
    date_commit = re.match(r'^(\d{4}-\d{2}-\d{2})-[a-f0-9]+-(\d+)$', version_str)
    if date_commit:
        return (date_commit.group(1), date_commit.group(2))

    # Date-only with release: 2021-01-04-c53b1882-1
    date_hash_rel = re.match(r'^(\d{4}-\d{2}-\d{2})-([a-f0-9]+)-(\d+)$', version_str)
    if date_hash_rel:
        return (date_hash_rel.group(1), date_hash_rel.group(3))

    # Kernel patch version: 5.4.213+3.4.5-1
    kernel_patch = re.match(r'^([\d.]+)\+[\d.]+-(\d+)$', version_str)
    if kernel_patch:
        return (kernel_patch.group(1), kernel_patch.group(2))

    # Kernel version with hash: 5.4.213-1-3e5772a22b9e9b5c3ac231967667ef89
    kernel_hash = re.match(r'^([\d.]+)-(\d+)-[a-f0-9]{20,}$', version_str)
    if kernel_hash:
        return (kernel_hash.group(1), kernel_hash.group(2))

    # Vendor format: 1-r0-45c8168a
    vendor = re.match(r'^(\d+)-r\d+-[a-f0-9]+$', version_str)
    if vendor:
        return (vendor.group(1), None)

    # Base-files special: 151-25.1023_223752
    base_files = re.match(r'^(\d+)-[\d._]+$', version_str)
    if base_files:
        return (base_files.group(1), None)

    # Version with variant suffix: 2017.3.23-1-fuseext or 1.2.3-2-minimal
    variant = re.match(r'^(.+?)-(\d{1,3})-([a-zA-Z]\w*)$', version_str)
    if variant:
        return (variant.group(1), variant.group(2))

    # Standard semver-pkgrel: 1.8.7-1 or 0.32-33
    standard = re.match(r'^(.+)-(\d{1,3})$', version_str)
    if standard:
        upstream = standard.group(1)
        release = standard.group(2)
        if not re.match(r'^\d{4}-\d{2}$', upstream):
            return (upstream, release)

    return (version_str, None)


def update_cpe_version(cpe_id: str, version: str) -> str:
    """Update a CPE ID with the actual version instead of wildcard."""
    if not cpe_id or not version:
        return cpe_id
    parts = cpe_id.split(':')
    if len(parts) >= 6 and parts[5] == '*':
        parts[5] = version
    return ':'.join(parts)


def identify_primary_package(packages: dict, members: list[str], source_path: str) -> str:
    """
    Identify the primary/official package from a source group.
    """
    if len(members) == 1:
        return members[0]

    source_basename = Path(source_path).name if source_path else ''

    # Get non-library, non-module candidates
    candidates = [
        name for name in members
        if not name.startswith('lib') and '-mod-' not in name and not name.startswith('kmod-')
    ]

    if not candidates:
        candidates = [name for name in members if not name.startswith('kmod-')]
    if not candidates:
        candidates = members

    # Sort by length, then alphabetically
    candidates.sort(key=lambda x: (len(x), x))

    # Check if any matches source basename
    for candidate in candidates:
        if candidate == source_basename:
            return candidate

    return candidates[0]


def classify_artifact_role(pkg_name: str, primary_name: str, pkg_data: dict) -> str:
    """Classify a package's role within a source group."""
    if pkg_name == primary_name:
        return "primary"

    if pkg_name.startswith('kmod-'):
        return "kernel-module"
    if pkg_name.startswith('lib'):
        return "library"
    if '-mod-' in pkg_name:
        return "module"
    if pkg_data.get('type') == 'library':
        return "library"

    return "binary"


def get_kernel_cpe(components: list[dict]) -> str | None:
    """
    Find the kernel component and generate its CPE.

    Returns CPE string like: cpe:2.3:o:linux:linux_kernel:5.4.213:*:*:*:*:*:*:*
    """
    for comp in components:
        # Look for a component named "kernel" or with kernel in source path
        if comp.get('name') == 'kernel' or 'kernel/linux' in comp.get('source', ''):
            version = comp.get('version', '')
            if version:
                # Extract base version (e.g., "5.4.213-1-hash" -> "5.4.213")
                base_version = version.split('-')[0]
                return f"cpe:2.3:o:linux:linux_kernel:{base_version}:*:*:*:*:*:*:*"
    return None


def assign_kernel_cpe_to_kmod(components: list[dict], kernel_cpe: str) -> int:
    """
    Assign kernel CPE to all components that have kmod-* artifacts.

    Returns count of components updated.
    """
    count = 0
    for comp in components:
        # Check if this component has any kmod-* artifacts
        artifacts = comp.get('artifacts', [])
        has_kmod = any(a.get('name', '').startswith('kmod-') for a in artifacts)

        if has_kmod and not comp.get('cpe'):
            comp['cpe'] = kernel_cpe
            count += 1

    return count


def build_provides_map(packages: dict) -> dict[str, str]:
    """Map virtual names to implementing packages."""
    provides_map = {}
    for name, pkg in packages.items():
        provides = pkg.get('provides')
        if provides:
            for virtual in provides.split(','):
                virtual = virtual.strip()
                if virtual:
                    provides_map[virtual] = name
    return provides_map


def build_source_component(source_path: str, members: list[str], packages: dict,
                           libc_cpe: str | None) -> dict:
    """
    Build a source-based component from a group of binary packages.
    """
    # Identify primary package
    primary_name = identify_primary_package(packages, members, source_path)
    primary_pkg = packages.get(primary_name, {})

    # Get version info from primary
    version_full = primary_pkg.get('version', '')
    upstream_version, release = normalize_version(version_full)

    # Determine component name (use source basename or primary package name)
    source_basename = Path(source_path).name if source_path else primary_name
    component_name = source_basename if source_basename else primary_name

    # Special case for toolchain (libc = musl)
    is_libc = component_name == 'toolchain' or (primary_name == 'libc')

    # Collect CPE from members (should be same for all)
    cpe_id = None
    for member in members:
        pkg = packages.get(member, {})
        if pkg.get('cpe_id'):
            cpe_id = pkg['cpe_id']
            break

    # Special case for libc/toolchain - use musl CPE
    if is_libc and libc_cpe:
        cpe_id = libc_cpe
        component_name = 'musl'  # Use actual implementation name

    if cpe_id:
        cpe_id = update_cpe_version(cpe_id, upstream_version)

    # Collect all unique licenses
    licenses = set()
    for member in members:
        pkg = packages.get(member, {})
        lic = pkg.get('license')
        if lic:
            licenses.add(lic)

    # Collect all patches and patched CVEs
    all_patches = set()
    all_patched_cves = {}
    for member in members:
        pkg = packages.get(member, {})
        patches = pkg.get('patches', [])
        all_patches.update(patches)
        # Merge patched_cves
        patched_cves = pkg.get('patched_cves', {})
        for cve, patch_list in patched_cves.items():
            if cve not in all_patched_cves:
                all_patched_cves[cve] = []
            for patch in patch_list:
                if patch not in all_patched_cves[cve]:
                    all_patched_cves[cve].append(patch)

    # Collect all static/embedded libraries
    all_static_libs = {}
    for member in members:
        pkg = packages.get(member, {})
        static_libs = pkg.get('static_libs', [])
        for lib in static_libs:
            lib_name = lib.get('name')
            if lib_name and lib_name not in all_static_libs:
                all_static_libs[lib_name] = lib.copy()
                all_static_libs[lib_name]['used_by'] = [member]
            elif lib_name:
                # Same lib used by multiple packages in this component
                if member not in all_static_libs[lib_name].get('used_by', []):
                    all_static_libs[lib_name].setdefault('used_by', []).append(member)

    # Get download URL from primary package
    download_url = primary_pkg.get('download_url')

    # Build artifacts list
    artifacts = []
    for member in sorted(members):
        pkg = packages.get(member, {})
        role = classify_artifact_role(member, primary_name, pkg)

        artifact = {
            "name": member,
            "role": role,
            "version": pkg.get('version', ''),
        }

        if pkg.get('hashes'):
            artifact["hashes"] = pkg['hashes']

        if pkg.get('purl'):
            artifact["purl"] = pkg['purl']

        if pkg.get('provides'):
            artifact["provides"] = pkg['provides']

        if pkg.get('depends'):
            artifact["depends"] = pkg['depends']

        if pkg.get('description'):
            # Truncate long descriptions
            desc = pkg['description']
            if len(desc) > 150:
                desc = desc[:147] + "..."
            artifact["description"] = desc

        artifacts.append(artifact)

    # Sort artifacts: primary first, then by role, then by name
    role_order = {"primary": 0, "binary": 1, "library": 2, "module": 3, "kernel-module": 4}
    artifacts.sort(key=lambda x: (role_order.get(x["role"], 5), x["name"]))

    # Build properties
    properties = []
    properties.append({"name": "openwrt:version_upstream", "value": upstream_version})
    if release:
        properties.append({"name": "openwrt:release_designation", "value": release})
    properties.append({"name": "openwrt:source_path", "value": source_path})
    properties.append({"name": "openwrt:artifact_count", "value": str(len(artifacts))})
    if is_libc:
        properties.append({"name": "openwrt:implementation", "value": "musl"})

    # Build pedigree for patches and patched CVEs
    pedigree = None
    if all_patches or all_patched_cves:
        pedigree = {}
        if all_patches:
            pedigree["patches"] = [{"name": p} for p in sorted(all_patches)]
        if all_patched_cves:
            # Sort CVEs and include the patches that fix each
            pedigree["patched_cves"] = {
                cve: sorted(patches)
                for cve, patches in sorted(all_patched_cves.items())
            }

    # Determine component type
    comp_type = primary_pkg.get('type', 'library')
    if source_path and 'kernel/linux' in source_path:
        comp_type = 'operating-system'

    # Build the component
    component = {
        "name": component_name,
        "version": version_full,
        "type": comp_type,
        "source": source_path,
    }

    if cpe_id:
        component["cpe"] = cpe_id

    if licenses:
        component["licenses"] = [{"license": {"id": lic}} for lic in sorted(licenses)]

    if primary_pkg.get('description'):
        component["description"] = primary_pkg['description']

    if primary_pkg.get('maintainer'):
        component["maintainer"] = primary_pkg['maintainer']

    # Add download URL as external reference (CycloneDX compliant)
    if download_url:
        component["externalReferences"] = [
            {
                "type": "distribution",
                "url": download_url
            }
        ]

    component["artifacts"] = artifacts

    if pedigree:
        component["pedigree"] = pedigree

    # Add static/embedded libraries (important for CVE tracking)
    if all_static_libs:
        static_lib_list = []
        for lib_name, lib_info in sorted(all_static_libs.items()):
            lib_entry = {
                "name": lib_name,
                "source": lib_info.get('source', 'unknown'),
            }
            if lib_info.get('cpe_id'):
                lib_entry["cpe"] = lib_info['cpe_id']
            if lib_info.get('notes'):
                lib_entry["notes"] = lib_info['notes']
            if lib_info.get('used_by') and len(lib_info['used_by']) > 1:
                lib_entry["used_by"] = lib_info['used_by']
            static_lib_list.append(lib_entry)
        component["staticLibraries"] = static_lib_list

    component["properties"] = properties

    return component


def analyze_metadata(input_path: Path, output_path: Path, compress: bool = False):
    """Main analysis function."""

    # Load input data
    with open(input_path, 'r') as f:
        data = json.load(f)

    # Extract project metadata and components
    if "components" in data:
        project_metadata = {
            "project_name": data.get("project_name", ""),
            "project_release": data.get("project_release", ""),
            "build_system": data.get("build_system", ""),
            "extraction_date": data.get("extraction_date", ""),
            "image_manifest": data.get("image_manifest"),
            "filtered": data.get("filtered", False),
            "packages_removed": data.get("packages_removed", []),
        }
        packages = data["components"]
    else:
        project_metadata = {
            "project_name": "",
            "project_release": "",
            "build_system": "",
            "extraction_date": "",
            "image_manifest": None,
            "filtered": False,
            "packages_removed": [],
        }
        packages = data

    print(f"Loaded {len(packages)} binary packages from {input_path}")
    if project_metadata["project_name"]:
        print(f"Project: {project_metadata['project_name']}")
    if project_metadata["filtered"]:
        print(f"Filtered to firmware image: {project_metadata['image_manifest']}")
        if project_metadata["packages_removed"]:
            print(f"Packages excluded (not in image): {len(project_metadata['packages_removed'])}")

    # Group packages by source path
    source_groups = defaultdict(list)
    for name, pkg in packages.items():
        source = pkg.get('source', '')
        if source:
            source_groups[source].append(name)
        else:
            # Packages without source get their own group
            source_groups[f'_standalone_{name}'].append(name)

    print(f"Identified {len(source_groups)} source components")

    # Build provides map
    provides_map = build_provides_map(packages)

    # Generate libc CPE (musl)
    libc_cpe = None
    libc_pkg = packages.get('libc')
    if libc_pkg:
        version = libc_pkg.get('version', '')
        upstream, _ = normalize_version(version)
        libc_cpe = f"cpe:2.3:a:musl-libc:musl:{upstream}:*:*:*:*:*:*:*"

    # Build source-based components
    components = []
    for source_path, members in source_groups.items():
        component = build_source_component(source_path, members, packages, libc_cpe)
        components.append(component)

    # Assign kernel CPE to kmod-* components
    kernel_cpe = get_kernel_cpe(components)
    if kernel_cpe:
        kmod_count = assign_kernel_cpe_to_kmod(components, kernel_cpe)
        print(f"Assigned kernel CPE to {kmod_count} kmod-* components: {kernel_cpe}")

    # Sort alphabetically by component name
    components.sort(key=lambda x: x['name'].lower())

    # Build virtual packages map
    virtual_packages = {}
    for virtual_name, implementing_pkg in provides_map.items():
        if virtual_name not in packages:
            virtual_packages[virtual_name] = implementing_pkg

    # Statistics
    total_artifacts = sum(len(c.get('artifacts', [])) for c in components)
    components_with_cpe = sum(1 for c in components if c.get('cpe'))
    unique_cpes = set(c.get('cpe') for c in components if c.get('cpe'))
    multi_artifact = sum(1 for c in components if len(c.get('artifacts', [])) > 1)
    components_with_download = sum(1 for c in components if c.get('externalReferences'))

    # Count patched CVEs
    components_with_patched_cves = 0
    total_patched_cves = set()
    for c in components:
        pedigree = c.get('pedigree', {})
        patched_cves = pedigree.get('patched_cves', {})
        if patched_cves:
            components_with_patched_cves += 1
            total_patched_cves.update(patched_cves.keys())

    # Count static/embedded libraries
    components_with_static_libs = 0
    total_static_libs = set()
    static_libs_with_cpe = set()
    for c in components:
        static_libs = c.get('staticLibraries', [])
        if static_libs:
            components_with_static_libs += 1
            for lib in static_libs:
                total_static_libs.add(lib['name'])
                if lib.get('cpe'):
                    static_libs_with_cpe.add(lib['name'])

    # Build summary
    summary = {
        "total_source_components": len(components),
        "total_binary_artifacts": total_artifacts,
        "multi_artifact_components": multi_artifact,
        "single_artifact_components": len(components) - multi_artifact,
        "components_with_cpe": components_with_cpe,
        "unique_cpe_ids": len(unique_cpes),
        "components_with_download_url": components_with_download,
        "components_with_patched_cves": components_with_patched_cves,
        "total_unique_patched_cves": len(total_patched_cves),
        "components_with_static_libs": components_with_static_libs,
        "total_unique_static_libs": len(total_static_libs),
        "static_libs_with_cpe": len(static_libs_with_cpe),
        "virtual_packages": len(virtual_packages),
    }

    # Build output
    output = {
        "project_name": project_metadata["project_name"],
        "project_release": project_metadata["project_release"],
        "build_system": project_metadata["build_system"],
        "extraction_date": project_metadata["extraction_date"],
        "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "image_manifest": project_metadata["image_manifest"],
        "filtered_to_image": project_metadata["filtered"],
        "summary": summary,
        "components": components,
        "virtual_packages": virtual_packages,
    }

    # Include removed packages list if filtering was applied
    if project_metadata["packages_removed"]:
        output["packages_not_in_image"] = project_metadata["packages_removed"]

    # Write output
    if compress:
        output_path = output_path.with_suffix('.json.gz')
        json_bytes = json.dumps(output, separators=(',', ':')).encode('utf-8')
        with gzip.open(output_path, 'wb') as f:
            f.write(json_bytes)
        uncompressed_size = len(json_bytes)
        compressed_size = output_path.stat().st_size
        ratio = (1 - compressed_size / uncompressed_size) * 100
        print(f"\nWrote compressed metadata to {output_path}")
        print(f"  Uncompressed: {uncompressed_size:,} bytes")
        print(f"  Compressed:   {compressed_size:,} bytes ({ratio:.1f}% reduction)")
    else:
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\nWrote enhanced metadata to {output_path}")

    print(f"\nSummary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")

    # Print multi-artifact components
    print(f"\nMulti-artifact components (top 10):")
    multi_comps = [(c['name'], len(c['artifacts'])) for c in components if len(c['artifacts']) > 1]
    multi_comps.sort(key=lambda x: -x[1])
    for name, count in multi_comps[:10]:
        comp = next(c for c in components if c['name'] == name)
        cpe = comp.get('cpe', 'no CPE')
        if cpe != 'no CPE':
            cpe = cpe.split(':')[4] if len(cpe.split(':')) > 4 else cpe
        print(f"  {name}: {count} artifacts - {cpe}")

    # Print virtual package samples
    print(f"\nVirtual Packages (sample of {min(10, len(virtual_packages))}):")
    for vname, impl in list(sorted(virtual_packages.items()))[:10]:
        print(f"  {vname} -> {impl}")

    # Print patched CVEs
    if total_patched_cves:
        print(f"\nPatched CVEs ({len(total_patched_cves)} unique):")
        for c in components:
            pedigree = c.get('pedigree', {})
            patched_cves = pedigree.get('patched_cves', {})
            if patched_cves:
                cves_str = ', '.join(sorted(patched_cves.keys()))
                print(f"  {c['name']}: {cves_str}")

    # Print static/embedded libraries
    if total_static_libs:
        print(f"\nStatic/Embedded Libraries ({len(total_static_libs)} unique):")
        for c in components:
            static_libs = c.get('staticLibraries', [])
            if static_libs:
                lib_names = []
                for lib in static_libs:
                    name = lib['name']
                    if lib.get('cpe'):
                        # Extract vendor:product from CPE
                        cpe_parts = lib['cpe'].split(':')
                        if len(cpe_parts) >= 5:
                            name += f" ({cpe_parts[3]}:{cpe_parts[4]})"
                    lib_names.append(name)
                print(f"  {c['name']}: {', '.join(lib_names)}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze OpenWRT metadata and produce CycloneDX-aligned output.'
    )
    parser.add_argument(
        '--compress', '-c',
        action='store_true',
        help='Output gzip-compressed minified JSON (.json.gz)'
    )
    parser.add_argument(
        '--input', '-i',
        type=Path,
        default=None,
        help='Input JSON file (default: data.json in script directory)'
    )
    parser.add_argument(
        '--output', '-o',
        type=Path,
        default=None,
        help='Output file (default: enhanced_metadata.json[.gz] in script directory)'
    )
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    input_path = args.input or (script_dir / 'data.json')
    output_path = args.output or (script_dir / 'enhanced_metadata.json')

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        print("Please run metadata_extractor.py first to generate data.json")
        return 1

    analyze_metadata(input_path, output_path, compress=args.compress)
    return 0


if __name__ == '__main__':
    exit(main())
