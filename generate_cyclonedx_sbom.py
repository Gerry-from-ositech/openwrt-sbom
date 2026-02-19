#!/usr/bin/env python3
"""
Generate CycloneDX v1.6 SBOM from enhanced metadata.

Phase 3: Transforms enhanced_metadata.json into a valid CycloneDX v1.6 SBOM.

Input: enhanced_metadata.json (from Phase 2)
Output: <ProjectName>_SBOM.json (CycloneDX v1.6 compliant)

Usage:
    python3 generate_cyclonedx_sbom.py [OPTIONS]

Options:
    --input, -i FILE    Input file (default: enhanced_metadata.json)
    --output, -o FILE   Output file (default: derived from project name,
                        e.g., "ExplorerII-OpenWRT21.02-Z8106_SBOM.json")
    --pretty            Pretty-print JSON output
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model import ExternalReference, ExternalReferenceType, HashType, HashAlgorithm, Property
from cyclonedx.model.license import LicenseExpression
from cyclonedx.output.json import JsonV1Dot6
from packageurl import PackageURL


# Map enhanced_metadata type strings to CycloneDX ComponentType
TYPE_MAP = {
    "application": ComponentType.APPLICATION,
    "library": ComponentType.LIBRARY,
    "operating-system": ComponentType.OPERATING_SYSTEM,
    "firmware": ComponentType.FIRMWARE,
    "framework": ComponentType.FRAMEWORK,
    "file": ComponentType.FILE,
    "device": ComponentType.DEVICE,
    "container": ComponentType.CONTAINER,
}

# Map hash algorithm strings to CycloneDX HashAlgorithm
HASH_ALG_MAP = {
    "SHA-256": HashAlgorithm.SHA_256,
    "SHA-384": HashAlgorithm.SHA_384,
    "SHA-512": HashAlgorithm.SHA_512,
    "SHA-1": HashAlgorithm.SHA_1,
    "MD5": HashAlgorithm.MD5,
}


def create_bom_ref(purl: str | None, name: str, version: str) -> str:
    """Create a unique bom-ref from purl or name+version."""
    if purl:
        return purl
    return f"pkg:opkg/{name}@{version}"


def parse_purl(purl_str: str) -> PackageURL | None:
    """Parse a PURL string safely."""
    try:
        return PackageURL.from_string(purl_str)
    except Exception:
        return None


def create_hash_types(hashes: list[dict]) -> set[HashType]:
    """Convert hash dictionaries to CycloneDX HashType set."""
    result = set()
    for h in hashes:
        alg = HASH_ALG_MAP.get(h.get("alg"))
        content = h.get("content")
        if alg and content:
            result.add(HashType(alg=alg, content=content))
    return result


def create_properties(artifact: dict, source_component_name: str) -> set[Property]:
    """Create CycloneDX properties from artifact data."""
    props = set()

    # Add source component reference
    props.add(Property(name="openwrt:source_component", value=source_component_name))

    # Add dependencies as property
    depends = artifact.get("depends", [])
    if depends:
        props.add(Property(name="openwrt:depends", value=",".join(depends)))

    # Add role
    role = artifact.get("role")
    if role:
        props.add(Property(name="openwrt:role", value=role))

    # Add provides (virtual packages)
    provides = artifact.get("provides")
    if provides:
        props.add(Property(name="openwrt:provides", value=provides))

    return props


def create_component_properties(component: dict) -> set[Property]:
    """Create properties from source component metadata."""
    props = set()

    # Add all existing properties from enhanced_metadata
    for prop in component.get("properties", []):
        name = prop.get("name")
        value = prop.get("value")
        if name and value:
            props.add(Property(name=name, value=value))

    # Add patches as property if present
    pedigree = component.get("pedigree", {})
    patches = pedigree.get("patches", [])
    if patches:
        patch_names = [p.get("name", "") for p in patches if p.get("name")]
        if patch_names:
            props.add(Property(name="openwrt:patches", value=",".join(patch_names)))

    # Add patched CVEs as property
    patched_cves = pedigree.get("patched_cves", {})
    if patched_cves:
        cve_list = sorted(patched_cves.keys())
        props.add(Property(name="openwrt:patched_cves", value=",".join(cve_list)))

    # Add static libraries as property
    static_libs = component.get("staticLibraries", [])
    if static_libs:
        lib_names = [lib.get("name", "") for lib in static_libs if lib.get("name")]
        if lib_names:
            props.add(Property(name="openwrt:static_libs", value=",".join(lib_names)))

    return props


def create_external_references(ext_refs: list[dict]) -> set[ExternalReference]:
    """Convert external references to CycloneDX format."""
    result = set()
    type_map = {
        "distribution": ExternalReferenceType.DISTRIBUTION,
        "website": ExternalReferenceType.WEBSITE,
        "vcs": ExternalReferenceType.VCS,
        "documentation": ExternalReferenceType.DOCUMENTATION,
        "issue-tracker": ExternalReferenceType.ISSUE_TRACKER,
        "license": ExternalReferenceType.LICENSE,
        "support": ExternalReferenceType.SUPPORT,
    }

    for ref in ext_refs:
        ref_type = type_map.get(ref.get("type"), ExternalReferenceType.OTHER)
        url = ref.get("url")
        if url:
            result.add(ExternalReference(type=ref_type, url=url))

    return result


def create_license_expression(licenses: list[dict]) -> LicenseExpression | None:
    """Create a license expression from license list."""
    if not licenses:
        return None

    # Extract license IDs
    license_ids = []
    for lic in licenses:
        lic_obj = lic.get("license", {})
        lic_id = lic_obj.get("id")
        if lic_id:
            license_ids.append(lic_id)

    if not license_ids:
        return None

    # Join multiple licenses with AND (conservative assumption)
    expression = " AND ".join(license_ids)

    try:
        return LicenseExpression(value=expression)
    except Exception:
        # If expression parsing fails, try just the first license
        try:
            return LicenseExpression(value=license_ids[0])
        except Exception:
            return None


def create_binary_component(artifact: dict, source_component: dict) -> Component:
    """
    Create a CycloneDX component from a binary artifact.

    Each binary artifact becomes its own component in the SBOM with full metadata.
    """
    name = artifact.get("name", "")
    version = artifact.get("version", "")
    purl_str = artifact.get("purl")

    # Get component type - binary artifacts are typically applications or libraries
    role = artifact.get("role", "binary")
    if role in ("library", "module"):
        comp_type = ComponentType.LIBRARY
    elif role == "kernel-module":
        comp_type = ComponentType.LIBRARY  # kernel modules are a type of library
    else:
        # Use source component type as fallback
        source_type = source_component.get("type", "library")
        comp_type = TYPE_MAP.get(source_type, ComponentType.LIBRARY)

    # Create bom-ref from purl
    bom_ref = create_bom_ref(purl_str, name, version)

    # Parse PURL
    purl = parse_purl(purl_str) if purl_str else None

    # Create hashes
    hashes = create_hash_types(artifact.get("hashes", []))

    # Create properties (includes depends, role, provides, source_component)
    properties = create_properties(artifact, source_component.get("name", ""))

    # Add source component properties (patches, patched_cves, static_libs)
    properties.update(create_component_properties(source_component))

    # Get CPE from source component
    cpe = source_component.get("cpe")

    # Get licenses from source component
    licenses_data = source_component.get("licenses", [])
    license_expr = create_license_expression(licenses_data)
    licenses = {license_expr} if license_expr else set()

    # Get external references from source component
    ext_refs = create_external_references(source_component.get("externalReferences", []))

    # Get description (prefer artifact description, fall back to source component)
    description = artifact.get("description") or source_component.get("description")

    # Create the component
    component = Component(
        type=comp_type,
        name=name,
        version=version,
        bom_ref=bom_ref,
        purl=purl,
        cpe=cpe,
        hashes=hashes if hashes else None,
        licenses=licenses if licenses else None,
        description=description,
        external_references=ext_refs if ext_refs else None,
        properties=properties if properties else None,
    )

    return component


def generate_sbom(input_path: Path, output_path: Path, pretty: bool = False) -> int:
    """
    Generate CycloneDX v1.6 SBOM from enhanced metadata.

    Returns: 0 on success, non-zero on error
    """
    # Load input data
    print(f"Loading enhanced metadata from {input_path}")
    with open(input_path, 'r') as f:
        data = json.load(f)

    # Extract metadata
    project_name = data.get("project_name", "OpenWrt")
    project_release = data.get("project_release", "")
    components_data = data.get("components", [])

    print(f"Project: {project_name}")
    print(f"Release: {project_release}")
    print(f"Source components: {len(components_data)}")

    # Create BOM
    bom = Bom()

    # Add metadata to BOM
    bom.metadata.timestamp = datetime.now(timezone.utc)

    # Create root component for the firmware/project
    root_component = Component(
        type=ComponentType.FIRMWARE,
        name=project_name,
        version=project_release,
        bom_ref=f"pkg:firmware/{project_name.lower().replace(' ', '-')}@{project_release}",
        description=f"OpenWrt-based firmware: {project_release}",
    )
    bom.metadata.component = root_component

    # First pass: Create all components and build lookup maps
    total_artifacts = 0
    all_components = []
    component_by_name = {}  # package name -> Component
    artifact_by_name = {}   # package name -> artifact dict (for depends lookup)

    for source_component in components_data:
        artifacts = source_component.get("artifacts", [])

        for artifact in artifacts:
            component = create_binary_component(artifact, source_component)
            bom.components.add(component)
            all_components.append(component)

            # Map package name to component for dependency resolution
            pkg_name = artifact.get("name", "")
            component_by_name[pkg_name] = component
            artifact_by_name[pkg_name] = artifact

            total_artifacts += 1

    print(f"Generated {total_artifacts} binary components")

    # Build virtual package map (provides -> implementing package)
    virtual_packages = data.get("virtual_packages", {})
    for virtual_name, impl_name in virtual_packages.items():
        if impl_name in component_by_name:
            component_by_name[virtual_name] = component_by_name[impl_name]

    # Second pass: Register dependency graph for each component
    deps_registered = 0
    for pkg_name, component in component_by_name.items():
        artifact = artifact_by_name.get(pkg_name)
        if not artifact:
            continue

        depends = artifact.get("depends", [])
        if not depends:
            # Register component with empty dependencies
            bom.register_dependency(component, [])
            continue

        # Resolve dependencies to actual components
        dep_components = []
        for dep_name in depends:
            dep_component = component_by_name.get(dep_name)
            if dep_component:
                dep_components.append(dep_component)

        bom.register_dependency(component, dep_components if dep_components else None)
        if dep_components:
            deps_registered += len(dep_components)

    # Register root component depends on all binary components
    bom.register_dependency(root_component, all_components)

    print(f"Registered {deps_registered} inter-component dependencies")

    # Generate output using CycloneDX library
    output_format = JsonV1Dot6(bom)
    sbom_json = output_format.output_as_string(indent=2 if pretty else None)

    # Write output
    with open(output_path, 'w') as f:
        f.write(sbom_json)

    print(f"\nWrote CycloneDX v1.6 SBOM to {output_path}")

    # Print summary statistics
    output_size = output_path.stat().st_size
    print(f"Output size: {output_size:,} bytes")

    # Validate output by re-parsing
    with open(output_path, 'r') as f:
        sbom_data = json.load(f)

    print(f"\nSBOM Summary:")
    print(f"  Spec version: {sbom_data.get('specVersion', 'unknown')}")
    print(f"  Components: {len(sbom_data.get('components', []))}")

    # Count components with various fields
    components_list = sbom_data.get('components', [])
    with_cpe = sum(1 for c in components_list if c.get('cpe'))
    with_purl = sum(1 for c in components_list if c.get('purl'))
    with_hashes = sum(1 for c in components_list if c.get('hashes'))
    with_licenses = sum(1 for c in components_list if c.get('licenses'))

    print(f"  With CPE: {with_cpe}")
    print(f"  With PURL: {with_purl}")
    print(f"  With hashes: {with_hashes}")
    print(f"  With licenses: {with_licenses}")

    return 0


def derive_output_filename(project_name: str) -> str:
    """
    Derive output filename from project name.

    Removes all spaces and appends '_SBOM.json'.
    Example: "Explorer II - OpenWRT21.02-Z8106" -> "ExplorerII-OpenWRT21.02-Z8106_SBOM.json"
    """
    # Remove all spaces from project name
    sanitized = project_name.replace(" ", "")
    return f"{sanitized}_SBOM.json"


def main():
    parser = argparse.ArgumentParser(
        description='Generate CycloneDX v1.6 SBOM from enhanced metadata.'
    )
    parser.add_argument(
        '--input', '-i',
        type=Path,
        default=None,
        help='Input file (default: enhanced_metadata.json in script directory)'
    )
    parser.add_argument(
        '--output', '-o',
        type=Path,
        default=None,
        help='Output file (default: derived from project name, e.g., ProjectName_SBOM.json)'
    )
    parser.add_argument(
        '--pretty',
        action='store_true',
        help='Pretty-print JSON output'
    )
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    input_path = args.input or (script_dir / 'enhanced_metadata.json')

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        print("Please run analyze_metadata.py first to generate enhanced_metadata.json")
        return 1

    # Derive output filename from project name if not explicitly specified
    if args.output:
        output_path = args.output
    else:
        # Load input to get project name for output filename
        with open(input_path, 'r') as f:
            data = json.load(f)
        project_name = data.get("project_name", "OpenWrt")
        output_filename = derive_output_filename(project_name)
        output_path = script_dir / output_filename

    return generate_sbom(input_path, output_path, args.pretty)


if __name__ == '__main__':
    exit(main())
