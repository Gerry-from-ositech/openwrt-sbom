"""
kernel_metadata.py — Linux kernel metadata extraction for OpenWRT builds.

Extracts kernel version, patches, and metadata from the kernel build directory.
Optionally includes kernel modules (kmod-*) as nested components.
"""

import os
from pathlib import Path
from typing import Optional, List


def find_linux_build_dir(build_root: Path) -> Optional[Path]:
    """
    Find the Linux kernel build directory within the OpenWRT build tree.

    Searches for directories matching pattern:
        build_dir/target-*/linux-*/linux-*

    Returns:
        Path to Linux kernel build directory, or None if not found.
    """
    build_dir = build_root / "build_dir"
    if not build_dir.exists():
        return None

    # Search for target directories
    for target_dir in build_dir.glob("target-*"):
        # Search for linux-{target}_{subtarget} directories
        for linux_target_dir in target_dir.glob("linux-*_*"):
            # Search for linux-{version} directories
            for linux_dir in linux_target_dir.glob("linux-[0-9]*"):
                if (linux_dir / "Makefile").exists():
                    return linux_dir

    return None


def extract_kernel_metadata(
    linux_root_dir: Path,
    build_root: Path,
    include_kmods: bool = False,
    packages_manifest: Path = None
) -> Optional[dict]:
    """
    Extract Linux kernel metadata from OpenWRT build directory.

    Args:
        linux_root_dir: Path to the Linux kernel build directory
        build_root: OpenWRT build root directory
        include_kmods: If True, include kernel modules as nested components
        packages_manifest: Path to Packages.manifest (for kmod extraction)

    Returns:
        Dictionary with kernel metadata or None if extraction fails
    """
    if not linux_root_dir or not linux_root_dir.exists():
        return None

    kernel_data = {}

    # 1. Extract version from kernel Makefile
    kernel_makefile = linux_root_dir / "Makefile"
    if kernel_makefile.exists():
        try:
            with open(kernel_makefile, 'r', encoding='utf-8') as f:
                lines = f.readlines()[:20]  # Version info is in first 20 lines

                version_parts = {}
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith('#') and "License-Identifier:" in line:
                        kernel_data['licence'] = line[1:].strip()
                    if line.startswith('VERSION ='):
                        version_parts['VERSION'] = line.split('=', 1)[1].strip()
                    elif line.startswith('PATCHLEVEL ='):
                        version_parts['PATCHLEVEL'] = line.split('=', 1)[1].strip()
                    elif line.startswith('SUBLEVEL ='):
                        version_parts['SUBLEVEL'] = line.split('=', 1)[1].strip()
                    elif line.startswith('EXTRAVERSION ='):
                        extraversion = line.split('=', 1)[1].strip()
                        if extraversion:
                            version_parts['EXTRAVERSION'] = extraversion
                    elif line.startswith('NAME ='):
                        kernel_data['codename'] = line.split('=', 1)[1].strip()

                # Construct full version
                if 'VERSION' in version_parts and 'PATCHLEVEL' in version_parts:
                    version = f"{version_parts['VERSION']}.{version_parts['PATCHLEVEL']}"
                    if 'SUBLEVEL' in version_parts and version_parts['SUBLEVEL']:
                        version += f".{version_parts['SUBLEVEL']}"
                    if 'EXTRAVERSION' in version_parts:
                        version += version_parts['EXTRAVERSION']
                    kernel_data['version'] = version

        except Exception as e:
            print(f"Error reading kernel Makefile: {e}")

    # 2. Extract target and subtarget from path
    path_str = str(linux_root_dir)
    path_parts = path_str.split('/')
    for part in path_parts:
        if part.startswith('linux-') and '_' in part:
            target_info = part[6:]  # Remove "linux-" prefix
            if '_' in target_info:
                target, subtarget = target_info.split('_', 1)
                kernel_data['architecture'] = f"{target}-{subtarget}"
                kernel_data['target'] = target
                break

    # 3. Standard kernel metadata
    kernel_data['package'] = 'linux'
    kernel_data['section'] = 'kernel'
    kernel_data['license'] = 'GPL-2.0'
    kernel_data['description'] = 'The Linux kernel is a free and open-source, monolithic, modular, multitasking, Unix-like operating system kernel.'
    kernel_data['maintainer'] = 'Linux Kernel Organization <torvalds@linux-foundation.org>'

    # 4. Construct source URL
    if 'version' in kernel_data:
        version = kernel_data['version']
        major_version = version.split('.')[0]
        kernel_data['source_url'] = f"https://cdn.kernel.org/pub/linux/kernel/v{major_version}.x/linux-{version}.tar.xz"

    # 5. Construct cpe_id (CPE 2.3 format)
    if 'version' in kernel_data:
        version = kernel_data['version']
        kernel_data['cpe_id'] = f"cpe:2.3:o:linux:linux_kernel:{version}:*:*:*:*:*:*:*"

    # 6. Extract patches from target/linux/{target}/patches-{patchver}
    patches = []
    if 'target' in kernel_data and 'version' in kernel_data:
        target = kernel_data['target']
        version_parts = kernel_data['version'].split('.')
        if len(version_parts) >= 2:
            patchver = f"{version_parts[0]}.{version_parts[1]}"
            patches_dir = build_root / 'target' / 'linux' / target / f'patches-{patchver}'

            if patches_dir.exists() and patches_dir.is_dir():
                try:
                    patch_files = sorted([
                        f.name for f in patches_dir.iterdir()
                        if f.is_file() and f.suffix == '.patch'
                    ])
                    patches = patch_files
                except Exception as e:
                    print(f"Error reading kernel patches: {e}")

    if patches:
        kernel_data['patches'] = patches

    kernel_data['modified'] = len(patches) > 0

    # 7. CycloneDX-specific fields
    version = kernel_data.get('version', 'unknown')
    kernel_data['type'] = 'operating-system'
    kernel_data['bom_ref'] = f"pkg:generic/linux_kernel@{version}"
    kernel_data['purl'] = f"pkg:generic/linux@{version}?download_url=https://cdn.kernel.org/pub/linux/kernel/"

    # 8. Include kernel modules if requested
    if include_kmods and packages_manifest:
        kmods = extract_kernel_modules(packages_manifest)
        if kmods:
            kernel_data['components'] = kmods

    return kernel_data


def extract_kernel_modules(packages_manifest: Path) -> List[dict]:
    """
    Extract kernel module metadata from Packages.manifest.

    Args:
        packages_manifest: Path to Packages.manifest file

    Returns:
        List of kernel module component dictionaries
    """
    kmods = []

    if not packages_manifest or not packages_manifest.exists():
        return kmods

    try:
        content = packages_manifest.read_text()
        # Split into package blocks
        blocks = content.split('\n\n')

        for block in blocks:
            if not block.strip():
                continue

            # Parse the block
            pkg_data = {}
            for line in block.split('\n'):
                if ':' in line and not line.startswith(' '):
                    key, value = line.split(':', 1)
                    pkg_data[key.strip()] = value.strip()

            # Only include kmod-* packages
            pkg_name = pkg_data.get('Package', '')
            if pkg_name.startswith('kmod-'):
                kmod = {
                    'type': 'library',
                    'name': pkg_name,
                    'version': pkg_data.get('Version', ''),
                    'description': pkg_data.get('Description', '').lstrip(),
                }
                kmods.append(kmod)

    except Exception as e:
        print(f"Error reading Packages.manifest: {e}")

    return kmods
