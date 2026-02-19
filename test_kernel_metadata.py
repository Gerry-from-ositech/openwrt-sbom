#!/usr/bin/env python3
"""
Test script for extracting Linux kernel metadata from OpenWRT build.
Demonstrates kmod inclusion/exclusion options.
"""

import os
import re
from pathlib import Path
from pprint import pprint
from typing import Optional, Dict, List

# Configuration
OPENWRT_ROOT_DIR = Path("/home/gerry/OpenWRT21.02-Z8106")
LINUX_BUILD_DIR = OPENWRT_ROOT_DIR / "build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_mt7981/linux-5.4.213"
PACKAGES_MANIFEST = OPENWRT_ROOT_DIR / "bin/targets/mediatek/mt7981/packages/Packages.manifest"


def extract_kernel_metadata(linux_root_dir: str, include_kmods: bool = False) -> Optional[Dict]:
    """
    Extract Linux kernel metadata from OpenWRT build directory.

    Args:
        linux_root_dir: Path to the Linux kernel build directory
        include_kmods: If True, include kernel modules as nested components

    Returns:
        Dictionary with kernel metadata or None if extraction fails
    """
    if not os.path.exists(linux_root_dir):
        print(f"Warning: Linux kernel directory not found: {linux_root_dir}")
        return None

    kernel_data = {}

    # 1. Extract version from kernel Makefile
    kernel_makefile = os.path.join(linux_root_dir, "Makefile")
    if os.path.exists(kernel_makefile):
        try:
            with open(kernel_makefile, 'r', encoding='utf-8') as f:
                lines = f.readlines()[:20]  # Version info is in first 20 lines

                version_parts = {}
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if line[0] == '#' and "License-Identifier:" in line:
                        kernel_data['licence'] = line[1:]
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
                        kernel_data['name'] = line.split('=', 1)[1].strip()

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
    path_parts = linux_root_dir.split('/')
    for part in path_parts:
        if part.startswith('linux-') and '_' in part:
            target_info = part[6:]  # Remove "linux-" prefix
            if '_' in target_info:
                target, subtarget = target_info.split('_', 1)
                kernel_data['architecture'] = f"{target}-{subtarget}"
                kernel_data['target'] = target
                break

    # 3. Construct source URL
    if 'version' in kernel_data:
        version = kernel_data['version']
        major_version = version.split('.')[0]
        kernel_data['source'] = f"https://cdn.kernel.org/pub/linux/kernel/v{major_version}.x/linux-{version}.tar.xz"

    # 4. Set standard kernel metadata
    kernel_data['section'] = 'kernel'
    kernel_data['homepage'] = 'https://www.kernel.org'
    kernel_data['license'] = 'GPL-2.0'
    kernel_data['description'] = 'The Linux kernel is a free and open-source, monolithic, modular, multitasking, Unix-like operating system kernel.'
    kernel_data['maintainer'] = 'Linux Kernel Organization'

    # 5. Construct cpe_id (CPE 2.3 format)
    if 'version' in kernel_data:
        version = kernel_data['version']
        kernel_data['cpe_id'] = f"cpe:2.3:o:linux:linux_kernel:{version}:*:*:*:*:*:*:*"

    # 6. Extract patches from target/linux/{target}/patches-{patchver}
    if 'target' in kernel_data and 'version' in kernel_data:
        target = kernel_data['target']
        version_parts = kernel_data['version'].split('.')
        if len(version_parts) >= 2:
            patchver = f"{version_parts[0]}.{version_parts[1]}"
            patches_dir = os.path.join(OPENWRT_ROOT_DIR, 'target', 'linux', target, f'patches-{patchver}')

            if os.path.exists(patches_dir) and os.path.isdir(patches_dir):
                try:
                    patch_files = [f for f in os.listdir(patches_dir)
                                   if f.endswith('.patch') and os.path.isfile(os.path.join(patches_dir, f))]
                    if patch_files:
                        patch_files.sort()
                        kernel_data['patch_count'] = len(patch_files)
                except Exception as e:
                    print(f"Error reading kernel patches: {e}")

    # 7. Add CycloneDX-specific fields
    version = kernel_data.get('version', 'unknown')
    kernel_data['bom-ref'] = f"pkg:openwrt/linux-kernel@{version}"
    kernel_data['type'] = 'operating-system'
    kernel_data['purl'] = f"pkg:generic/linux@{version}?download_url=https://cdn.kernel.org/pub/linux/kernel/"
    kernel_data['modified'] = kernel_data.get('patch_count', 0) > 0

    # 8. Include kernel modules if requested
    if include_kmods:
        kmods = extract_kernel_modules()
        if kmods:
            kernel_data['components'] = kmods

    return kernel_data


def extract_kernel_modules() -> List[Dict]:
    """
    Extract kernel module metadata from Packages.manifest.

    Returns:
        List of kernel module component dictionaries
    """
    kmods = []

    if not PACKAGES_MANIFEST.exists():
        print(f"Warning: Packages.manifest not found: {PACKAGES_MANIFEST}")
        return kmods

    try:
        content = PACKAGES_MANIFEST.read_text()
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


def main():
    """Test kernel metadata extraction with both kmod options."""

    print("=" * 70)
    print("TEST 1: Kernel metadata WITHOUT kmod components (include_kmods=False)")
    print("=" * 70)

    kernel_data = extract_kernel_metadata(str(LINUX_BUILD_DIR), include_kmods=False)

    if kernel_data:
        pprint(kernel_data, width=100, sort_dicts=False)
    else:
        print("Failed to extract kernel metadata")

    print("\n")
    print("=" * 70)
    print("TEST 2: Kernel metadata WITH kmod components (include_kmods=True)")
    print("=" * 70)

    kernel_data_with_kmods = extract_kernel_metadata(str(LINUX_BUILD_DIR), include_kmods=True)

    if kernel_data_with_kmods:
        # Show summary first
        components = kernel_data_with_kmods.get('components', [])
        print(f"\nKernel modules found: {len(components)}")
        print("\nFirst 5 kernel modules:")
        for kmod in components[:5]:
            print(f"  - {kmod['name']}: {kmod.get('description', '')[:50]}...")

        print("\n\nFull kernel metadata (components truncated to first 5):")
        # Truncate components for display
        display_data = kernel_data_with_kmods.copy()
        if 'components' in display_data and len(display_data['components']) > 5:
            display_data['components'] = display_data['components'][:5]
            display_data['components'].append({'...': f'and {len(components) - 5} more modules'})

        pprint(display_data, width=100, sort_dicts=False)
    else:
        print("Failed to extract kernel metadata")


if __name__ == '__main__':
    main()
