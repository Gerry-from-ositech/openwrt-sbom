#!/usr/bin/env python3
"""
get_openwrt_meta.py — OpenWRT for Explorer II development

Extracts Version, License and source url for OpenWRT used for Explorer II-Z8106
"""
import os
import re


# ----------------------------------------------------------------------
# Version detection
# ----------------------------------------------------------------------

def extract_openwrt_release_from_version_mk(root):
    """
    Parse include/version.mk to extract the OpenWrt release version.

    Looks for the VERSION_NUMBER default value, e.g.:
        VERSION_NUMBER:=$(if $(VERSION_NUMBER),$(VERSION_NUMBER),21.02-SNAPSHOT)

    Returns the base release version (e.g., "21.02") or None if not found.
    """
    version_mk = os.path.join(root, "include", "version.mk")
    if not os.path.isfile(version_mk):
        return None

    try:
        with open(version_mk, 'r') as f:
            content = f.read()

        # Look for VERSION_NUMBER default: ,21.02-SNAPSHOT) or ,22.03.5)
        # Pattern matches the default value in $(if ...,DEFAULT)
        match = re.search(
            r'VERSION_NUMBER:=\$\(if[^,]+,[^,]+,([^)]+)\)',
            content
        )
        if match:
            version = match.group(1).strip()
            # Remove -SNAPSHOT suffix if present to get base release
            base_version = re.sub(r'-SNAPSHOT$', '', version)
            return base_version

        # Fallback: look for direct assignment
        match = re.search(r'VERSION_NUMBER:=([^\s\n]+)', content)
        if match:
            version = match.group(1).strip()
            if not version.startswith('$('):
                return re.sub(r'-SNAPSHOT$', '', version)

    except (IOError, OSError):
        pass

    return None


def extract_openwrt_version_from_dirname(root):
    """
    Fallback: Extract version from directory name pattern OpenWRTXX.XX-*
    """
    ret = "unknown"
    i = root.find("OpenWRT")
    if i != -1:
        x = root[i:].find('-')
        if x != -1:
            ret = root[i+7:i+x]
    return ret


def extract_openwrt_version(root):
    """
    Extract OpenWrt release version, preferring version.mk over directory name.
    """
    # Try version.mk first (more reliable)
    version = extract_openwrt_release_from_version_mk(root)
    if version:
        return version

    # Fallback to directory name parsing
    return extract_openwrt_version_from_dirname(root)
    

# ----------------------------------------------------------------------
# License detection
# ----------------------------------------------------------------------

def extract_openwrt_license(root):
    licenses_dir = os.path.join(root, "LICENSES")
    if not os.path.isdir(licenses_dir):
        return None

    spdx_ids = []
    for entry in os.listdir(licenses_dir):
        full = os.path.join(licenses_dir, entry)
        if os.path.isfile(full):
            spdx_ids.append(entry.strip())

    if not spdx_ids:
        return None

    return ",".join(sorted(spdx_ids))

# ----------------------------------------------------------------------
# Combined scanner
# ----------------------------------------------------------------------

def extract_openwrt_metadata(root):
    """
    Extract comprehensive OpenWrt metadata from a build directory.
    """
    openwrt_build_dir = str(root)
    version = extract_openwrt_version(openwrt_build_dir)

    return {
        "package": "openwrt",
        "version": version,
        "license": extract_openwrt_license(openwrt_build_dir),
        "type": "os",
        "source_url": f"https://downloads.openwrt.org/releases/{version}",
        "description": "open-source, Linux-based operating system designed for embedded devices"
    }

# ----------------------------------------------------------------------
# CLI entry point
# ----------------------------------------------------------------------
OPENWRT_ROOT_DIR = "/home/gerry/OpenWRT21.02-Z8106"
if __name__ == "__main__":
    result = extract_openwrt_metadata(OPENWRT_ROOT_DIR)
    print(result)

