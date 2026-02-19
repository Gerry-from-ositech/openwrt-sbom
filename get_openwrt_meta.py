#!/usr/bin/env python3
"""
get_openwrt_meta.py — OpenWRT for Explorer II development

Extracts Version, License and source url for OpenWRT used for Explorer II-Z8106
"""
import os


# ----------------------------------------------------------------------
# Version detection
# ----------------------------------------------------------------------

def extract_openwrt_version(root):
    
    ret = "unknown"
    i = root.find("OpenWRT")
    if i != -1:
        x = root[i:].find('-')
        ret = root[i+7:i+x]
    
    return ret
    

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

    return " OR ".join(sorted(spdx_ids))

# ----------------------------------------------------------------------
# Combined scanner
# ----------------------------------------------------------------------

def extract_openwrt_metadata(root):
    
    openwrt_build_dir = str(root)

    return {
        "package": "openwrt",
        "version": extract_openwrt_version(openwrt_build_dir),
        "license": extract_openwrt_license(openwrt_build_dir),
        "type": "os",
        "source_url": "https://downloads.openwrt.org/releases/21.02",
        "description": "open-source, Linux-based operating system designed for embedded devices"
    }

# ----------------------------------------------------------------------
# CLI entry point
# ----------------------------------------------------------------------
OPENWRT_ROOT_DIR = "/home/gerry/OpenWRT21.02-Z8106"
if __name__ == "__main__":
    result = extract_openwrt_metadata(OPENWRT_ROOT_DIR)
    print(result)

