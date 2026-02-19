"""
metadata_extractor.py — OpenWrt firmware component metadata extractor.

Reads config.json from the project directory, constructs key build paths,
and extracts package metadata from IPK files.

Directory layout assumed:
    <parent>/
        <openwrt_build_root>/    ← OpenWrt build tree (from config)
        openwrt-metadata-extractor/  ← this project (CWD when running)
"""

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from datetime import datetime
from pathlib import Path
from typing import Optional

from kernel_metadata import extract_kernel_metadata, find_linux_build_dir
from get_openwrt_meta import extract_openwrt_metadata


# ---------------------------------------------------------------------------
# Known Metadata for packages without CPE in IPK or Makefile
# ---------------------------------------------------------------------------
# CPE values are in 2.2 URI format - will be converted to 2.3 at runtime
KNOWN_METADATA = {
    'musl': {
        'license': 'MIT',
        'cpe_id': 'cpe:/a:musl-libc:musl',
        'description': 'musl is a lightweight, fast, simple, free C standard library.',
    },
    'busybox': {
        'cpe_id': 'cpe:/a:busybox:busybox',
        'description': 'BusyBox combines tiny versions of many common UNIX utilities into a single small executable.',
    },
    'gcc': {
        'license': 'GPL-3.0-with-GCC-exception',
        'cpe_id': 'cpe:/a:gnu:gcc',
    },
    'binutils': {
        'license': 'GPL-3.0+',
        'cpe_id': 'cpe:/a:gnu:binutils',
    },
    'glibc': {
        'license': 'LGPL-2.1',
        'cpe_id': 'cpe:/a:gnu:glibc',
    },
    'gdb': {
        'license': 'GPL-3.0+',
        'cpe_id': 'cpe:/a:gnu:gdb',
    },
    'libjpeg-turbo': {
        'cpe_id': 'cpe:/a:libjpeg-turbo:libjpeg-turbo',
    },
    'libnghttp2-14': {
        'cpe_id': 'cpe:/a:nghttp2:nghttp2',
    },
    'iperf': {
        'cpe_id': 'cpe:/a:iperf_project:iperf',
    },
    'iperf3': {
        'cpe_id': 'cpe:/a:es:iperf3',
    },
    'libgmp10': {
        'cpe_id': 'cpe:/a:gmplib:gmp',
    },
    'liblz4-1': {
        'cpe_id': 'cpe:/a:lz4_project:lz4',
    },
    'libnettle8': {
        'cpe_id': 'cpe:/a:nettle_project:nettle',
    },
    'libcap': {
        'cpe_id': 'cpe:/a:libcap_project:libcap',
    },
    'lua': {
        'cpe_id': 'cpe:/a:lua:lua',
    },
    'libpcap1': {
        'cpe_id': 'cpe:/a:tcpdump:libpcap',
    },
    'libncurses6': {
        'cpe_id': 'cpe:/a:gnu:ncurses',
    },
    'terminfo': {
        'cpe_id': 'cpe:/a:gnu:ncurses',
    },
    'minidlna': {
        'cpe_id': 'cpe:/a:minidlna_project:minidlna',
    },
    'xl2tpd': {
        'cpe_id': 'cpe:/a:xelerance:xl2tpd',
    },
    'ksmbd-server': {
        'cpe_id': 'cpe:/a:ksmbd_project:ksmbd',
    },
    'ipset': {
        'cpe_id': 'cpe:/a:netfilter:ipset',
    },
    'libipset13': {
        'cpe_id': 'cpe:/a:netfilter:ipset',
    },
    'libmnl0': {
        'cpe_id': 'cpe:/a:netfilter:libmnl',
    },
    'libnfnetlink0': {
        'cpe_id': 'cpe:/a:netfilter:libnfnetlink',
    },
    'libnetfilter-conntrack3': {
        'cpe_id': 'cpe:/a:netfilter:libnetfilter_conntrack',
    },
    'libusb-1.0-0': {
        'cpe_id': 'cpe:/a:libusb:libusb',
    },
    'ethtool': {
        'cpe_id': 'cpe:/a:kernel:ethtool',
    },
    'wireguard-tools': {
        'cpe_id': 'cpe:/a:wireguard:wireguard-tools',
    },
    'libtirpc': {
        'cpe_id': 'cpe:/a:libtirpc_project:libtirpc',
    },
    'liblzo2': {
        'cpe_id': 'cpe:/a:oberhumer:lzo',
    },
    'libgpg-error': {
        'cpe_id': 'cpe:/a:gnupg:libgpg-error',
    },
    'libimobiledevice': {
        'cpe_id': 'cpe:/a:libimobiledevice:libimobiledevice',
    },
    'attr': {
        'cpe_id': 'cpe:/a:gnu:attr',
    },
    'libattr': {
        'cpe_id': 'cpe:/a:gnu:attr',
    },
    'libedit': {
        'cpe_id': 'cpe:/a:thrysoee:libedit',
    },
    'libevdev': {
        'cpe_id': 'cpe:/a:freedesktop:libevdev',
    },
    'liburing': {
        'cpe_id': 'cpe:/a:kernel:liburing',
    },
    'iw': { 
       'cpe_id': 'cpe:/a:kernel:iw',
    },
}


# ---------------------------------------------------------------------------
# Known Embedded/Statically-Linked Libraries
# ---------------------------------------------------------------------------
# Maps package names to libraries they embed or statically link.
# These cannot be detected from Makefiles because the code is built-in.
# Format: package_name -> list of {name, version (optional), cpe_id (optional), notes}

KNOWN_EMBEDDED_LIBRARIES = {
    'dropbear': [
        {
            'name': 'libtomcrypt',
            'cpe_id': 'cpe:2.3:a:libtom:libtomcrypt:*:*:*:*:*:*:*:*',
            'notes': 'Built-in crypto library, not dynamically linked',
        },
        {
            'name': 'libtommath',
            'cpe_id': 'cpe:2.3:a:libtom:libtommath:*:*:*:*:*:*:*:*',
            'notes': 'Built-in bignum library used by libtomcrypt',
        },
    ],
    'busybox': [
        {
            'name': 'busybox-internal-zlib',
            'notes': 'Busybox may include zlib-like code for gzip/gunzip applets',
            'conditional': 'BUSYBOX_CONFIG_FEATURE_SEAMLESS_GZ',
        },
    ],
    'wolfssl': [
        {
            'name': 'wolfcrypt',
            'cpe_id': 'cpe:2.3:a:wolfssl:wolfssl:*:*:*:*:*:*:*:*',
            'notes': 'wolfCrypt is embedded in wolfSSL',
        },
    ],
    'mbedtls': [
        {
            'name': 'mbedcrypto',
            'cpe_id': 'cpe:2.3:a:arm:mbed_tls:*:*:*:*:*:*:*:*',
            'notes': 'mbedcrypto is embedded in mbedTLS',
        },
    ],
    'hostapd': [
        {
            'name': 'internal-crypto',
            'notes': 'hostapd can use internal crypto implementation',
            'conditional': 'CONFIG_INTERNAL_LIBTOMMATH',
        },
    ],
    'wpa-supplicant': [
        {
            'name': 'internal-crypto',
            'notes': 'wpa_supplicant can use internal crypto implementation',
            'conditional': 'CONFIG_INTERNAL_LIBTOMMATH',
        },
    ],
}


# ---------------------------------------------------------------------------
# CPE Format Conversion
# ---------------------------------------------------------------------------

def convert_cpe22_to_cpe23(cpe22: str) -> str:
    """
    Convert CPE 2.2 URI format to CPE 2.3 formatted string.

    CPE 2.2 URI: cpe:/{part}:{vendor}:{product}:{version}...
    CPE 2.3 FS:  cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*

    Examples:
        cpe:/a:openssl:openssl:1.1.1 -> cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*
        cpe:/o:linux:linux_kernel    -> cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*

    Args:
        cpe22: CPE 2.2 URI format string

    Returns:
        CPE 2.3 formatted string, or original if conversion fails
    """
    if not cpe22:
        return cpe22

    # Already in CPE 2.3 format
    if cpe22.startswith("cpe:2.3:"):
        return cpe22

    # Must be CPE 2.2 URI format: cpe:/{part}:{vendor}:{product}...
    if not cpe22.startswith("cpe:/"):
        return cpe22

    try:
        # Remove "cpe:/" prefix
        content = cpe22[5:]

        # Split into components
        parts = content.split(":")

        if len(parts) < 2:
            return cpe22

        # First character is the part (a, o, h)
        part = parts[0] if parts[0] else "a"

        # Remaining components: vendor, product, version, update, edition, language
        components = parts[1:] if len(parts) > 1 else []

        # Build CPE 2.3 with exactly 11 components total
        # Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        cpe23_parts = ["cpe", "2.3", part]

        # Add up to 10 more components, using * for missing values
        for i in range(10):
            if i < len(components) and components[i]:
                # Escape special characters in CPE 2.3
                value = components[i].replace("\\", "\\\\")
                cpe23_parts.append(value)
            else:
                cpe23_parts.append("*")

        return ":".join(cpe23_parts)

    except Exception:
        return cpe22


def extract_cpe_from_makefile(makefile_path: Path) -> Optional[str]:
    """
    Extract PKG_CPE_ID from an OpenWrt package Makefile.

    Searches for line matching: PKG_CPE_ID:=<value>

    Args:
        makefile_path: Path to package Makefile

    Returns:
        CPE-ID string or None if not found
    """
    if not makefile_path.exists():
        return None

    try:
        with open(makefile_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                # Match PKG_CPE_ID:= or PKG_CPE_ID :=
                match = re.match(r"^\s*PKG_CPE_ID\s*:?=\s*(.+?)\s*$", line)
                if match:
                    cpe_id = match.group(1).strip()
                    if cpe_id:
                        return cpe_id
    except Exception:
        pass

    return None


def find_package_makefile(source_path: str, build_root: Path) -> Optional[Path]:
    """
    Find the Makefile for a package based on its Source path.

    Args:
        source_path: The Source field from IPK (e.g., "feeds/packages/net/curl")
        build_root: OpenWrt build root directory

    Returns:
        Path to Makefile if found, None otherwise
    """
    if not source_path:
        return None

    makefile_path = build_root / source_path / "Makefile"
    if makefile_path.exists():
        return makefile_path

    return None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CONFIG_FILE = Path(__file__).parent / "config.json"


def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        print(f"ERROR: config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    with config_path.open() as f:
        config = json.load(f)

    required = {"openwrt_build_root", "project_name"}
    missing = required - config.keys()
    if missing:
        print(f"ERROR: config missing required keys: {missing}", file=sys.stderr)
        sys.exit(1)

    return config


# ---------------------------------------------------------------------------
# Path construction
# ---------------------------------------------------------------------------

def build_paths(config: dict) -> dict:
    """
    Construct absolute paths for all key OpenWrt build locations.

    The project directory (CWD / script location) sits alongside the
    OpenWrt build root — both are children of the same parent directory.
    """
    project_dir = Path(__file__).parent.resolve()
    parent_dir  = project_dir.parent

    build_root = parent_dir / config["openwrt_build_root"]

    paths = {
        "project_dir":   project_dir,
        "build_root":    build_root,
        "bin_dir":       build_root / "bin",
        "bin_targets":   build_root / "bin" / "targets",
        "bin_packages":  build_root / "bin" / "packages",
        "build_dir":     build_root / "build_dir",
    }
    return paths


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------

def find_ipk_files(paths: dict) -> list[Path]:
    """Recursively find all *.ipk files under bin/targets and bin/packages."""
    ipk_files = []
    for search_root in (paths["bin_targets"], paths["bin_packages"]):
        if search_root.exists():
            ipk_files.extend(sorted(search_root.rglob("*.ipk")))
    return ipk_files


def find_manifest_files(paths: dict) -> list[Path]:
    """Recursively find all Packages.manifest files under bin/."""
    if not paths["bin_dir"].exists():
        return []
    return sorted(paths["bin_dir"].rglob("Packages.manifest"))


def find_image_manifest(paths: dict) -> Optional[Path]:
    """
    Find the firmware image manifest file.

    This is the authoritative list of packages actually installed in the
    firmware image (not just built as IPK files). The manifest is typically
    named like: <image-name>.manifest in bin/targets/<target>/<subtarget>/

    Returns:
        Path to image manifest if found, None otherwise
    """
    if not paths["bin_targets"].exists():
        return None

    # Find .manifest files (excluding Packages.manifest)
    manifests = []
    for f in paths["bin_targets"].rglob("*.manifest"):
        if f.name != "Packages.manifest" and not f.name.startswith("Packages"):
            manifests.append(f)

    if not manifests:
        return None

    # If multiple manifests, prefer the one with the largest size (most complete)
    # or return the first one sorted by name
    manifests.sort(key=lambda x: (-x.stat().st_size, x.name))
    return manifests[0]


def parse_image_manifest(manifest_path: Path) -> set[str]:
    """
    Parse the firmware image manifest to get list of installed packages.

    Manifest format is: <package_name> - <version>
    Example: busybox - 1.33.2-5

    Returns:
        Set of package names that are in the firmware image
    """
    packages = set()
    try:
        with open(manifest_path, 'r') as f:
            for line in f:
                line = line.strip()
                if ' - ' in line:
                    pkg_name = line.split(' - ')[0].strip()
                    if pkg_name:
                        packages.add(pkg_name)
    except Exception as e:
        print(f"  Warning: Could not parse image manifest: {e}")
    return packages


def filter_packages_by_manifest(packages: dict, installed_packages: set[str]) -> tuple[dict, list[str]]:
    """
    Filter extracted packages to only include those in the firmware image.

    Args:
        packages: Dictionary of extracted package metadata
        installed_packages: Set of package names from image manifest

    Returns:
        Tuple of (filtered_packages, removed_package_names)
    """
    filtered = {}
    removed = []

    for name, data in packages.items():
        if name != 'kernel' and ( name in ['openwrt','linux'] or name in installed_packages):
        #if  name in ['openwrt','linux'] or name in installed_packages:
            filtered[name] = data
        else:
            removed.append(name)

    return filtered, removed


# ---------------------------------------------------------------------------
# IPK Metadata Extraction
# ---------------------------------------------------------------------------

# IPK Archive Format:
#   IPKs are gzip-compressed tar files containing:
#     ./debian-binary      - format version marker ("2.0")
#     ./control.tar.gz     - metadata (what we extract)
#     ./data.tar.gz        - actual installed files
#   The control file is RFC 822 key:value format, same as Debian packages.

# Fields to extract from IPK control file
# Excludes: Installed-Size, Alternatives, SourceDateEpoch
#
# Field Notes (from analysis of 395 IPKs):
#   Package      - Always present, canonical package name
#   Version      - Always present, see version format variations below
#   Source       - Path within build tree (e.g. feeds/packages/net/curl)
#   SourceName   - Logical source package name (differs from Package for sub-packages)
#   Section      - Category: net, libs, kernel, luci, MTK Properties, etc.
#   Architecture - aarch64_cortex-a53 or "all" (arch-independent)
#   Description  - Human-readable, sometimes multi-line
#   Depends      - Dependency list with optional version constraints (99.5% present)
#   License      - 57 packages have no license, mostly vendor/custom (85.6% present)
#   Maintainer   - Optional upstream maintainer (44.1% present)
#   LicenseFiles - Filenames within package for license text (23.3% present)
#   CPE-ID       - Only 77/395 packages have CPE, critical gap for vuln scanning (19.5%)
#   Provides     - Virtual package name, e.g. libnettle8 provides libnettle (16.2%)
#   ABIVersion   - Library ABI suffix, embedded in package name (12.7% present)
#
# Version Format Variations:
#   semver-pkgrel  - "2020.81-2", "1.8.7-1"  - Most common, upstream_ver-pkgrelease
#   git-hash       - "git-24.341.33460-ea492c5" - LuCI packages tracked by git
#   date-snapshot  - "2021-05-16-b14c4688-2" - Date + commit hash
#   single-int     - "1" - Vendor/custom packages with no real version
#   vendor-r0      - "1-r0-45c8168a" - MTK vendor packages with build commit
#
#   The PKG_RELEASE suffix (-2, -1, etc.) is always the last hyphen-delimited
#   component for semver packages — this is the OpenWrt patch counter.

IPK_FIELDS = [
    "Package",
    "Version",
    "Source",
    "SourceName",
    "Section",
    "Architecture",
    "Description",
    "Depends",
    "License",
    "Maintainer",
    "LicenseFiles",
    "CPE-ID",
    "Provides",
    "ABIVersion",
]


# ---------------------------------------------------------------------------
# CycloneDX Field Generation
# ---------------------------------------------------------------------------

# Section to CycloneDX component type mapping
# See: https://cyclonedx.org/docs/1.6/json/#components_items_type
SECTION_TO_TYPE = {
    "libs": "library",
    "lib": "library",
    "kernel": "operating-system",
    "base": "application",
    "net": "application",
    "utils": "application",
    "luci": "application",
    "lang": "framework",
    "firmware": "firmware",
}


def compute_file_hash(file_path: Path) -> Optional[str]:
    """Compute SHA256 hash of a file."""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None


def derive_component_type(section: str) -> str:
    """
    Derive CycloneDX component type from OpenWrt section.

    Returns one of: application, framework, library, operating-system, firmware
    Default: library
    """
    if not section:
        return "library"
    section_lower = section.lower()
    return SECTION_TO_TYPE.get(section_lower, "library")


def build_purl(name: str, version: str) -> str:
    """
    Build Package URL (purl) for an OpenWrt package.

    Format: pkg:opkg/{name}@{version}
    See: https://github.com/package-url/purl-spec
    """
    # URL-encode special characters in name/version if needed
    return f"pkg:opkg/{name}@{version}"


def build_bom_ref(name: str, version: str) -> str:
    """
    Build unique bom-ref identifier for CycloneDX.

    Uses same format as purl for consistency.
    """
    return f"pkg:opkg/{name}@{version}"


def find_package_patches(source_path: str, build_root: Path) -> list[str]:
    """
    Find patch files for a package based on its Source path.

    Patches are typically in {source}/patches/ directory.

    Args:
        source_path: The Source field from IPK (e.g., "feeds/packages/net/curl")
        build_root: OpenWrt build root directory

    Returns:
        List of patch filenames, or empty list if none found.
    """
    if not source_path:
        return []

    patches_dir = build_root / source_path / "patches"

    if not patches_dir.exists() or not patches_dir.is_dir():
        return []

    try:
        patch_files = sorted([
            f.name for f in patches_dir.iterdir()
            if f.is_file() and f.suffix == ".patch"
        ])
        return patch_files
    except Exception:
        return []


def extract_patched_cves(patches: list[str]) -> dict[str, list[str]]:
    """
    Extract CVE IDs from patch filenames.

    Patches often contain CVE IDs in their names, e.g.:
        CVE-2022-37434.patch
        006-fix-CVE-2022-37434.patch
        102-CVE-2018-16301.patch

    Args:
        patches: List of patch filenames

    Returns:
        Dictionary mapping CVE IDs to list of patches that address them
        Example: {"CVE-2022-37434": ["006-fix-CVE-2022-37434.patch"]}
    """
    cve_pattern = re.compile(r'(CVE-\d{4}-\d+)', re.IGNORECASE)
    patched_cves = {}

    for patch in patches:
        matches = cve_pattern.findall(patch)
        for cve in matches:
            cve_upper = cve.upper()
            if cve_upper not in patched_cves:
                patched_cves[cve_upper] = []
            if patch not in patched_cves[cve_upper]:
                patched_cves[cve_upper].append(patch)

    # Sort by CVE ID
    return dict(sorted(patched_cves.items()))


def extract_download_url_from_makefile(makefile_path: Path) -> Optional[str]:
    """
    Extract PKG_SOURCE_URL from an OpenWrt package Makefile.

    Searches for lines matching:
        PKG_SOURCE_URL:=<value>
        PKG_SOURCE_URL:=<value1> <value2>  (multiple mirrors)

    For git sources, also checks PKG_SOURCE_PROTO.

    Args:
        makefile_path: Path to package Makefile

    Returns:
        Download URL string or None if not found
    """
    if not makefile_path or not makefile_path.exists():
        return None

    source_url = None
    source_proto = None

    try:
        with open(makefile_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

            # Match PKG_SOURCE_URL:= (may span multiple lines with \)
            # First try single-line match
            url_match = re.search(
                r'^\s*PKG_SOURCE_URL\s*:?=\s*(.+?)(?:\s*\\?\s*$)',
                content,
                re.MULTILINE
            )
            if url_match:
                source_url = url_match.group(1).strip()
                # If it ends with \, it continues on next line - just take first URL
                if '\\' in source_url:
                    source_url = source_url.replace('\\', '').strip()
                # Take first URL if multiple (space-separated)
                if ' ' in source_url:
                    source_url = source_url.split()[0]
                # Remove trailing question marks (used for git URLs)
                source_url = source_url.rstrip('?')

            # Check for git protocol
            proto_match = re.search(
                r'^\s*PKG_SOURCE_PROTO\s*:?=\s*(\w+)',
                content,
                re.MULTILINE
            )
            if proto_match:
                source_proto = proto_match.group(1).strip()

            # For git sources without explicit URL, the URL might be the git repo
            if source_proto == 'git' and source_url:
                # Git URLs are used directly
                return source_url

            # Expand common OpenWrt URL macros
            if source_url:
                # Common macros - expand to actual values
                macro_expansions = {
                    '@GNU': 'https://ftp.gnu.org/gnu',
                    '@GNOME': 'https://download.gnome.org/sources',
                    '@SF': 'https://downloads.sourceforge.net',
                    '@GITHUB': 'https://codeload.github.com',
                    '@KERNEL': 'https://www.kernel.org/pub',
                    '@APACHE': 'https://archive.apache.org/dist',
                }
                for macro, url in macro_expansions.items():
                    if source_url.startswith(macro + '/'):
                        source_url = source_url.replace(macro, url, 1)
                        break

                # Skip if still contains unexpanded macros
                if '$(' in source_url or '@' in source_url:
                    return None

                return source_url

    except Exception:
        pass

    return None


def extract_build_depends_from_makefile(makefile_path: Path) -> list[str]:
    """
    Extract PKG_BUILD_DEPENDS from an OpenWrt package Makefile.

    PKG_BUILD_DEPENDS lists packages needed at build time but not necessarily
    at runtime. When a package appears in BUILD_DEPENDS but not in runtime
    DEPENDS, it may indicate static linking.

    Args:
        makefile_path: Path to package Makefile

    Returns:
        List of build dependency package names
    """
    if not makefile_path or not makefile_path.exists():
        return []

    build_deps = []

    try:
        with open(makefile_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

            # Match PKG_BUILD_DEPENDS:= (may have conditional syntax)
            # Examples:
            #   PKG_BUILD_DEPENDS:=libpcap
            #   PKG_BUILD_DEPENDS:=util-linux e2fsprogs/host
            #   PKG_BUILD_DEPENDS:=BUSYBOX_CONFIG_PAM:libpam
            match = re.search(
                r'^\s*PKG_BUILD_DEPENDS\s*:=\s*(.*)$',
                content,
                re.MULTILINE
            )
            if match:
                deps_str = match.group(1).strip()

                # Skip if empty
                if not deps_str:
                    return []

                # Handle line continuation
                if '\\' in deps_str:
                    # Find all continuation lines
                    full_match = re.search(
                        r'^\s*PKG_BUILD_DEPENDS\s*:=\s*(.+?)(?:\n(?!\s*PKG_))',
                        content,
                        re.MULTILINE | re.DOTALL
                    )
                    if full_match:
                        deps_str = full_match.group(1).replace('\\', ' ').replace('\n', ' ')

                # Split by whitespace
                for dep in deps_str.split():
                    dep = dep.strip()
                    if not dep:
                        continue

                    # Handle conditional deps: CONDITION:package
                    if ':' in dep and '=' not in dep:
                        parts = dep.split(':')
                        if len(parts) >= 2:
                            dep = parts[-1]  # Take the package name part

                    # Remove /host suffix (host-only build tools)
                    if dep.endswith('/host'):
                        continue  # Skip host-only tools

                    # Clean up the dependency name
                    dep = dep.strip('+')  # Remove leading + (optional marker)

                    # Validate: must be a valid package name (alphanumeric, dash, underscore)
                    if dep and not dep.startswith('$') and re.match(r'^[a-zA-Z0-9_-]+$', dep):
                        build_deps.append(dep)

    except Exception:
        pass

    return build_deps


def detect_static_dependencies(
    package_name: str,
    build_depends: list[str],
    runtime_depends: list[str],
    config_path: Optional[Path] = None
) -> list[dict]:
    """
    Detect likely statically-linked libraries by comparing build and runtime deps.

    A package in PKG_BUILD_DEPENDS but not in runtime Depends is likely
    statically linked into the binary.

    Args:
        package_name: Name of the package being analyzed
        build_depends: List from PKG_BUILD_DEPENDS
        runtime_depends: List from IPK Depends field
        config_path: Optional path to .config for checking conditionals

    Returns:
        List of dicts with static dependency info
    """
    static_deps = []

    # Normalize runtime depends (remove version constraints)
    runtime_set = set()
    for dep in runtime_depends:
        # Strip version constraints: "libfoo (>= 1.0)" -> "libfoo"
        dep_name = dep.split('(')[0].strip()
        dep_name = dep_name.split()[0] if dep_name else ''
        if dep_name:
            runtime_set.add(dep_name)

    # Check each build dependency
    for build_dep in build_depends:
        # Normalize build dep name
        build_dep = build_dep.strip()

        # Check if this build dep is NOT in runtime deps
        if build_dep and build_dep not in runtime_set:
            # Also check for lib* variants
            lib_variant = f"lib{build_dep}" if not build_dep.startswith('lib') else build_dep
            base_variant = build_dep[3:] if build_dep.startswith('lib') else build_dep

            if lib_variant not in runtime_set and base_variant not in runtime_set:
                static_deps.append({
                    'name': build_dep,
                    'source': 'build_depends',
                    'notes': 'In PKG_BUILD_DEPENDS but not in runtime Depends',
                })

    # Add known embedded libraries
    if package_name in KNOWN_EMBEDDED_LIBRARIES:
        for embedded in KNOWN_EMBEDDED_LIBRARIES[package_name]:
            # Check if conditional is satisfied (if specified)
            if 'conditional' in embedded and config_path:
                # TODO: Check .config for conditional
                pass

            static_dep = {
                'name': embedded['name'],
                'source': 'known_embedded',
                'notes': embedded.get('notes', 'Known embedded library'),
            }
            if 'cpe_id' in embedded:
                static_dep['cpe_id'] = embedded['cpe_id']
            static_deps.append(static_dep)

    return static_deps


def extract_control_from_ipk(ipk_path: Path) -> Optional[str]:
    """
    Extract the control file content from an IPK archive.

    IPK structure (gzip tar):
        ./debian-binary
        ./control.tar.gz  <- contains ./control
        ./data.tar.gz

    Returns:
        Control file content as string, or None if extraction fails.
    """
    try:
        with tarfile.open(ipk_path, "r:gz") as outer_tar:
            # Find control.tar.gz in the outer archive
            for member in outer_tar.getmembers():
                if member.name in ("./control.tar.gz", "control.tar.gz"):
                    control_tar_data = outer_tar.extractfile(member)
                    if control_tar_data is None:
                        continue

                    # Open the inner control.tar.gz
                    with gzip.open(io.BytesIO(control_tar_data.read()), "rb") as gz:
                        with tarfile.open(fileobj=gz, mode="r:") as inner_tar:
                            # Find the control file
                            for inner_member in inner_tar.getmembers():
                                if inner_member.name in ("./control", "control"):
                                    control_file = inner_tar.extractfile(inner_member)
                                    if control_file:
                                        return control_file.read().decode("utf-8")
    except Exception as e:
        print(f"Warning: Failed to extract control from {ipk_path.name}: {e}")

    return None


def parse_control_file(control_content: str) -> dict:
    """
    Parse RFC 822 format control file into a dictionary.

    Handles multi-line values (continuation lines start with space).
    Renames CPE-ID to cpe_id.

    Returns:
        Dictionary of field name -> value.
    """
    data = {}
    current_key = None
    current_value = []

    for line in control_content.split("\n"):
        if line.startswith(" ") or line.startswith("\t"):
            # Continuation line
            if current_key:
                current_value.append(line.strip())
        elif ":" in line:
            # Save previous field
            if current_key:
                value = " ".join(current_value).strip()
                if current_key in IPK_FIELDS:
                    # Rename CPE-ID to cpe_id
                    key = "cpe_id" if current_key == "CPE-ID" else current_key.lower().replace("-", "_")
                    data[key] = value

            # Start new field
            key, _, value = line.partition(":")
            current_key = key.strip()
            current_value = [value.strip()]
        else:
            # Empty line or other - save current field
            if current_key:
                value = " ".join(current_value).strip()
                if current_key in IPK_FIELDS:
                    key = "cpe_id" if current_key == "CPE-ID" else current_key.lower().replace("-", "_")
                    data[key] = value
                current_key = None
                current_value = []

    # Don't forget the last field
    if current_key:
        value = " ".join(current_value).strip()
        if current_key in IPK_FIELDS:
            key = "cpe_id" if current_key == "CPE-ID" else current_key.lower().replace("-", "_")
            data[key] = value

    return data


def extract_ipk_metadata(ipk_path: Path, build_root: Path = None) -> Optional[dict]:
    """
    Extract metadata from a single IPK file.

    Args:
        ipk_path: Path to the IPK file
        build_root: OpenWrt build root (for finding patches and Makefiles)

    Returns:
        Dictionary with package metadata, or None if extraction fails.
    """
    control_content = extract_control_from_ipk(ipk_path)
    if control_content is None:
        return None

    metadata = parse_control_file(control_content)

    # Convert depends from comma-separated string to list of strings
    if "depends" in metadata and metadata["depends"]:
        metadata["depends"] = [dep.strip() for dep in metadata["depends"].split(",")]

    # --- CycloneDX Required/Recommended Fields ---

    name = metadata.get("package", "")
    version = metadata.get("version", "")
    section = metadata.get("section", "")
    source = metadata.get("source", "")

    # type - derived from section
    metadata["type"] = derive_component_type(section)

    # bom-ref - unique identifier
    if name and version:
        metadata["bom_ref"] = build_bom_ref(name, version)

    # purl - Package URL
    if name and version:
        metadata["purl"] = build_purl(name, version)

    # hashes - SHA256 of IPK file
    file_hash = compute_file_hash(ipk_path)
    if file_hash:
        metadata["hashes"] = [{"alg": "SHA-256", "content": file_hash}]

    # patches - list of patch files applied
    if build_root and source:
        patches = find_package_patches(source, build_root)
        if patches:
            metadata["patches"] = patches

            # patched_cves - extract CVE IDs from patch filenames
            patched_cves = extract_patched_cves(patches)
            if patched_cves:
                metadata["patched_cves"] = patched_cves

    # modified - True if patches exist
    metadata["modified"] = len(metadata.get("patches", [])) > 0

    # --- Download URL Extraction ---
    # Extract PKG_SOURCE_URL from Makefile
    makefile_path = None
    if build_root and source:
        makefile_path = find_package_makefile(source, build_root)
        if makefile_path:
            download_url = extract_download_url_from_makefile(makefile_path)
            if download_url:
                metadata["download_url"] = download_url

    # --- Static/Embedded Library Detection ---
    # Detect libraries that are statically linked or embedded in the binary
    if makefile_path:
        build_depends = extract_build_depends_from_makefile(makefile_path)
        if build_depends:
            metadata["build_depends"] = build_depends

        # Get runtime depends from metadata (already parsed from IPK)
        runtime_depends = []
        if "depends" in metadata:
            deps = metadata["depends"]
            if isinstance(deps, list):
                runtime_depends = deps
            elif isinstance(deps, str):
                runtime_depends = [d.strip() for d in deps.split(',') if d.strip()]

        # Detect static dependencies
        static_deps = detect_static_dependencies(
            name,
            build_depends,
            runtime_depends,
            build_root / ".config" if build_root else None
        )
        if static_deps:
            metadata["static_libs"] = static_deps

    # Also check for known embedded libraries even without Makefile
    elif name in KNOWN_EMBEDDED_LIBRARIES:
        static_deps = []
        for embedded in KNOWN_EMBEDDED_LIBRARIES[name]:
            static_dep = {
                'name': embedded['name'],
                'source': 'known_embedded',
                'notes': embedded.get('notes', 'Known embedded library'),
            }
            if 'cpe_id' in embedded:
                static_dep['cpe_id'] = embedded['cpe_id']
            static_deps.append(static_dep)
        if static_deps:
            metadata["static_libs"] = static_deps

    # --- CPE-ID Enrichment (3-tier fallback) ---
    # 1. IPK control file (already extracted above)
    # 2. Makefile PKG_CPE_ID
    # 3. KNOWN_METADATA dictionary

    if "cpe_id" not in metadata and makefile_path:
            makefile_cpe = extract_cpe_from_makefile(makefile_path)
            if makefile_cpe:
                metadata["cpe_id"] = makefile_cpe
                metadata["cpe_source"] = "makefile"

    if "cpe_id" not in metadata and name:
        # Fallback 2: Try KNOWN_METADATA
        # Check exact name first, then try base name without version suffix
        known = KNOWN_METADATA.get(name)
        if not known:
            # Try matching base package name (e.g., "libncurses6" -> check libncurses)
            base_name = re.sub(r'\d+$', '', name)
            if base_name != name:
                known = KNOWN_METADATA.get(base_name)

        if known and "cpe_id" in known:
            metadata["cpe_id"] = known["cpe_id"]
            metadata["cpe_source"] = "known_metadata"

    # Convert all CPE-IDs to CPE 2.3 format
    if "cpe_id" in metadata:
        metadata["cpe_id"] = convert_cpe22_to_cpe23(metadata["cpe_id"])

    # Add the IPK file path for reference
    metadata["ipk_file"] = str(ipk_path)

    return metadata


def extract_all_ipk_metadata(ipk_files: list[Path], build_root: Path = None) -> dict[str, dict]:
    """
    Extract metadata from all IPK files.

    Args:
        ipk_files: List of IPK file paths
        build_root: OpenWrt build root (for finding patches)

    Returns:
        Dictionary keyed by package name, value is package metadata dict.
    """
    packages = {}
    errors = 0

    for ipk_path in ipk_files:
        metadata = extract_ipk_metadata(ipk_path, build_root)
        if metadata and "package" in metadata:
            pkg_name = metadata["package"]
            packages[pkg_name] = metadata
        else:
            errors += 1

    if errors:
        print(f"Warning: Failed to extract metadata from {errors} IPK files")

    return packages


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_paths(config: dict, paths: dict) -> None:
    print("=" * 70)
    print(f"Project : {config['project_name']}")
    print("=" * 70)
    print("\n--- Key build paths ---")
    labels = {
        "project_dir":  "Project dir     ",
        "build_root":   "OpenWrt root    ",
        "bin_dir":      "bin/            ",
        "bin_targets":  "bin/targets/    ",
        "bin_packages": "bin/packages/   ",
        "build_dir":    "build_dir/      ",
    }
    for key, label in labels.items():
        p = paths[key]
        status = "OK" if p.exists() else "NOT FOUND"
        print(f"  {label}: {p}  [{status}]")
    print()


def print_ipk_list(ipk_files: list[Path], build_root: Path) -> None:
    print(f"--- IPK files found: {len(ipk_files)} ---")
    for f in ipk_files:
        print(f"  {f.relative_to(build_root)}")
    print()


def print_manifest_list(manifest_files: list[Path], build_root: Path) -> None:
    print(f"--- Packages.manifest files found: {len(manifest_files)} ---")
    for f in manifest_files:
        print(f"  {f.relative_to(build_root)}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def print_statistics(packages: dict, ipk_files: list, manifest_files: list) -> None:
    """Print detailed statistics and sample packages (verbose mode)."""
    from pprint import pprint

    # Summary statistics
    print("\n" + "=" * 70)
    print("EXTRACTION SUMMARY")
    print("=" * 70)
    print(f"IPK files found:      {len(ipk_files)}")
    print(f"Packages extracted:   {len(packages)}")
    print(f"Manifest files:       {len(manifest_files)}")

    # Field presence statistics
    field_counts = {}
    for pkg_data in packages.values():
        for field in pkg_data:
            if field != "ipk_file":
                field_counts[field] = field_counts.get(field, 0) + 1

    print("\n--- Field Presence ---")
    for field, count in sorted(field_counts.items(), key=lambda x: -x[1]):
        pct = 100 * count / len(packages) if packages else 0
        print(f"  {field:20s}: {count:4d} ({pct:5.1f}%)")

    # CycloneDX field statistics
    cpe_count = field_counts.get("cpe_id", 0)
    patches_count = sum(1 for p in packages.values() if p.get("patches"))
    modified_count = sum(1 for p in packages.values() if p.get("modified"))

    # CPE source breakdown
    cpe_from_ipk = sum(1 for p in packages.values() if "cpe_id" in p and "cpe_source" not in p)
    cpe_from_makefile = sum(1 for p in packages.values() if p.get("cpe_source") == "makefile")
    cpe_from_known = sum(1 for p in packages.values() if p.get("cpe_source") == "known_metadata")

    # New fields statistics
    patched_cves_count = sum(1 for p in packages.values() if p.get("patched_cves"))
    download_url_count = sum(1 for p in packages.values() if p.get("download_url"))
    total_cves_patched = sum(len(p.get("patched_cves", {})) for p in packages.values())

    # Static library statistics
    static_libs_count = sum(1 for p in packages.values() if p.get("static_libs"))
    build_depends_count = sum(1 for p in packages.values() if p.get("build_depends"))
    total_static_libs = sum(len(p.get("static_libs", [])) for p in packages.values())
    known_embedded_count = sum(
        1 for p in packages.values()
        for lib in p.get("static_libs", [])
        if lib.get("source") == "known_embedded"
    )
    detected_static_count = total_static_libs - known_embedded_count

    print(f"\n--- CycloneDX Coverage ---")
    print(f"  Packages with CPE-ID:  {cpe_count} / {len(packages)} ({100*cpe_count/len(packages):.1f}%)")
    print(f"    - From IPK:          {cpe_from_ipk}")
    print(f"    - From Makefile:     {cpe_from_makefile}")
    print(f"    - From KNOWN_METADATA: {cpe_from_known}")
    print(f"  Packages with patches: {patches_count} / {len(packages)} ({100*patches_count/len(packages):.1f}%)")
    print(f"  Packages modified:     {modified_count} / {len(packages)} ({100*modified_count/len(packages):.1f}%)")
    print(f"  Packages with patched CVEs: {patched_cves_count} ({total_cves_patched} unique CVEs)")
    print(f"  Packages with download URL: {download_url_count} / {len(packages)} ({100*download_url_count/len(packages):.1f}%)")
    print(f"  Packages with build deps:   {build_depends_count} / {len(packages)}")
    print(f"  Packages with static libs:  {static_libs_count} ({total_static_libs} total)")
    print(f"    - Known embedded:         {known_embedded_count}")
    print(f"    - Detected (build-only):  {detected_static_count}")
    print(f"  All packages have: type, bom_ref, purl, hashes")

    # Sample output
    print("\n--- Sample Package (with CPE-ID) ---")
    for pkg_name, pkg_data in packages.items():
        if "cpe_id" in pkg_data:
            pprint({k: v for k, v in pkg_data.items() if k != "ipk_file"})
            break

    print("\n--- Sample Package (with patches) ---")
    for pkg_name, pkg_data in packages.items():
        if pkg_data.get("patches") and len(pkg_data["patches"]) >= 2:
            pprint({k: v for k, v in pkg_data.items() if k != "ipk_file"})
            break

    print("\n--- Sample Package (CPE from Makefile) ---")
    for pkg_name, pkg_data in packages.items():
        if pkg_data.get("cpe_source") == "makefile":
            pprint({k: v for k, v in pkg_data.items() if k != "ipk_file"})
            break
    else:
        print("  (none found)")

    print("\n--- Sample Package (CPE from KNOWN_METADATA) ---")
    for pkg_name, pkg_data in packages.items():
        if pkg_data.get("cpe_source") == "known_metadata":
            pprint({k: v for k, v in pkg_data.items() if k != "ipk_file"})
            break
    else:
        print("  (none found)")

    print("\n--- Sample Package (with patched CVEs) ---")
    for pkg_name, pkg_data in packages.items():
        if pkg_data.get("patched_cves"):
            pprint({k: v for k, v in pkg_data.items() if k != "ipk_file"})
            break
    else:
        print("  (none found)")

    print("\n--- Sample Package (with download URL) ---")
    for pkg_name, pkg_data in packages.items():
        if pkg_data.get("download_url"):
            pprint({k: v for k, v in pkg_data.items() if k != "ipk_file"})
            break
    else:
        print("  (none found)")

    print("\n--- Sample Package (with static/embedded libraries) ---")
    for pkg_name, pkg_data in packages.items():
        if pkg_data.get("static_libs"):
            pprint({k: v for k, v in pkg_data.items() if k != "ipk_file"})
            break
    else:
        print("  (none found)")

    print("\n--- All Packages with Static/Embedded Libraries ---")
    for pkg_name, pkg_data in sorted(packages.items()):
        if pkg_data.get("static_libs"):
            static_info = pkg_data["static_libs"]
            libs = [lib["name"] for lib in static_info]
            cpes = [lib.get("cpe_id", "no-cpe") for lib in static_info if lib.get("cpe_id")]
            print(f"  {pkg_name}: {', '.join(libs)}")
            if cpes:
                for cpe in cpes:
                    print(f"    CPE: {cpe}")

    print("\n--- Sample Package (without CPE-ID, no patches) ---")
    for pkg_name, pkg_data in packages.items():
        if "cpe_id" not in pkg_data and not pkg_data.get("patches"):
            pprint({k: v for k, v in pkg_data.items() if k != "ipk_file"})
            break

    # Print Linux kernel metadata
    if "linux-kernel" in packages:
        print("\n--- Linux Kernel Package ---")
        kernel = packages["linux-kernel"]
        # Truncate patches list for display
        display_kernel = kernel.copy()
        if "patches" in display_kernel and len(display_kernel["patches"]) > 5:
            patch_count = len(display_kernel["patches"])
            display_kernel["patches"] = display_kernel["patches"][:5] + [f"... and {patch_count - 5} more patches"]
        pprint(display_kernel, width=100, sort_dicts=False)


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Extract OpenWRT package metadata from IPK files.'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed statistics and sample packages'
    )
    parser.add_argument(
        '--ui',
        action='store_true',
        help='Launch interactive browser after extraction'
    )
    parser.add_argument(
        '--no-filter',
        action='store_true',
        dest='no_filter',
        help='Include all built IPK packages, not just those in firmware image'
    )
    args = parser.parse_args()

    config = load_config(CONFIG_FILE)
    paths  = build_paths(config)

    print_paths(config, paths)

    ipk_files      = find_ipk_files(paths)
    manifest_files = find_manifest_files(paths)

    # Extract metadata from all IPKs
    print("Extracting metadata from IPK files...")
    packages = extract_all_ipk_metadata(ipk_files, paths["build_root"])

    # Extract OpenWRT metadata
    openwrt_data = extract_openwrt_metadata(paths["build_root"])
    packages["openwrt"] = openwrt_data

    # Extract Linux kernel metadata
    print("Extracting Linux kernel metadata...")
    linux_build_dir = find_linux_build_dir(paths["build_root"])
    if linux_build_dir:
        print(f"  Found kernel at: {linux_build_dir}")
        # Find the target packages manifest for kmod extraction
        target_manifest = list(paths["bin_targets"].rglob("packages/Packages.manifest"))
        manifest_path = target_manifest[0] if target_manifest else None

        kernel_data = extract_kernel_metadata(
            linux_build_dir,
            paths["build_root"],
            include_kmods=False,  # Set to True to include kmod components
            packages_manifest=manifest_path
        )
        if kernel_data:
            packages["linux"] = kernel_data
            print(f"  Kernel version: {kernel_data.get('version', 'unknown')}")
            print(f"  Kernel patches: {len(kernel_data.get('patches', []))}")
    else:
        print("  Warning: Linux kernel build directory not found")

    # Filter packages to only those in the firmware image (unless --no-filter)
    image_manifest = find_image_manifest(paths)
    removed_packages = []

    if image_manifest and not args.no_filter:
        print(f"\nFiltering against firmware image manifest...")
        print(f"  Manifest: {image_manifest.name}")
        installed_packages = parse_image_manifest(image_manifest)
        print(f"  Packages in firmware image: {len(installed_packages)}")

        packages, removed_packages = filter_packages_by_manifest(packages, installed_packages)
        print(f"  Packages after filtering: {len(packages)}")

        if removed_packages:
            print(f"  Removed (built but not installed): {len(removed_packages)}")
            if args.verbose:
                for pkg in sorted(removed_packages):
                    print(f"    - {pkg}")
    elif not image_manifest:
        print("\n  Warning: No firmware image manifest found, including all built packages")
    else:
        print("\n  Note: --no-filter specified, including all built packages")

    # Show statistics and samples only in verbose mode
    if args.verbose:
        print_statistics(packages, ipk_files, manifest_files)

    # Sort packages alphabetically by name
    sorted_packages = dict(sorted(packages.items()))

    # Get build system info
    try:
        build_system = subprocess.run(
            ["uname", "-a"],
            capture_output=True,
            text=True
        ).stdout.strip()
    except Exception:
        build_system = "unknown"

    # Build output structure with project metadata
    output = {
        "project_name": config["project_name"],
        "project_release": config.get("project_release", ""),
        "build_system": build_system,
        "extraction_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "image_manifest": str(image_manifest.name) if image_manifest else None,
        "filtered": not args.no_filter and image_manifest is not None,
        "packages_removed": sorted(removed_packages) if removed_packages else [],
        "components": sorted_packages
    }

    # Write extracted data
    output_file = Path("data.json")
    with open(output_file, "w") as json_file:
        json.dump(output, json_file, indent=4)

    print(f"\nExtracted {len(packages)} packages to {output_file}")

    # Launch interactive UI if requested
    if args.ui:
        print("\nLaunching interactive browser...")
        from browse_metadata import browse_metadata
        browse_metadata(output_file)



if __name__ == "__main__":
    main()

    
    
