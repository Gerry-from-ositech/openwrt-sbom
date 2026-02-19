#!/usr/bin/env python3
"""
CVE File Lookup Helper

Provides a unified interface for checking if a file is compiled into
the kernel, regardless of which JSON format is used.

Usage:
    from cve_file_lookup import CVEFileLookup

    # Load from either format
    lookup = CVEFileLookup.load('hybrid_combined.json')
    # or
    lookup = CVEFileLookup.load('cve_triage_full.json')

    # Check if file is compiled
    if lookup.file_exists('fs/ext4/extents.c'):
        print("CVE may apply")

    # Get build info (only available with cve_triage_full.json)
    if lookup.build_info:
        print(f"Kernel: {lookup.build_info['kernel_version']['full']}")
"""

import json
import os
from typing import Dict, List, Optional, Set


class CVEFileLookup:
    """Unified interface for CVE file lookups."""

    def __init__(self):
        self._files: Set[str] = set()
        self._by_directory: Dict[str, List[str]] = {}
        self.build_info: Optional[Dict] = None
        self.file_stats: Optional[Dict] = None

    @classmethod
    def load(cls, json_path: str) -> 'CVEFileLookup':
        """Load from either hybrid_combined.json or cve_triage_full.json format."""
        lookup = cls()

        with open(json_path, 'r') as f:
            data = json.load(f)

        # Detect format and load accordingly
        if 'files' in data:
            # cve_triage format (with or without build_info)
            # 'files' is a list of paths (or dict with {path: true} in old format)
            lookup._load_cve_triage_format(data)
        else:
            # hybrid_combined.json format (directory -> file list)
            lookup._load_combined_format(data)

        return lookup

    def _load_cve_triage_format(self, data: Dict):
        """Load from cve_triage format with flat file paths."""
        # Handle both list format (new) and dict format (old)
        files_data = data['files']
        if isinstance(files_data, list):
            self._files = set(files_data)
        else:
            # Old dict format with {path: true}
            self._files = set(files_data.keys())

        self.build_info = data.get('build_info')
        self.file_stats = data.get('file_stats')

        # Also build directory index for compatibility
        for filepath in self._files:
            dir_path = os.path.dirname(filepath)
            filename = os.path.basename(filepath)
            if dir_path not in self._by_directory:
                self._by_directory[dir_path] = []
            self._by_directory[dir_path].append(filename)

    def _load_combined_format(self, data: Dict):
        """Load from hybrid_combined format (directory -> file list)."""
        self._by_directory = data

        # Build flat file set for efficient lookups
        for dir_path, files in data.items():
            for filename in files:
                self._files.add(f"{dir_path}/{filename}")

    def file_exists(self, filepath: str) -> bool:
        """Check if a file path is compiled into the kernel."""
        # Normalize path (remove leading ./ or /)
        filepath = filepath.lstrip('./')
        return filepath in self._files

    def files_in_directory(self, dir_path: str) -> List[str]:
        """Get all compiled files in a directory."""
        dir_path = dir_path.rstrip('/')
        return self._by_directory.get(dir_path, [])

    def search_files(self, pattern: str) -> List[str]:
        """Search for files matching a pattern (simple substring match)."""
        return [f for f in self._files if pattern in f]

    def get_kernel_version(self) -> Optional[str]:
        """Get kernel version if available."""
        if self.build_info:
            return self.build_info.get('kernel_version', {}).get('full')
        return None

    def is_subsystem_enabled(self, subsystem: str) -> Optional[bool]:
        """Check if a subsystem is enabled (requires cve_triage format)."""
        if self.build_info:
            return self.build_info.get('subsystems', {}).get(subsystem)
        return None

    def get_architecture(self) -> Optional[str]:
        """Get architecture if available."""
        if self.build_info:
            return self.build_info.get('architecture', {}).get('arch')
        return None

    @property
    def total_files(self) -> int:
        """Total number of compiled files."""
        return len(self._files)


def check_cve_applicability(lookup: CVEFileLookup,
                            files: List[str] = None,
                            subsystem: str = None,
                            arch: str = None) -> dict:
    """
    Check if a CVE is potentially applicable.

    Args:
        lookup: CVEFileLookup instance
        files: List of file paths mentioned in CVE
        subsystem: Subsystem name (e.g., 'bluetooth', 'netfilter')
        arch: Architecture requirement (e.g., 'x86', 'arm64')

    Returns:
        dict with 'applicable' bool and 'reasons' list
    """
    result = {'applicable': True, 'reasons': []}

    # Check architecture
    if arch and lookup.get_architecture():
        if lookup.get_architecture() != arch:
            result['applicable'] = False
            result['reasons'].append(f"Architecture mismatch: {arch} vs {lookup.get_architecture()}")

    # Check subsystem
    if subsystem:
        enabled = lookup.is_subsystem_enabled(subsystem)
        if enabled is False:
            result['applicable'] = False
            result['reasons'].append(f"Subsystem '{subsystem}' not enabled")

    # Check files
    if files:
        found_files = [f for f in files if lookup.file_exists(f)]
        if not found_files:
            result['applicable'] = False
            result['reasons'].append(f"No affected files compiled: {files}")
        else:
            result['found_files'] = found_files

    return result


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cve_file_lookup.py <json_file> [file_path_to_check]")
        sys.exit(1)

    json_file = sys.argv[1]
    lookup = CVEFileLookup.load(json_file)

    print(f"Loaded {lookup.total_files} files")

    if lookup.build_info:
        print(f"Kernel: {lookup.get_kernel_version()}")
        print(f"Architecture: {lookup.get_architecture()}")

    if len(sys.argv) > 2:
        filepath = sys.argv[2]
        exists = lookup.file_exists(filepath)
        print(f"\nFile '{filepath}': {'EXISTS' if exists else 'NOT FOUND'}")
