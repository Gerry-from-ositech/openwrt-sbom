#!/usr/bin/env python3
"""
Linux Kernel Component Scanner

Scans a Linux kernel build directory and identifies compiled components
by detecting directories containing .o object files.

Usage:
    python component_scan.py -r /path/to/linux/build [-o output.json]
    python component_scan.py  -r  /home/gerry/OpenWRT21.02-Z8106/build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_mt7981/linux-5.4.213
"""

import argparse
import json
import os
import sys


def scan_components(source_root):
    """
    Scan the Linux source tree for compiled components.
    Returns dict mapping directory paths to lists of source files.
    
    Post-build: looks for .o files in directories -  What WAS compiled  after full build
    
    """
    results = {}

    exclude_files = ['Kconfig', 'Makefile']
    exclude_file_types = ('.cmd', '.order', '.builtin', '.hardening', '.mod', '.a', '.ko')
    included_file_exts = ('.c', '.h')

    for dirpath, dirnames, filenames in os.walk(source_root):
        rel_dir = dirpath[len(source_root)+1:]

        # Skip documentation
        if 'Documentation' in rel_dir:
            continue
        # Skip host build tools
        if rel_dir == 'scripts' or rel_dir.startswith('scripts/'):
            continue
        # Skip initramfs
        if rel_dir == 'usr' or rel_dir.startswith('usr/'):
            continue

        if not rel_dir:
            continue

        # Check if this dir has any compiled files
        if not any(f.endswith('.o') for f in filenames):
            continue

        # Collect source files
        file_list = []
        for filename in filenames:
            if filename in exclude_files:
                continue
            if filename.endswith(exclude_file_types):
                continue
            ext_idx = filename.rfind('.')
            if ext_idx != -1 and filename[ext_idx:] in included_file_exts:
                file_list.append(filename)

        if file_list:
            results[rel_dir] = sorted(file_list)

    return results


def main():
    parser = argparse.ArgumentParser(
        description='Scan Linux kernel build for compiled components',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -r /path/to/linux/build
  %(prog)s -r /path/to/linux/build -o components.json
  %(prog)s -r /path/to/linux/build --format text
        '''
    )

    parser.add_argument(
        '-r', '--root',
        required=True,
        help='Linux build root directory'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file path (default: stdout)'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'text'],
        default='json',
        help='Output format (default: json)'
    )

    args = parser.parse_args()

    # Validate root directory
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"Error: Directory not found: {root}", file=sys.stderr)
        sys.exit(1)

    # Check for .config to confirm it's a Linux build
    if not os.path.isfile(os.path.join(root, '.config')):
        print(f"Warning: No .config found in {root}", file=sys.stderr)

    # Scan
    results = scan_components(root)

    # Output
    if args.format == 'json':
        output = json.dumps(dict(sorted(results.items())), indent=2)
    else:  # text
        lines = []
        for dir_path, files in sorted(results.items()):
            for f in files:
                lines.append(f"{dir_path}/{f}")
        output = '\n'.join(lines)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output + '\n')
        print(f"Output written to: {args.output}", file=sys.stderr)
        print(f"Directories: {len(results)}, Files: {sum(len(v) for v in results.values())}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
