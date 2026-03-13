#!/usr/bin/env python3
"""
Utility to filter kernel components from data.json and create no_linux_data.json.

Filters out all components with "section": "kernel" or names starting with "kmod-".
"""

import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(
        description='Filter kernel components from OpenWrt metadata'
    )
    parser.add_argument(
        '-i', '--input',
        default='data.json',
        help='Input JSON file (default: data.json)'
    )
    parser.add_argument(
        '-o', '--output',
        default='no_linux_data.json',
        help='Output JSON file (default: no_linux_data.json)'
    )
    args = parser.parse_args()

    # Load input data
    try:
        with open(args.input, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Input file '{args.input}' not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{args.input}': {e}", file=sys.stderr)
        sys.exit(1)

    # Update project name
    data['project_name'] = 'Test1 - No Linux'

    # Filter components
    components = data.get('components', {})
    filtered_components = {}
    filtered_names = []

    for name, component in components.items():
        if component.get('section') == 'kernel' or name.startswith('kmod-'):
            filtered_names.append(name)
        else:
            filtered_components[name] = component

    # Print filtered component names
    if filtered_names:
        print("Filtered components (section: kernel or kmod-*):")
        print("-" * 40)
        for name in sorted(filtered_names):
            print(f"  {name}")
        print()

    # Update components in data
    data['components'] = filtered_components

    # Write output
    with open(args.output, 'w') as f:
        json.dump(data, f, indent=4)

    # Print statistics
    total_filtered = len(filtered_names)
    total_kept = len(filtered_components)
    print("Statistics:")
    print("-" * 40)
    print(f"Total components filtered:     {total_filtered}")
    print(f"Total components not filtered: {total_kept}")
    print(f"Output written to: {args.output}")


if __name__ == '__main__':
    main()
