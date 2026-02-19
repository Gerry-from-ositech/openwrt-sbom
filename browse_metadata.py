#!/usr/bin/env python3
"""
browse_metadata.py - Interactive browser for OpenWRT metadata.

Can be run standalone:
    python3 browse_metadata.py data.json

Or called from metadata_extractor.py with --ui flag.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path
from pprint import pprint
from typing import Optional


def load_data(data_path: Path) -> dict:
    """Load metadata from JSON file."""
    with open(data_path, 'r') as f:
        data = json.load(f)

    # Handle both new format (with components key) and old format
    if "components" in data:
        return data
    else:
        return {"components": data}


def get_composite_groups(components: dict) -> dict[str, list[str]]:
    """
    Identify composite groups by shared CPE ID or source path.

    Returns: {group_name: [member_names]}
    """
    # Group by CPE ID
    cpe_groups = defaultdict(list)
    for name, pkg in components.items():
        cpe_id = pkg.get('cpe_id')
        if cpe_id:
            # Normalize CPE by removing version
            parts = cpe_id.split(':')
            if len(parts) >= 6:
                parts[5] = '*'
            normalized_cpe = ':'.join(parts)
            cpe_groups[normalized_cpe].append(name)

    # Group by source path
    source_groups = defaultdict(list)
    for name, pkg in components.items():
        source = pkg.get('source')
        if source:
            source_groups[source].append(name)

    # Merge groups (prefer CPE-based)
    composite_groups = {}

    # Start with CPE groups that have 2+ members
    for cpe, members in cpe_groups.items():
        if len(members) >= 2:
            # Use shortest non-lib name as group name
            candidates = [m for m in members if not m.startswith('lib') and '-mod-' not in m]
            if not candidates:
                candidates = members
            candidates.sort(key=lambda x: (len(x), x))
            group_name = candidates[0]
            composite_groups[group_name] = sorted(members)

    # Add source groups for packages not in CPE groups
    packages_in_cpe_groups = set()
    for members in composite_groups.values():
        packages_in_cpe_groups.update(members)

    for source, members in source_groups.items():
        if len(members) >= 2:
            # Check if any member is already in a CPE group
            if not any(m in packages_in_cpe_groups for m in members):
                candidates = [m for m in members if not m.startswith('lib') and '-mod-' not in m]
                if not candidates:
                    candidates = members
                candidates.sort(key=lambda x: (len(x), x))
                group_name = candidates[0]
                composite_groups[group_name] = sorted(members)

    return composite_groups


def cmd_show_totals(data: dict) -> None:
    """Command 1: Show totals."""
    components = data.get("components", {})
    composite_groups = get_composite_groups(components)

    # Count packages with CPE
    packages_with_cpe = sum(1 for pkg in components.values() if pkg.get('cpe_id'))

    # Get unique CPEs
    unique_cpes = set()
    for pkg in components.values():
        cpe = pkg.get('cpe_id')
        if cpe:
            unique_cpes.add(cpe)

    print("\n" + "=" * 60)
    print("TOTALS")
    print("=" * 60)
    print(f"Total components:        {len(components)}")
    print(f"Components with CPE:     {packages_with_cpe}")
    print(f"Unique CPE IDs:          {len(unique_cpes)}")
    print(f"Composite groups:        {len(composite_groups)}")

    print("\n--- Composite Groups ---")
    # Sort by member count descending
    sorted_groups = sorted(composite_groups.items(), key=lambda x: -len(x[1]))
    for group_name, members in sorted_groups:
        print(f"  {group_name}: {len(members)} members")


def cmd_show_composites(data: dict) -> None:
    """Command 2: Show all composite components."""
    components = data.get("components", {})
    composite_groups = get_composite_groups(components)

    print("\n" + "=" * 60)
    print("COMPOSITE COMPONENTS")
    print("=" * 60)

    # Sort groups alphabetically
    for group_name in sorted(composite_groups.keys()):
        members = composite_groups[group_name]

        # Get common CPE and license from group
        cpes = set()
        licenses = set()
        for member in members:
            pkg = components.get(member, {})
            if pkg.get('cpe_id'):
                cpes.add(pkg['cpe_id'])
            if pkg.get('license'):
                licenses.add(pkg['license'])

        print(f"\n{group_name} ({len(members)} members)")
        print(f"  CPE: {', '.join(sorted(cpes)) if cpes else 'none'}")
        print(f"  License: {', '.join(sorted(licenses)) if licenses else 'none'}")
        print(f"  Members: {', '.join(sorted(members))}")


def cmd_search(data: dict) -> None:
    """Command 3: Search mode."""
    components = data.get("components", {})

    print("\n" + "=" * 60)
    print("SEARCH MODE")
    print("=" * 60)
    print("Commands:")
    print("  pkgname name1,name2,...  - Show metadata for named packages")
    print("  key value [key value...] - Find packages matching key=value pairs")
    print("  q                        - Return to main menu")
    print()

    while True:
        try:
            user_input = input("search>>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not user_input:
            continue

        if user_input.lower() == 'q':
            break

        parts = user_input.split()
        if not parts:
            continue

        if parts[0].lower() == 'pkgname':
            # pkgname name1,name2,...
            if len(parts) < 2:
                print("Usage: pkgname name1,name2,...")
                continue

            # Join remaining parts and split by comma
            names_str = ' '.join(parts[1:])
            names = [n.strip() for n in names_str.split(',')]

            found = []
            not_found = []
            for name in names:
                if name in components:
                    found.append(name)
                else:
                    not_found.append(name)

            if not_found:
                print(f"Not found: {', '.join(not_found)}")

            # Display found packages in alpha order
            for name in sorted(found):
                print(f"\n--- {name} ---")
                pkg = components[name]
                # Exclude ipk_file for cleaner output
                display_pkg = {k: v for k, v in pkg.items() if k != 'ipk_file'}
                pprint(display_pkg, width=100)

        else:
            # key value [key value ...] search
            if len(parts) < 2 or len(parts) % 2 != 0:
                print("Usage: key1 value1 [key2 value2 ...]")
                print("Example: license GPL-2.0")
                print("Example: section net type application")
                continue

            # Parse key-value pairs
            search_criteria = {}
            for i in range(0, len(parts), 2):
                key = parts[i]
                value = parts[i + 1]
                search_criteria[key] = value

            # Find matching packages
            matches = []
            for name, pkg in components.items():
                match = True
                for key, value in search_criteria.items():
                    pkg_value = pkg.get(key)
                    if pkg_value is None:
                        match = False
                        break
                    # Handle list values (like depends)
                    if isinstance(pkg_value, list):
                        if value not in pkg_value:
                            match = False
                            break
                    else:
                        # Case-insensitive string comparison
                        if str(pkg_value).lower() != value.lower():
                            match = False
                            break
                if match:
                    matches.append(name)

            if not matches:
                print(f"No packages found matching: {search_criteria}")
            else:
                print(f"\nFound {len(matches)} packages:")
                for name in sorted(matches):
                    pkg = components[name]
                    version = pkg.get('version', '')
                    cpe = pkg.get('cpe_id', 'no CPE')
                    print(f"  {name} {version} - {cpe}")


def show_menu() -> None:
    """Display the main menu."""
    print("\n" + "=" * 60)
    print("METADATA BROWSER")
    print("=" * 60)
    print("Enter the number of the command to execute or 'q' to quit.")
    print()
    print("1. Show Totals")
    print("2. Show all composite components")
    print("3. Search")
    print()


def browse_metadata(data_path: Path) -> None:
    """Main interactive browser loop."""
    if not data_path.exists():
        print(f"Error: File not found: {data_path}")
        return

    data = load_data(data_path)
    project_name = data.get("project_name", "Unknown Project")

    print(f"\nLoaded: {data_path}")
    print(f"Project: {project_name}")
    print(f"Components: {len(data.get('components', {}))}")

    while True:
        show_menu()

        try:
            user_input = input(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            break

        if not user_input:
            continue

        if user_input.lower() == 'q':
            print("Exiting...")
            break

        if user_input == '1':
            cmd_show_totals(data)
        elif user_input == '2':
            cmd_show_composites(data)
        elif user_input == '3':
            cmd_search(data)
        else:
            print(f"Unknown command: {user_input}")


def main():
    """Entry point for standalone execution."""
    if len(sys.argv) < 2:
        print("Usage: python3 browse_metadata.py <data.json>")
        print("       python3 browse_metadata.py data.json")
        sys.exit(1)

    data_path = Path(sys.argv[1])
    browse_metadata(data_path)


if __name__ == '__main__':
    main()
