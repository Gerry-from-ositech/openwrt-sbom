#!/usr/bin/env python3
"""
CycloneDX SBOM Browser - Interactive CLI utility for browsing CycloneDX v1.6 SBOMs.
"""

import argparse
import json
import pprint
import readline
import sys


class SBOMBrowser:
    def __init__(self, sbom_file):
        self.sbom_file = sbom_file
        self.sbom = None
        self.components = {}
        self.load_sbom()

    def load_sbom(self):
        """Load and index the SBOM file."""
        try:
            with open(self.sbom_file, 'r') as f:
                self.sbom = json.load(f)
        except FileNotFoundError:
            print(f"Error: File '{self.sbom_file}' not found", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in '{self.sbom_file}': {e}", file=sys.stderr)
            sys.exit(1)

        # Index components by name
        for component in self.sbom.get('components', []):
            name = component.get('name')
            if name:
                self.components[name] = component

        print(f"Loaded SBOM: {self.sbom_file}")
        print(f"Components: {len(self.components)}")
        print(f"Spec Version: {self.sbom.get('specVersion', 'unknown')}")
        print()

    def get_field_value(self, component, field_name):
        """Get a field value from a component, including nested properties."""
        # Direct field access
        if field_name in component:
            value = component[field_name]
            if isinstance(value, list):
                if field_name == 'hashes':
                    return ', '.join(f"{h.get('alg')}:{h.get('content', '')[:16]}..." for h in value)
                elif field_name == 'licenses':
                    return ', '.join(
                        lic.get('expression', lic.get('license', {}).get('id', 'unknown'))
                        for lic in value
                    )
                elif field_name == 'externalReferences':
                    return ', '.join(ref.get('url', '') for ref in value)
                return str(value)
            return str(value)

        # Check in properties (openwrt:* fields)
        for prop in component.get('properties', []):
            if prop.get('name') == field_name:
                return prop.get('value', '')

        return ''

    def cmd_list_full(self, pkg_name):
        """Show full component structure for a package."""
        if pkg_name not in self.components:
            print(f"Package '{pkg_name}' not found")
            # Suggest similar names
            matches = [n for n in self.components if pkg_name.lower() in n.lower()]
            if matches:
                print(f"Did you mean: {', '.join(sorted(matches)[:5])}")
            return

        print(f"\nComponent: {pkg_name}")
        print("=" * 60)
        pprint.pprint(self.components[pkg_name], width=100)
        print()

    def cmd_list_all_full(self):
        """Show full component structure for all packages."""
        sorted_names = sorted(self.components.keys(), key=str.lower)
        for name in sorted_names:
            print(f"\nComponent: {name}")
            print("=" * 60)
            pprint.pprint(self.components[name], width=100)
        print(f"\nTotal: {len(sorted_names)} packages")

    def cmd_list_all_fields(self, fields):
        """List all packages with specified fields."""
        sorted_names = sorted(self.components.keys(), key=str.lower)

        # Calculate column widths
        name_width = max(len(n) for n in sorted_names)
        header = f"{'Package':<{name_width}}"
        for field in fields:
            header += f"  {field}"
        print(header)
        print("-" * len(header))

        for name in sorted_names:
            component = self.components[name]
            line = f"{name:<{name_width}}"
            for field in fields:
                value = self.get_field_value(component, field)
                line += f"  {value}"
            print(line)

        print(f"\nTotal: {len(sorted_names)} packages")

    def cmd_list_pkgnames(self, fields=None):
        """List all package names alphabetically with optional fields."""
        sorted_names = sorted(self.components.keys(), key=str.lower)

        if fields:
            # Calculate column widths
            name_width = max(len(n) for n in sorted_names)
            header = f"{'Package':<{name_width}}"
            for field in fields:
                header += f"  {field}"
            print(header)
            print("-" * len(header))

            for name in sorted_names:
                component = self.components[name]
                line = f"{name:<{name_width}}"
                for field in fields:
                    value = self.get_field_value(component, field)
                    line += f"  {value}"
                print(line)
        else:
            for name in sorted_names:
                print(name)

        print(f"\nTotal: {len(sorted_names)} packages")

    def cmd_help(self):
        """Show help message."""
        print("""
SBOM Browser Commands:
----------------------
  list <pkgname> full           Show full CycloneDX component structure (pprint)
  list * full                   Show full structure for ALL packages
  list * field1,field2,...      List ALL packages with specified fields
  list pkgnames [field1,field2] List sorted package names with optional fields

  info                          Show SBOM metadata info
  search <pattern>              Search package names containing pattern
  fields                        List common CycloneDX fields

  help, h, ?                    Show this help
  quit, q                       Exit the browser

Field Examples:
  list pkgnames version,cpe
  list * version,cpe
  list * openwrt:source_component,openwrt:patched_cves
  list pkgnames type,openwrt:source_component
""")

    def cmd_info(self):
        """Show SBOM metadata."""
        print("\nSBOM Information:")
        print("=" * 60)
        print(f"  File: {self.sbom_file}")
        print(f"  Format: {self.sbom.get('bomFormat', 'unknown')}")
        print(f"  Spec Version: {self.sbom.get('specVersion', 'unknown')}")
        print(f"  Serial Number: {self.sbom.get('serialNumber', 'unknown')}")
        print(f"  Version: {self.sbom.get('version', 'unknown')}")
        print(f"  Components: {len(self.components)}")
        print(f"  Dependencies: {len(self.sbom.get('dependencies', []))}")

        metadata = self.sbom.get('metadata', {})
        if metadata:
            print("\nMetadata:")
            if 'timestamp' in metadata:
                print(f"  Timestamp: {metadata['timestamp']}")
            if 'component' in metadata:
                mc = metadata['component']
                print(f"  Subject: {mc.get('name', 'unknown')} v{mc.get('version', 'unknown')}")
        print()

    def cmd_search(self, pattern):
        """Search for packages matching pattern."""
        matches = [n for n in self.components if pattern.lower() in n.lower()]
        if matches:
            for name in sorted(matches, key=str.lower):
                print(name)
            print(f"\nFound: {len(matches)} packages")
        else:
            print(f"No packages matching '{pattern}'")

    def cmd_fields(self):
        """List common CycloneDX fields."""
        print("""
Common CycloneDX Fields:
------------------------
  name                    Package name
  version                 Package version
  type                    Component type (application, library, etc.)
  cpe                     CPE identifier
  purl                    Package URL
  bom-ref                 BOM reference ID
  description             Package description
  licenses                License information
  hashes                  File hashes
  externalReferences      External URLs

OpenWrt Properties (use full name):
-----------------------------------
  openwrt:release              OpenWrt release version (e.g., 21.02)
  openwrt:depends              Runtime dependencies
  openwrt:source_component     Parent source package
  openwrt:source_path          Source directory path
  openwrt:version_upstream     Upstream version
  openwrt:release_designation  Package rebuild number
  openwrt:role                 Component role (primary/artifact)
  openwrt:artifact_count       Number of binary artifacts
  openwrt:patches              Applied patches
  openwrt:patched_cves         CVEs fixed by patches
  openwrt:static_libs          Statically linked libraries
""")

    def parse_command(self, cmd_line):
        """Parse and execute a command."""
        parts = cmd_line.strip().split()
        if not parts:
            return True

        cmd = parts[0].lower()

        if cmd in ('q', 'quit', 'exit'):
            return False

        if cmd in ('h', 'help', '?'):
            self.cmd_help()
            return True

        if cmd == 'info':
            self.cmd_info()
            return True

        if cmd == 'fields':
            self.cmd_fields()
            return True

        if cmd == 'search' and len(parts) >= 2:
            self.cmd_search(parts[1])
            return True

        if cmd == 'list':
            if len(parts) >= 2 and parts[1] == '*':
                # list * full | list * [field1,field2,...]
                if len(parts) >= 3 and parts[2].lower() == 'full':
                    self.cmd_list_all_full()
                elif len(parts) >= 3:
                    fields = [f.strip() for f in parts[2].split(',')]
                    self.cmd_list_all_fields(fields)
                else:
                    print("Usage: list * full | list * field1,field2,...")
            elif len(parts) >= 3 and parts[2].lower() == 'full':
                # list <pkgname> full
                self.cmd_list_full(parts[1])
            elif len(parts) >= 2 and parts[1].lower() == 'pkgnames':
                # list pkgnames [field1,field2,...]
                fields = None
                if len(parts) >= 3:
                    fields = [f.strip() for f in parts[2].split(',')]
                self.cmd_list_pkgnames(fields)
            elif len(parts) == 2:
                # list <pkgname> - treat as shorthand for list <pkgname> full
                self.cmd_list_full(parts[1])
            else:
                print("Usage: list <pkgname> full | list pkgnames [field1,field2,...] | list * full | list * field1,field2,...")
            return True

        print(f"Unknown command: {cmd}. Type 'help' for available commands.")
        return True

    def run(self):
        """Run the interactive command loop."""
        self.cmd_help()
        while True:
            try:
                cmd_line = input("> ").strip()
                if not self.parse_command(cmd_line):
                    print("Goodbye!")
                    break
            except KeyboardInterrupt:
                print("\nUse 'q' to quit")
            except EOFError:
                print("\nGoodbye!")
                break


def main():
    parser = argparse.ArgumentParser(
        description='Interactive CycloneDX SBOM Browser'
    )
    parser.add_argument(
        'sbom_file',
        nargs='?',
        default='ExplorerII-OpenWRT21.02-Z8106_SBOM.json',
        help='CycloneDX SBOM JSON file (default: ExplorerII-OpenWRT21.02-Z8106_SBOM.json)'
    )
    args = parser.parse_args()

    browser = SBOMBrowser(args.sbom_file)
    browser.run()


if __name__ == '__main__':
    main()
