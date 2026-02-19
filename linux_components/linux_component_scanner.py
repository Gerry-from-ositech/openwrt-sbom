#!/usr/bin/env python3
"""
Linux Kernel Component Scanner

Scans a Linux kernel build directory and identifies which source files
will be compiled based on .config CONFIG_* directives by parsing Makefiles.

Usage:
    python linux_component_scanner.py -r /path/to/linux/build [-o output.json]
    
    Pre-build: parses Makefiles and .config  What SHOULD be compiled
    
    python linux_component_scanner.py -r  /home/gerry/OpenWRT21.02-Z8106/build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_mt7981/linux-5.4.213
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple


class ConfigParser:
    """Parses Linux kernel .config files."""

    def parse(self, config_path: str) -> Dict[str, str]:
        """
        Parse .config file and extract enabled CONFIG_ options.

        Returns dict mapping config name to value ('y', 'm', or string value).
        """
        config = {}
        config_pattern = re.compile(r'^(CONFIG_\w+)=(.+)$')

        with open(config_path, 'r') as f:
            for line in f:
                line = line.strip()
                match = config_pattern.match(line)
                if match:
                    name, value = match.groups()
                    # Remove quotes from string values
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    config[name] = value

        return config


class MakefileParser:
    """Parses Linux kernel Makefiles to extract build targets."""

    def __init__(self, config: Dict[str, str], verbose: bool = False):
        self.config = config
        self.verbose = verbose
        # Cache for module definitions (e.g., ext4-y := file1.o file2.o)
        self.module_defs: Dict[str, List[str]] = {}

    def _expand_config_var(self, var: str) -> str:
        """
        Expand $(CONFIG_XXX) or $(subst m,y,$(CONFIG_XXX)) to its value.
        """
        # Handle $(subst m,y,$(CONFIG_XXX)) pattern - treat as enabled if config is y or m
        subst_match = re.match(r'\$\(subst\s+m,y,\$\((CONFIG_\w+)\)\)', var)
        if subst_match:
            config_name = subst_match.group(1)
            value = self.config.get(config_name, '')
            # subst m,y means: if m, return y; otherwise return as-is
            return 'y' if value in ('y', 'm') else ''

        # Handle simple $(CONFIG_XXX) pattern
        match = re.match(r'\$\((CONFIG_\w+)\)', var)
        if match:
            config_name = match.group(1)
            return self.config.get(config_name, '')
        return var

    def _join_continued_lines(self, lines: List[str]) -> List[str]:
        """Join lines that end with backslash continuation."""
        result = []
        current = ''

        for line in lines:
            # Remove comments
            comment_idx = line.find('#')
            if comment_idx >= 0:
                line = line[:comment_idx]

            line = line.rstrip()

            if line.endswith('\\'):
                current += line[:-1] + ' '
            else:
                current += line
                if current.strip():
                    result.append(current)
                current = ''

        if current.strip():
            result.append(current)

        return result

    def _parse_targets(self, value: str) -> List[str]:
        """Parse space-separated targets from a Makefile line."""
        # Split on whitespace, filter empty
        targets = [t.strip() for t in value.split() if t.strip()]
        return targets

    def parse(self, makefile_path: str) -> Tuple[List[str], List[str]]:
        """
        Parse a Makefile and return:
        - List of .o files to build
        - List of subdirectories to recurse into

        Uses two-pass approach: first collect module definitions, then process obj- lines.
        """
        objects = []
        subdirs = []

        if not os.path.exists(makefile_path):
            return objects, subdirs

        with open(makefile_path, 'r') as f:
            lines = f.readlines()

        # Join continued lines
        lines = self._join_continued_lines(lines)

        # Patterns for different Makefile constructs
        # obj-y += file.o  or  obj-$(CONFIG_XXX) += file.o  or  obj-$(subst m,y,$(CONFIG_XXX)) += file.o
        obj_pattern = re.compile(r'^obj-(\$\(subst\s+m,y,\$\(CONFIG_\w+\)\)|\$\(CONFIG_\w+\)|y|m)\s*[+:]?=\s*(.+)$')

        # module-y := file1.o file2.o  or  module-$(CONFIG_XXX) += file.o  or  module-objs += file.o
        # Also handles module-objs-y and module-objs-$(CONFIG_XXX) patterns
        module_def_pattern = re.compile(r'^(\w[\w-]*?)(?:-objs)?-(\$\(CONFIG_\w+\)|y|m)\s*[+:]?=\s*(.+)$')
        # Separate pattern for simple -objs assignment
        module_objs_pattern = re.compile(r'^(\w[\w-]*)-objs\s*[+:]?=\s*(.+)$')

        # PASS 1: Collect all module definitions first
        for line in lines:
            line = line.strip()

            # Try the main module definition pattern (module-y, module-objs-y, etc.)
            module_match = module_def_pattern.match(line)
            if module_match:
                module_name, condition, targets_str = module_match.groups()

                # Skip obj- prefix (handled in pass 2)
                if module_name == 'obj':
                    continue

                # Evaluate condition
                if condition in ('y', 'm'):
                    enabled = True
                else:
                    value = self._expand_config_var(condition)
                    enabled = value in ('y', 'm')

                if enabled:
                    targets = self._parse_targets(targets_str)
                    if module_name not in self.module_defs:
                        self.module_defs[module_name] = []
                    self.module_defs[module_name].extend(
                        [t for t in targets if t.endswith('.o')]
                    )
                continue

            # Try simple -objs pattern (module-objs := ...)
            objs_match = module_objs_pattern.match(line)
            if objs_match:
                module_name, targets_str = objs_match.groups()
                if module_name == 'obj':
                    continue
                targets = self._parse_targets(targets_str)
                if module_name not in self.module_defs:
                    self.module_defs[module_name] = []
                self.module_defs[module_name].extend(
                    [t for t in targets if t.endswith('.o')]
                )

        # PASS 2: Process obj- lines and expand module references
        for line in lines:
            line = line.strip()

            # Check for obj-y or obj-$(CONFIG_XXX) patterns
            obj_match = obj_pattern.match(line)
            if obj_match:
                condition, targets_str = obj_match.groups()

                # Evaluate condition
                if condition == 'y' or condition == 'm':
                    enabled = True
                else:
                    value = self._expand_config_var(condition)
                    enabled = value in ('y', 'm')

                if enabled:
                    targets = self._parse_targets(targets_str)
                    for target in targets:
                        if target.endswith('/'):
                            subdirs.append(target.rstrip('/'))
                        elif target.endswith('.o'):
                            # Check if this is a module reference
                            module_name = target[:-2]  # Remove .o
                            if module_name in self.module_defs:
                                objects.extend(self.module_defs[module_name])
                            else:
                                objects.append(target)

        return objects, subdirs


class ComponentScanner:
    """Scans Linux kernel source tree for components to build."""

    # Top-level kernel directories to scan
    KERNEL_DIRS = [
        'arch', 'block', 'certs', 'crypto', 'drivers', 'fs', 'init',
        'ipc', 'kernel', 'lib', 'mm', 'net', 'security', 'sound', 'virt'
    ]

    # Architecture subdirectories that use core-y/libs-y patterns
    ARCH_SUBDIRS = ['kernel', 'mm', 'lib', 'crypto', 'net']

    def __init__(self, root: str, config: Dict[str, str], verbose: bool = False,
                 include_headers: bool = True):
        self.root = Path(root)
        self.config = config
        self.verbose = verbose
        self.include_headers = include_headers
        self.parser = MakefileParser(config, verbose)

    def _object_to_source(self, obj_file: str, directory: Path) -> List[str]:
        """
        Convert .o filename to corresponding source file(s).
        Returns list of source files that exist.
        """
        sources = []
        base = obj_file[:-2]  # Remove .o extension

        # Try common source extensions
        for ext in ['.c', '.S', '.s']:
            src_path = directory / (base + ext)
            if src_path.exists():
                sources.append(base + ext)
                break

        return sources

    def _get_headers_in_dir(self, directory: Path) -> List[str]:
        """Get all .h header files in a directory."""
        headers = []
        if directory.exists():
            for f in directory.iterdir():
                if f.is_file() and f.suffix == '.h':
                    headers.append(f.name)
        return headers

    def _scan_directory(self, rel_dir: str, visited: Set[str]) -> Dict[str, List[str]]:
        """
        Recursively scan a directory for components.
        Returns dict mapping relative paths to source files.
        """
        results = {}

        if rel_dir in visited:
            return results
        visited.add(rel_dir)

        abs_dir = self.root / rel_dir
        makefile = abs_dir / 'Makefile'

        if not makefile.exists():
            # Try Kbuild file as alternative
            makefile = abs_dir / 'Kbuild'

        if not makefile.exists():
            return results

        if self.verbose:
            print(f"Parsing: {rel_dir}/Makefile", file=sys.stderr)

        # Reset module definitions for each Makefile
        self.parser.module_defs = {}

        objects, subdirs = self.parser.parse(str(makefile))

        # Convert objects to source files
        sources = []
        for obj in objects:
            src_files = self._object_to_source(obj, abs_dir)
            sources.extend(src_files)

        # Include header files if option enabled and we found source files
        if sources and self.include_headers:
            headers = self._get_headers_in_dir(abs_dir)
            sources.extend(headers)

        if sources:
            results[rel_dir] = sorted(set(sources))

        # Recurse into subdirectories
        for subdir in subdirs:
            sub_rel = f"{rel_dir}/{subdir}"
            sub_results = self._scan_directory(sub_rel, visited)
            results.update(sub_results)

        return results

    def _scan_arch_directory(self, arch: str, visited: Set[str]) -> Dict[str, List[str]]:
        """
        Special handling for architecture directories.
        arch/ uses core-y, libs-y patterns instead of obj-y.
        """
        results = {}
        arch_base = f"arch/{arch}"

        # Scan the arch top-level Makefile for direct objects
        sub_results = self._scan_directory(arch_base, visited)
        results.update(sub_results)

        # Directly scan known arch subdirectories
        for subdir in self.ARCH_SUBDIRS:
            subdir_path = f"{arch_base}/{subdir}"
            if (self.root / subdir_path).exists():
                sub_results = self._scan_directory(subdir_path, visited)
                results.update(sub_results)

        # Also check for vdso subdirectory within kernel
        vdso_path = f"{arch_base}/kernel/vdso"
        if (self.root / vdso_path).exists():
            sub_results = self._scan_directory(vdso_path, visited)
            results.update(sub_results)

        return results

    def scan(self) -> Dict[str, List[str]]:
        """
        Scan the kernel source tree and return components to build.
        Returns dict mapping relative directory paths to source files.
        """
        results = {}
        visited: Set[str] = set()

        # Determine architecture from config
        arch = None
        for key in self.config:
            if key.startswith('CONFIG_ARCH_'):
                arch = key.replace('CONFIG_ARCH_', '').lower()
                break

        # For ARM64, use arm64 directory
        if self.config.get('CONFIG_ARM64') == 'y':
            arch = 'arm64'

        for top_dir in self.KERNEL_DIRS:
            top_path = self.root / top_dir
            if not top_path.exists():
                continue

            # Special handling for arch directory
            if top_dir == 'arch' and arch:
                sub_results = self._scan_arch_directory(arch, visited)
                results.update(sub_results)
            else:
                sub_results = self._scan_directory(top_dir, visited)
                results.update(sub_results)

        return results


def output_json(results: Dict[str, List[str]], output_file=None):
    """Output results as JSON."""
    # Sort by directory path
    sorted_results = dict(sorted(results.items()))

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(sorted_results, f, indent=2)
    else:
        print(json.dumps(sorted_results, indent=2))


def output_text(results: Dict[str, List[str]], output_file=None):
    """Output results as text listing."""
    lines = []
    for dir_path, files in sorted(results.items()):
        for f in sorted(files):
            lines.append(f"{dir_path}/{f}")

    output = '\n'.join(lines)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(output + '\n')
    else:
        print(output)


def output_csv(results: Dict[str, List[str]], output_file=None):
    """Output results as CSV."""
    lines = ['directory,filename']
    for dir_path, files in sorted(results.items()):
        for f in sorted(files):
            lines.append(f'"{dir_path}","{f}"')

    output = '\n'.join(lines)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(output + '\n')
    else:
        print(output)


def main():
    parser = argparse.ArgumentParser(
        description='Scan Linux kernel build for components based on .config directives',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  %(prog)s -r /path/to/linux/build -o components.json
  %(prog)s -r /path/to/linux/build --format text
        '''
    )

    parser.add_argument(
        '-r', '--root',
        default='.',
        help='Linux build root directory (default: current directory)'
    )
    parser.add_argument(
        '-c', '--config',
        help='Path to .config file (default: ROOT/.config)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file path (default: stdout)'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'text', 'csv'],
        default='json',
        help='Output format (default: json)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed parsing information'
    )
    parser.add_argument(
        '--no-headers',
        action='store_true',
        help='Exclude .h header files from output (default: include headers)'
    )

    args = parser.parse_args()

    # Resolve paths
    root = os.path.abspath(args.root)
    config_path = args.config or os.path.join(root, '.config')

    # Validate paths
    if not os.path.isdir(root):
        print(f"Error: Root directory not found: {root}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(config_path):
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"Root: {root}", file=sys.stderr)
        print(f"Config: {config_path}", file=sys.stderr)

    # Parse config
    config_parser = ConfigParser()
    config = config_parser.parse(config_path)

    if args.verbose:
        enabled_y = sum(1 for v in config.values() if v == 'y')
        enabled_m = sum(1 for v in config.values() if v == 'm')
        print(f"Enabled configs: {enabled_y} built-in, {enabled_m} modules", file=sys.stderr)

    # Scan for components
    include_headers = not args.no_headers
    scanner = ComponentScanner(root, config, args.verbose, include_headers)
    results = scanner.scan()

    if args.verbose:
        total_dirs = len(results)
        total_files = sum(len(files) for files in results.values())
        print(f"Found: {total_dirs} directories, {total_files} source files", file=sys.stderr)

    # Output results
    if args.format == 'json':
        output_json(results, args.output)
    elif args.format == 'text':
        output_text(results, args.output)
    elif args.format == 'csv':
        output_csv(results, args.output)

    if args.output and args.verbose:
        print(f"Output written to: {args.output}", file=sys.stderr)


if __name__ == '__main__':
    main()
