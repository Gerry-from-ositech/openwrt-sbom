#!/usr/bin/env python3
"""
Hybrid Linux Kernel Component Scanner

Combines two approaches for maximum accuracy:
1. Makefile parsing - determines what SHOULD be compiled based on .config
2. Object file detection - confirms what WAS actually compiled

Reports discrepancies between configured and built components.

Usage:
    python hybrid_scan_linux_components.py -r /path/to/linux/build [-o output.json]
    python hybrid_scan_linux_components.py -r /path/to/linux/build --format text
    python hybrid_scan_linux_components.py -r /path/to/linux/build --report discrepancies
    
   To create hybrid_combined.json that can be used as is for vms linux component lookup
   python hybrid_scan_linux_components.py -r  /home/gerry/OpenWRT21.02-Z8106/build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_mt7981/linux-5.4.213 --report combined option
   

   
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class ScanResult:
    """Results from the hybrid scan."""
    # Files that are both configured and compiled (includes headers if enabled)
    confirmed: Dict[str, List[str]] = field(default_factory=dict)
    # Files configured in Makefile but no .o found
    configured_not_built: Dict[str, List[str]] = field(default_factory=dict)
    # Files with .o but not found in Makefile parsing (includes headers if enabled)
    built_not_configured: Dict[str, List[str]] = field(default_factory=dict)

    def total_confirmed(self) -> int:
        return sum(len(files) for files in self.confirmed.values())

    def total_source_files(self) -> int:
        """Count only .c and .S files (not headers)."""
        count = 0
        for files in self.confirmed.values():
            count += sum(1 for f in files if f.endswith(('.c', '.S', '.s')))
        return count

    def total_header_files(self) -> int:
        """Count only .h files."""
        count = 0
        for files in self.confirmed.values():
            count += sum(1 for f in files if f.endswith('.h'))
        for files in self.built_not_configured.values():
            count += sum(1 for f in files if f.endswith('.h'))
        return count

    def total_discrepancies(self) -> int:
        return (sum(len(files) for files in self.configured_not_built.values()) +
                sum(1 for files in self.built_not_configured.values()
                    for f in files if f.endswith(('.c', '.S', '.s'))))


class BuildMetadataExtractor:
    """Extracts build metadata useful for CVE triage."""

    def __init__(self, root: str, config: Dict[str, str]):
        self.root = Path(root)
        self.config = config

    def extract(self) -> Dict:
        """Extract all relevant build metadata."""
        return {
            "kernel_version": self._get_kernel_version(),
            "architecture": self._get_architecture(),
            "platform": self._get_platform(),
            "compiler": self._get_compiler(),
            "security_features": self._get_security_features(),
            "subsystems": self._get_subsystems(),
            "config_stats": self._get_config_stats(),
        }

    def _get_kernel_version(self) -> Dict[str, str]:
        """Extract kernel version from Makefile."""
        makefile = self.root / "Makefile"
        version_info = {}
        if makefile.exists():
            with open(makefile, 'r') as f:
                for line in f:
                    for key in ['VERSION', 'PATCHLEVEL', 'SUBLEVEL', 'EXTRAVERSION']:
                        if line.startswith(f'{key} ='):
                            val = line.split('=', 1)[1].strip()
                            version_info[key.lower()] = val
                    if len(version_info) >= 4:
                        break
            # Compose full version string
            v = version_info
            version_info['full'] = f"{v.get('version', '0')}.{v.get('patchlevel', '0')}.{v.get('sublevel', '0')}{v.get('extraversion', '')}"
        return version_info

    def _get_architecture(self) -> Dict[str, any]:
        """Extract architecture information."""
        arch_configs = {}
        arch_map = {
            'CONFIG_ARM64': 'arm64',
            'CONFIG_ARM': 'arm',
            'CONFIG_X86_64': 'x86_64',
            'CONFIG_X86': 'x86',
            'CONFIG_MIPS': 'mips',
            'CONFIG_PPC': 'powerpc',
            'CONFIG_RISCV': 'riscv',
        }
        detected_arch = None
        for cfg, arch in arch_map.items():
            if self.config.get(cfg) == 'y':
                detected_arch = arch
                break

        return {
            "arch": detected_arch,
            "bits": "64" if self.config.get('CONFIG_64BIT') == 'y' else "32",
            "mmu": self.config.get('CONFIG_MMU') == 'y',
            "smp": self.config.get('CONFIG_SMP') == 'y',
        }

    def _get_platform(self) -> Dict[str, str]:
        """Extract platform/SoC information."""
        platform = {}
        # Known platform prefixes to look for
        platform_prefixes = [
            'CONFIG_ARCH_MEDIATEK',
            'CONFIG_ARCH_ROCKCHIP',
            'CONFIG_ARCH_SUNXI',
            'CONFIG_ARCH_QCOM',
            'CONFIG_ARCH_MVEBU',
            'CONFIG_ARCH_BCM',
            'CONFIG_ARCH_HISI',
            'CONFIG_ARCH_TEGRA',
            'CONFIG_ARCH_EXYNOS',
            'CONFIG_ARCH_ZYNQ',
            'CONFIG_ARCH_INTEL',
        ]
        for prefix in platform_prefixes:
            if self.config.get(prefix) == 'y':
                platform['vendor'] = prefix.replace('CONFIG_ARCH_', '')
                break

        # Look for SOC_* configs
        for key, val in self.config.items():
            if key.startswith('CONFIG_SOC_') and val == 'y' and not key.startswith('CONFIG_SOC_BUS'):
                platform['soc'] = key.replace('CONFIG_SOC_', '')
                break

        # Look for specific chip configs (e.g., CONFIG_MACH_MT7981)
        for key, val in self.config.items():
            if key.startswith('CONFIG_MACH_') and val == 'y':
                platform['machine'] = key.replace('CONFIG_MACH_', '')
                break

        return platform

    def _get_compiler(self) -> Dict[str, str]:
        """Extract compiler information."""
        compile_h = self.root / "include/generated/compile.h"
        compiler_info = {}
        if compile_h.exists():
            with open(compile_h, 'r') as f:
                for line in f:
                    if 'LINUX_COMPILER' in line:
                        # Extract the string between quotes
                        import re
                        match = re.search(r'"([^"]*)"', line)
                        if match:
                            compiler_info['version'] = match.group(1)
        return compiler_info

    def _get_security_features(self) -> Dict[str, bool]:
        """Extract security hardening features."""
        security_configs = [
            'CONFIG_STACKPROTECTOR',
            'CONFIG_STACKPROTECTOR_STRONG',
            'CONFIG_FORTIFY_SOURCE',
            'CONFIG_STRICT_KERNEL_RWX',
            'CONFIG_STRICT_MODULE_RWX',
            'CONFIG_RANDOMIZE_BASE',  # KASLR
            'CONFIG_RANDOMIZE_MEMORY',
            'CONFIG_HARDENED_USERCOPY',
            'CONFIG_SLAB_FREELIST_RANDOM',
            'CONFIG_KASAN',
            'CONFIG_UBSAN',
            'CONFIG_CFI_CLANG',
            'CONFIG_SHADOW_CALL_STACK',
        ]
        return {cfg.replace('CONFIG_', ''): self.config.get(cfg) == 'y'
                for cfg in security_configs}

    def _get_subsystems(self) -> Dict[str, bool]:
        """Extract enabled subsystems relevant to CVE triage."""
        subsystem_configs = [
            ('networking', 'CONFIG_NET'),
            ('ipv4', 'CONFIG_INET'),
            ('ipv6', 'CONFIG_IPV6'),
            ('netfilter', 'CONFIG_NETFILTER'),
            ('bridge', 'CONFIG_BRIDGE'),
            ('wireless', 'CONFIG_WLAN'),
            ('bluetooth', 'CONFIG_BT'),
            ('usb', 'CONFIG_USB'),
            ('usb_storage', 'CONFIG_USB_STORAGE'),
            ('scsi', 'CONFIG_SCSI'),
            ('ata', 'CONFIG_ATA'),
            ('nvme', 'CONFIG_NVME_CORE'),
            ('mmc', 'CONFIG_MMC'),
            ('mtd', 'CONFIG_MTD'),
            ('nand', 'CONFIG_MTD_NAND'),
            ('spi', 'CONFIG_SPI'),
            ('i2c', 'CONFIG_I2C'),
            ('gpio', 'CONFIG_GPIOLIB'),
            ('pwm', 'CONFIG_PWM'),
            ('watchdog', 'CONFIG_WATCHDOG'),
            ('rtc', 'CONFIG_RTC_CLASS'),
            ('dma_engine', 'CONFIG_DMADEVICES'),
            ('crypto', 'CONFIG_CRYPTO'),
            ('ext4', 'CONFIG_EXT4_FS'),
            ('f2fs', 'CONFIG_F2FS_FS'),
            ('squashfs', 'CONFIG_SQUASHFS'),
            ('ubifs', 'CONFIG_UBIFS_FS'),
            ('jffs2', 'CONFIG_JFFS2_FS'),
            ('nfs', 'CONFIG_NFS_FS'),
            ('nfsd', 'CONFIG_NFSD'),
            ('cifs', 'CONFIG_CIFS'),
            ('fuse', 'CONFIG_FUSE_FS'),
            ('overlayfs', 'CONFIG_OVERLAY_FS'),
            ('bpf', 'CONFIG_BPF'),
            ('bpf_syscall', 'CONFIG_BPF_SYSCALL'),
            ('kvm', 'CONFIG_KVM'),
            ('devmem', 'CONFIG_DEVMEM'),
            ('debugfs', 'CONFIG_DEBUG_FS'),
            ('profiling', 'CONFIG_PROFILING'),
            ('kprobes', 'CONFIG_KPROBES'),
            ('ftrace', 'CONFIG_FTRACE'),
        ]
        return {name: self.config.get(cfg) in ('y', 'm')
                for name, cfg in subsystem_configs}

    def _get_config_stats(self) -> Dict[str, int]:
        """Get statistics about the configuration."""
        builtin = sum(1 for v in self.config.values() if v == 'y')
        modules = sum(1 for v in self.config.values() if v == 'm')
        return {
            "builtin_count": builtin,
            "module_count": modules,
            "total_enabled": builtin + modules,
        }


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
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    config[name] = value

        return config


class MakefileParser:
    """Enhanced Makefile parser with better pattern coverage."""

    def __init__(self, config: Dict[str, str], verbose: bool = False):
        self.config = config
        self.verbose = verbose
        self.module_defs: Dict[str, List[str]] = {}
        # Track Makefile variables like mmu-y, tmp-y, file-mmu-y
        self.makefile_vars: Dict[str, List[str]] = {}

    def _expand_config_var(self, var: str) -> str:
        """Expand $(CONFIG_XXX) or $(subst ...) to its value."""
        # Handle $(subst m,y,$(CONFIG_XXX)) pattern - treat m as y
        subst_my_match = re.match(r'\$\(subst\s+m,y,\$\((CONFIG_\w+)\)\)', var)
        if subst_my_match:
            config_name = subst_my_match.group(1)
            value = self.config.get(config_name, '')
            return 'y' if value in ('y', 'm') else ''

        # Handle $(subst y,$(CONFIG_X),$(CONFIG_Y)) pattern
        # This means: if CONFIG_Y is 'y', substitute with CONFIG_X's value
        subst_yc_match = re.match(
            r'\$\(subst\s+y,\$\((CONFIG_\w+)\),\$\((CONFIG_\w+)\)\)', var
        )
        if subst_yc_match:
            config_x = subst_yc_match.group(1)
            config_y = subst_yc_match.group(2)
            value_y = self.config.get(config_y, '')
            if value_y == 'y':
                # Substitute 'y' with CONFIG_X's value
                return self.config.get(config_x, '')
            else:
                # Keep original value
                return value_y

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
            # Remove comments (but be careful with strings)
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
        return [t.strip() for t in value.split() if t.strip()]

    def _is_condition_enabled(self, condition: str) -> bool:
        """Check if a Makefile condition is enabled."""
        if condition in ('y', 'm'):
            return True
        value = self._expand_config_var(condition)
        return value in ('y', 'm')

    def _expand_makefile_vars(self, targets_str: str) -> str:
        """Expand $(var-y) and $(varname) style Makefile variable references."""
        # Pattern to match $(varname-y), $(varname), $(varname_underscore)
        var_pattern = re.compile(r'\$\((\w[\w-]*)\)')

        def replace_var(match):
            var_name = match.group(1)
            # Direct match
            if var_name in self.makefile_vars:
                return ' '.join(self.makefile_vars[var_name])
            # Try with -y suffix (for cases like $(mmu-y) stored as mmu-y)
            if not var_name.endswith('-y'):
                var_with_y = f"{var_name}-y"
                if var_with_y in self.makefile_vars:
                    return ' '.join(self.makefile_vars[var_with_y])
            return ''

        return var_pattern.sub(replace_var, targets_str)

    def parse(self, makefile_path: str) -> Tuple[List[str], List[str]]:
        """
        Parse a Makefile and return:
        - List of .o files to build
        - List of subdirectories to recurse into
        """
        objects = []
        subdirs = []

        if not os.path.exists(makefile_path):
            return objects, subdirs

        with open(makefile_path, 'r') as f:
            lines = f.readlines()

        lines = self._join_continued_lines(lines)

        # Patterns for Makefile constructs
        # obj-y, obj-m, obj-$(CONFIG_XXX), obj-$(subst m,y,$(CONFIG_XXX)), obj-$(subst y,$(CONFIG_X),$(CONFIG_Y))
        obj_pattern = re.compile(
            r'^obj-(\$\(subst\s+y,\$\(CONFIG_\w+\),\$\(CONFIG_\w+\)\)|\$\(subst\s+m,y,\$\(CONFIG_\w+\)\)|\$\(CONFIG_\w+\)|y|m)\s*[+:]?=\s*(.+)$'
        )

        # lib-y, lib-$(CONFIG_XXX) - library objects (used in arch/*/lib/)
        lib_pattern = re.compile(
            r'^lib-(\$\(CONFIG_\w+\)|y|m)\s*[+:]?=\s*(.+)$'
        )

        # head-y - head objects (like head.o in arch/*/kernel/)
        head_pattern = re.compile(
            r'^head-y\s*[+:]?=\s*(.+)$'
        )

        # obj-vdso - vDSO objects (used in arch/*/kernel/vdso/)
        obj_vdso_pattern = re.compile(
            r'^obj-vdso\s*[+:]?=\s*(.+)$'
        )

        # subdir-y, subdir-$(CONFIG_XXX) - for subdirectory traversal
        subdir_pattern = re.compile(
            r'^subdir-(\$\(CONFIG_\w+\)|y|m)\s*[+:]?=\s*(.+)$'
        )

        # module-y := file1.o file2.o (composite object definitions)
        # Also handles module-$(subst m,y,$(CONFIG_XXX)) patterns
        module_def_pattern = re.compile(
            r'^(\w[\w-]*?)(?:-objs)?-(\$\(subst\s+m,y,\$\(CONFIG_\w+\)\)|\$\(CONFIG_\w+\)|y|m)\s*[+:]?=\s*(.+)$'
        )

        # module-objs := file1.o file2.o (simple composite definition)
        module_objs_pattern = re.compile(r'^(\w[\w-]*)-objs\s*[+:]?=\s*(.+)$')

        # core-y, libs-y patterns (used in arch/ Makefiles)
        core_pattern = re.compile(r'^(?:core|libs|drivers|net)-y\s*[+:]?=\s*(.+)$')

        # Generic variable assignment pattern: var-y, var-$(CONFIG_XXX), var-$(subst m,y,...)
        # Captures: varname-y := ... or varname-$(CONFIG_XXX) := ...
        # Used for patterns like mmu-y, tmp-y, file-mmu-y, bridge-$(subst m,y,...), etc.
        # Group 3 captures the operator (:=, =, or +=)
        var_assign_pattern = re.compile(
            r'^(\w[\w-]*)-(\$\(subst\s+m,y,\$\(CONFIG_\w+\)\)|\$\(CONFIG_\w+\)|y|m)\s*([+:]?=)\s*(.+)$'
        )

        # Simple variable assignment (without -y suffix): varname := value or varname = value
        # Used for patterns like: libfdt_files = fdt.o ..., ipv6-offload := ip6_offload.o ...
        simple_var_pattern = re.compile(
            r'^(\w[\w-]*)\s*[:]?=\s*(.+)$'
        )

        # Reserved prefixes that are NOT variable assignments
        reserved_prefixes = {'obj', 'lib', 'subdir', 'head', 'core', 'libs',
                             'drivers', 'net', 'extra', 'always', 'targets',
                             'hostprogs', 'ccflags', 'asflags', 'ldflags',
                             'CFLAGS', 'AFLAGS', 'LDFLAGS', 'KBUILD'}

        # Reserved simple variable names
        reserved_simple_vars = {'CFLAGS_REMOVE', 'AFLAGS_REMOVE', 'ccflags-y',
                                'asflags-y', 'ldflags-y', 'KASAN_SANITIZE',
                                'KCOV_INSTRUMENT', 'GCOV_PROFILE', 'UBSAN_SANITIZE',
                                'OBJECT_FILES_NON_STANDARD', 'CPPFLAGS', 'EXTRA_CFLAGS'}

        # PASS 0: Collect Makefile variable assignments (mmu-y, tmp-y, etc.)
        self.makefile_vars = {}  # Reset for this Makefile
        for line in lines:
            line = line.strip()

            # Check for var-y or var-$(CONFIG_*) pattern
            var_match = var_assign_pattern.match(line)
            if var_match:
                var_base, condition, operator, targets_str = var_match.groups()
                # Skip reserved prefixes
                if var_base in reserved_prefixes:
                    continue
                # Skip module definitions (handled separately)
                if var_base.endswith('-objs'):
                    continue

                var_name = f"{var_base}-y"  # Normalize to -y form
                if self._is_condition_enabled(condition):
                    targets = self._parse_targets(targets_str)
                    obj_targets = [t for t in targets if t.endswith('.o')]
                    if obj_targets:
                        # := or = replaces, += appends
                        if operator == '+=':
                            if var_name not in self.makefile_vars:
                                self.makefile_vars[var_name] = []
                            self.makefile_vars[var_name].extend(obj_targets)
                        else:
                            # := or = - replace the variable
                            self.makefile_vars[var_name] = obj_targets
                continue

            # Check for simple variable assignment (no -y suffix)
            simple_match = simple_var_pattern.match(line)
            if simple_match:
                var_name, targets_str = simple_match.groups()
                # Skip reserved names and assignments with flags/paths
                if var_name in reserved_simple_vars:
                    continue
                # Skip exact matches of reserved prefixes (obj, lib, etc.) but not
                # variables that just start with them (libfdt_files, objcopy, etc.)
                if var_name in reserved_prefixes:
                    continue
                # Skip if the value contains flags or paths (starts with - or /)
                if targets_str.strip().startswith(('-', '/', '$(')):
                    continue

                targets = self._parse_targets(targets_str)
                obj_targets = [t for t in targets if t.endswith('.o')]
                if obj_targets:
                    if var_name not in self.makefile_vars:
                        self.makefile_vars[var_name] = []
                    self.makefile_vars[var_name].extend(obj_targets)

        # PASS 1: Collect module definitions
        for line in lines:
            line = line.strip()

            # Module definition with condition
            module_match = module_def_pattern.match(line)
            if module_match:
                module_name, condition, targets_str = module_match.groups()
                if module_name == 'obj' or module_name == 'subdir':
                    continue

                if self._is_condition_enabled(condition):
                    # Expand Makefile variable references
                    targets_str = self._expand_makefile_vars(targets_str)
                    targets = self._parse_targets(targets_str)
                    if module_name not in self.module_defs:
                        self.module_defs[module_name] = []
                    self.module_defs[module_name].extend(
                        [t for t in targets if t.endswith('.o')]
                    )
                continue

            # Simple -objs pattern
            objs_match = module_objs_pattern.match(line)
            if objs_match:
                module_name, targets_str = objs_match.groups()
                if module_name not in ('obj', 'subdir'):
                    # Expand Makefile variable references like $(file-mmu-y)
                    targets_str = self._expand_makefile_vars(targets_str)
                    targets = self._parse_targets(targets_str)
                    if module_name not in self.module_defs:
                        self.module_defs[module_name] = []
                    self.module_defs[module_name].extend(
                        [t for t in targets if t.endswith('.o')]
                    )

        # PASS 2: Process obj- and subdir- lines
        for line in lines:
            line = line.strip()

            # Check for obj-y or obj-$(CONFIG_XXX)
            obj_match = obj_pattern.match(line)
            if obj_match:
                condition, targets_str = obj_match.groups()

                if self._is_condition_enabled(condition):
                    # Expand Makefile variable references like $(mmu-y)
                    targets_str = self._expand_makefile_vars(targets_str)
                    targets = self._parse_targets(targets_str)
                    for target in targets:
                        if target.endswith('/'):
                            subdirs.append(target.rstrip('/'))
                        elif target.endswith('.o'):
                            module_name = target[:-2]
                            if module_name in self.module_defs:
                                objects.extend(self.module_defs[module_name])
                            else:
                                objects.append(target)
                continue

            # Check for subdir-y or subdir-$(CONFIG_XXX)
            subdir_match = subdir_pattern.match(line)
            if subdir_match:
                condition, targets_str = subdir_match.groups()
                if self._is_condition_enabled(condition):
                    targets = self._parse_targets(targets_str)
                    subdirs.extend([t.rstrip('/') for t in targets])
                continue

            # Check for core-y, libs-y patterns (arch directories)
            core_match = core_pattern.match(line)
            if core_match:
                targets_str = core_match.group(1)
                targets = self._parse_targets(targets_str)
                for target in targets:
                    if target.endswith('/'):
                        subdirs.append(target.rstrip('/'))
                    elif target.endswith('.o'):
                        objects.append(target)
                continue

            # Check for lib-y or lib-$(CONFIG_XXX) patterns
            lib_match = lib_pattern.match(line)
            if lib_match:
                condition, targets_str = lib_match.groups()
                if self._is_condition_enabled(condition):
                    # Expand Makefile variable references like $(libfdt_files)
                    targets_str = self._expand_makefile_vars(targets_str)
                    targets = self._parse_targets(targets_str)
                    for target in targets:
                        if target.endswith('.o'):
                            objects.append(target)
                continue

            # Check for head-y pattern
            head_match = head_pattern.match(line)
            if head_match:
                targets_str = head_match.group(1)
                targets = self._parse_targets(targets_str)
                for target in targets:
                    if target.endswith('.o'):
                        objects.append(target)
                continue

            # Check for obj-vdso pattern
            vdso_match = obj_vdso_pattern.match(line)
            if vdso_match:
                targets_str = vdso_match.group(1)
                targets = self._parse_targets(targets_str)
                for target in targets:
                    if target.endswith('.o'):
                        objects.append(target)

        return objects, subdirs


class ObjectFileScanner:
    """Scans for compiled .o files in the build tree."""

    EXCLUDE_DIRS = {'Documentation', 'scripts', 'usr', 'tools', 'samples'}

    def __init__(self, root: str):
        self.root = Path(root)

    def scan(self) -> Dict[str, Set[str]]:
        """
        Scan for .o files and return dict mapping directories to object files.
        Returns dict[rel_dir] = set of .o filenames
        """
        results: Dict[str, Set[str]] = {}

        for dirpath, dirnames, filenames in os.walk(self.root):
            rel_dir = os.path.relpath(dirpath, self.root)

            # Skip excluded directories
            if any(excl in rel_dir.split(os.sep) for excl in self.EXCLUDE_DIRS):
                continue

            # Skip root
            if rel_dir == '.':
                continue

            # Collect .o files (exclude built-in.o and other special files)
            obj_files = set()
            for f in filenames:
                if f.endswith('.o') and not f.startswith('built-in'):
                    # Also skip modules.order artifacts
                    if not f.endswith('.mod.o'):
                        obj_files.add(f)

            if obj_files:
                results[rel_dir] = obj_files

        return results


class HybridScanner:
    """
    Hybrid scanner combining Makefile parsing and object file detection.
    """

    KERNEL_DIRS = [
        'arch', 'block', 'certs', 'crypto', 'drivers', 'fs', 'init',
        'ipc', 'kernel', 'lib', 'mm', 'net', 'security', 'sound', 'virt'
    ]

    ARCH_SUBDIRS = ['kernel', 'mm', 'lib', 'crypto', 'net', 'boot', 'kvm']

    def __init__(self, root: str, config: Dict[str, str],
                 verbose: bool = False, include_headers: bool = True):
        self.root = Path(root)
        self.config = config
        self.verbose = verbose
        self.include_headers = include_headers
        self.makefile_parser = MakefileParser(config, verbose)
        self.object_scanner = ObjectFileScanner(root)

    def _detect_architecture(self) -> Optional[str]:
        """Detect target architecture from config."""
        # Check for specific arch configs
        arch_map = {
            'CONFIG_ARM64': 'arm64',
            'CONFIG_ARM': 'arm',
            'CONFIG_X86_64': 'x86',
            'CONFIG_X86': 'x86',
            'CONFIG_MIPS': 'mips',
            'CONFIG_PPC': 'powerpc',
            'CONFIG_RISCV': 'riscv',
            'CONFIG_S390': 's390',
        }

        for config_key, arch in arch_map.items():
            if self.config.get(config_key) == 'y':
                return arch

        # Fallback: look for CONFIG_ARCH_*
        for key in self.config:
            if key.startswith('CONFIG_ARCH_') and self.config[key] == 'y':
                return key.replace('CONFIG_ARCH_', '').lower()

        return None

    def _object_to_source(self, obj_file: str, directory: Path) -> Optional[str]:
        """Convert .o filename to source file if it exists."""
        base = obj_file[:-2]

        for ext in ['.c', '.S', '.s']:
            src_path = directory / (base + ext)
            if src_path.exists():
                return base + ext

        return None

    def _get_headers(self, directory: Path) -> List[str]:
        """Get header files in directory."""
        headers = []
        if directory.exists():
            for f in directory.iterdir():
                if f.is_file() and f.suffix == '.h':
                    headers.append(f.name)
        return sorted(headers)

    def _scan_makefile_tree(self, rel_dir: str, visited: Set[str]) -> Dict[str, Set[str]]:
        """
        Recursively scan Makefiles and return expected .o files per directory.
        Returns dict[rel_dir] = set of expected .o filenames
        """
        results: Dict[str, Set[str]] = {}

        if rel_dir in visited:
            return results
        visited.add(rel_dir)

        abs_dir = self.root / rel_dir
        makefile = abs_dir / 'Makefile'
        if not makefile.exists():
            makefile = abs_dir / 'Kbuild'
        if not makefile.exists():
            return results

        if self.verbose:
            print(f"  Parsing: {rel_dir}/Makefile", file=sys.stderr)

        # Reset module definitions for each Makefile
        self.makefile_parser.module_defs = {}

        objects, subdirs = self.makefile_parser.parse(str(makefile))

        if objects:
            if rel_dir not in results:
                results[rel_dir] = set()
            results[rel_dir].update(objects)

        # Recurse into subdirectories
        for subdir in subdirs:
            sub_rel = f"{rel_dir}/{subdir}"
            sub_results = self._scan_makefile_tree(sub_rel, visited)
            for dir_path, objs in sub_results.items():
                if dir_path not in results:
                    results[dir_path] = set()
                results[dir_path].update(objs)

        return results

    def _scan_arch_makefiles(self, arch: str, visited: Set[str]) -> Dict[str, Set[str]]:
        """Special handling for architecture directories."""
        results: Dict[str, Set[str]] = {}
        arch_base = f"arch/{arch}"

        # Scan main arch Makefile
        sub_results = self._scan_makefile_tree(arch_base, visited)
        for dir_path, objs in sub_results.items():
            if dir_path not in results:
                results[dir_path] = set()
            results[dir_path].update(objs)

        # Scan known arch subdirectories
        for subdir in self.ARCH_SUBDIRS:
            subdir_path = f"{arch_base}/{subdir}"
            if (self.root / subdir_path).exists():
                sub_results = self._scan_makefile_tree(subdir_path, visited)
                for dir_path, objs in sub_results.items():
                    if dir_path not in results:
                        results[dir_path] = set()
                    results[dir_path].update(objs)

        return results

    def scan(self) -> ScanResult:
        """
        Perform hybrid scan combining both methods.
        Returns ScanResult with confirmed files and discrepancies.
        """
        result = ScanResult()

        if self.verbose:
            print("Phase 1: Scanning Makefiles...", file=sys.stderr)

        # Phase 1: Get expected objects from Makefiles
        makefile_objects: Dict[str, Set[str]] = {}
        visited: Set[str] = set()

        arch = self._detect_architecture()
        if self.verbose and arch:
            print(f"  Detected architecture: {arch}", file=sys.stderr)

        for top_dir in self.KERNEL_DIRS:
            top_path = self.root / top_dir
            if not top_path.exists():
                continue

            if top_dir == 'arch' and arch:
                sub_results = self._scan_arch_makefiles(arch, visited)
            else:
                sub_results = self._scan_makefile_tree(top_dir, visited)

            for dir_path, objs in sub_results.items():
                if dir_path not in makefile_objects:
                    makefile_objects[dir_path] = set()
                makefile_objects[dir_path].update(objs)

        if self.verbose:
            print(f"  Found {len(makefile_objects)} directories in Makefiles",
                  file=sys.stderr)

        # Phase 2: Scan for actual .o files
        if self.verbose:
            print("Phase 2: Scanning for object files...", file=sys.stderr)

        actual_objects = self.object_scanner.scan()

        if self.verbose:
            print(f"  Found {len(actual_objects)} directories with .o files",
                  file=sys.stderr)

        # Phase 3: Cross-reference and categorize
        if self.verbose:
            print("Phase 3: Cross-referencing...", file=sys.stderr)

        all_dirs = set(makefile_objects.keys()) | set(actual_objects.keys())

        for rel_dir in sorted(all_dirs):
            abs_dir = self.root / rel_dir
            expected = makefile_objects.get(rel_dir, set())
            actual = actual_objects.get(rel_dir, set())

            confirmed_sources = []
            configured_not_built = []
            built_not_configured = []

            # Check expected objects
            for obj in expected:
                if obj in actual:
                    # Confirmed: both configured and built
                    src = self._object_to_source(obj, abs_dir)
                    if src:
                        confirmed_sources.append(src)
                else:
                    # Configured but not built
                    src = self._object_to_source(obj, abs_dir)
                    if src:
                        configured_not_built.append(src)

            # Check actual objects not in expected
            for obj in actual:
                if obj not in expected:
                    src = self._object_to_source(obj, abs_dir)
                    if src:
                        built_not_configured.append(src)

            # Collect headers for directories with any compiled sources
            headers = []
            if self.include_headers and (confirmed_sources or built_not_configured):
                headers = self._get_headers(abs_dir)

            # Store results - merge headers with source files
            if confirmed_sources or (self.include_headers and headers and not built_not_configured):
                all_files = set(confirmed_sources)
                if self.include_headers and headers:
                    all_files.update(headers)
                if all_files:
                    result.confirmed[rel_dir] = sorted(all_files)

            if configured_not_built:
                result.configured_not_built[rel_dir] = sorted(set(configured_not_built))

            if built_not_configured:
                all_files = set(built_not_configured)
                # Add headers to built_not_configured if no confirmed sources
                if self.include_headers and headers and not confirmed_sources:
                    all_files.update(headers)
                if all_files:
                    result.built_not_configured[rel_dir] = sorted(all_files)

        return result


def output_combined(result: ScanResult) -> Dict[str, List[str]]:
    """
    Combine confirmed and built_not_configured into a single result.
    This gives the most accurate picture of what was actually compiled.
    Headers are already merged into the source file lists.
    """
    combined: Dict[str, List[str]] = {}

    all_dirs = set(result.confirmed.keys()) | set(result.built_not_configured.keys())

    for rel_dir in sorted(all_dirs):
        files = set()
        files.update(result.confirmed.get(rel_dir, []))
        files.update(result.built_not_configured.get(rel_dir, []))

        if files:
            combined[rel_dir] = sorted(files)

    return combined


def output_cve_triage(result: ScanResult, build_metadata: Dict = None,
                      output_file: Optional[str] = None):
    """
    Output optimized for CVE triage lookups.

    Creates a JSON with:
    - files: list of compiled file paths (use as set for O(1) lookup)
    - build_info: kernel version, arch, security features, subsystems
    - file_stats: counts of source and header files

    Usage in Python:
        data = json.load(f)
        files_set = set(data["files"])  # Convert to set for O(1) lookup

        # Check if file is compiled
        if file_path in files_set: CVE may apply

        # Check kernel version
        if data["build_info"]["kernel_version"]["full"] in affected_versions: ...

        # Check if subsystem is enabled
        if data["build_info"]["subsystems"]["bluetooth"]: ...
    """
    files_list = []

    # Include confirmed files (configured AND built)
    for dir_path, files in result.confirmed.items():
        for f in files:
            files_list.append(f"{dir_path}/{f}")

    # Include built_not_configured files (actually compiled, just missed by parser)
    for dir_path, files in result.built_not_configured.items():
        for f in files:
            files_list.append(f"{dir_path}/{f}")

    # Do NOT include configured_not_built - those files aren't compiled

    # Sort for consistent output
    files_list = sorted(set(files_list))

    output_data = {
        "files": files_list,
        "file_stats": {
            "total_files": len(files_list),
            "source_files": sum(1 for f in files_list if f.endswith(('.c', '.S', '.s'))),
            "header_files": sum(1 for f in files_list if f.endswith('.h')),
        },
    }

    # Add build metadata if provided
    if build_metadata:
        output_data["build_info"] = build_metadata

    output = json.dumps(output_data, indent=2)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(output + '\n')
    else:
        print(output)


def output_json(data: dict, output_file: Optional[str] = None):
    """Output as JSON."""
    output = json.dumps(data, indent=2)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(output + '\n')
    else:
        print(output)


def output_text(data: Dict[str, List[str]], output_file: Optional[str] = None):
    """Output as text listing."""
    lines = []
    for dir_path, files in sorted(data.items()):
        for f in sorted(files):
            lines.append(f"{dir_path}/{f}")

    output = '\n'.join(lines)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(output + '\n')
    else:
        print(output)


def output_discrepancy_report(result: ScanResult, output_file: Optional[str] = None):
    """Output a discrepancy report."""
    lines = []
    lines.append("=" * 70)
    lines.append("HYBRID SCAN DISCREPANCY REPORT")
    lines.append("=" * 70)
    lines.append("")

    # Count only source files for "built but not configured" (headers are expected)
    built_not_configured_src = sum(1 for files in result.built_not_configured.values()
                                    for f in files if f.endswith(('.c', '.S', '.s')))

    # Summary
    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"Source files (.c/.S):             {result.total_source_files()} files")
    lines.append(f"Header files (.h):                {result.total_header_files()} files")
    lines.append(f"Configured but NOT built:         {sum(len(f) for f in result.configured_not_built.values())} files")
    lines.append(f"Built but NOT in Makefile parse:  {built_not_configured_src} source files")
    lines.append("")

    # Configured but not built
    if result.configured_not_built:
        lines.append("=" * 70)
        lines.append("CONFIGURED BUT NOT BUILT")
        lines.append("(Files referenced in Makefiles but no .o found)")
        lines.append("-" * 70)
        for dir_path, files in sorted(result.configured_not_built.items()):
            for f in files:
                lines.append(f"  {dir_path}/{f}")
        lines.append("")

    # Built but not configured (only show source files, not headers)
    if built_not_configured_src > 0:
        lines.append("=" * 70)
        lines.append("BUILT BUT NOT IN MAKEFILE PARSE")
        lines.append("(Source files with .o but not found via Makefile parsing)")
        lines.append("(May indicate Makefile patterns not yet supported)")
        lines.append("-" * 70)
        for dir_path, files in sorted(result.built_not_configured.items()):
            for f in files:
                if f.endswith(('.c', '.S', '.s')):
                    lines.append(f"  {dir_path}/{f}")
        lines.append("")

    output = '\n'.join(lines)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(output + '\n')
    else:
        print(output)


def main():
    parser = argparse.ArgumentParser(
        description='Hybrid Linux kernel component scanner (Makefile + object file detection)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -r /path/to/linux/build
  %(prog)s -r /path/to/linux/build -o components.json
  %(prog)s -r /path/to/linux/build --format text
  %(prog)s -r /path/to/linux/build --report discrepancies
  %(prog)s -r /path/to/linux/build --report full
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
        choices=['json', 'text'],
        default='json',
        help='Output format (default: json)'
    )
    parser.add_argument(
        '--report',
        choices=['combined', 'discrepancies', 'full', 'cve-triage'],
        default='combined',
        help='Report type: combined (default), discrepancies, full, or cve-triage'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed progress information'
    )
    parser.add_argument(
        '--no-headers',
        action='store_true',
        help='Exclude .h header files from output'
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
        print(f"Config: {enabled_y} built-in, {enabled_m} modules", file=sys.stderr)

    # Scan
    include_headers = not args.no_headers
    scanner = HybridScanner(root, config, args.verbose, include_headers)
    result = scanner.scan()

    # Output based on report type
    if args.report == 'discrepancies':
        output_discrepancy_report(result, args.output)
    elif args.report == 'full':
        full_data = {
            'confirmed': result.confirmed,
            'configured_not_built': result.configured_not_built,
            'built_not_configured': result.built_not_configured,
            'summary': {
                'total_files': result.total_confirmed() + sum(len(f) for f in result.built_not_configured.values()),
                'source_files': result.total_source_files(),
                'header_files': result.total_header_files() if include_headers else 0,
                'configured_not_built_files': sum(len(f) for f in result.configured_not_built.values()),
                'built_not_configured_source_files': sum(1 for files in result.built_not_configured.values()
                                                          for f in files if f.endswith(('.c', '.S', '.s'))),
            }
        }
        output_json(full_data, args.output)
    elif args.report == 'cve-triage':
        # Optimized format for CVE triage with file paths as keys
        # Include build metadata for additional CVE filtering
        metadata_extractor = BuildMetadataExtractor(root, config)
        build_metadata = metadata_extractor.extract()
        output_cve_triage(result, build_metadata, args.output)
    else:  # combined
        combined = output_combined(result)
        if args.format == 'json':
            output_json(combined, args.output)
        else:
            output_text(combined, args.output)

    # Print summary to stderr
    if args.verbose or args.output:
        print(f"\nResults:", file=sys.stderr)
        print(f"  Source files (.c/.S):      {result.total_source_files()}", file=sys.stderr)
        if include_headers:
            print(f"  Header files (.h):         {result.total_header_files()}", file=sys.stderr)
        print(f"  Configured (not built):    {sum(len(f) for f in result.configured_not_built.values())}", file=sys.stderr)
        built_not_configured_src = sum(1 for files in result.built_not_configured.values()
                                        for f in files if f.endswith(('.c', '.S', '.s')))
        if built_not_configured_src > 0:
            print(f"  Built (not in Makefile):   {built_not_configured_src}", file=sys.stderr)
        total = result.total_confirmed() + sum(len(f) for f in result.built_not_configured.values())
        print(f"  Total in output:           {total}", file=sys.stderr)

        if args.output:
            print(f"\nOutput written to: {args.output}", file=sys.stderr)


if __name__ == '__main__':
    main()
