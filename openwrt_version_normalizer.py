"""
openwrt_version_normalizer.py
─────────────────────────────
Parse OpenWrt package version strings into stable (Version) and
volatile (ExtraVersion) components.

Patterns handled
────────────────
  1-25.1023_224042          →  Version: 1                    ExtraVersion: 25.1023_224042
  1-26.0224_021306          →  Version: 1                    ExtraVersion: 26.0224_021306
  1-r0-45c8168a             →  Version: 1-r0                 ExtraVersion: 45c8168a
  1-r0-54307b0c             →  Version: 1-r0                 ExtraVersion: 54307b0c
  2021-07-18-bc9d317f-2     →  Version: 2021-07-18-bc9d317f  ExtraVersion: 2
  2021-07-18-bc9d317f-3     →  Version: 2021-07-18-bc9d317f  ExtraVersion: 3
  1-25.1023_224045          →  Version: 1                    ExtraVersion: 25.1023_224045

Usage
─────
    # As a library
    from openwrt_version_normalizer import normalize, normalize_package_csv

    result = normalize("1-r0-45c8168a")
    print(result.version)        # "1-r0"
    print(result.extra_version)  # "45c8168a"
    print(result.original)       # "1-r0-45c8168a"

    # From the command line — built-in demo
    python openwrt_version_normalizer.py

    # From the command line — process a CSV file
    #   Input CSV must have a header row with columns: PkgName,version
    #   Output CSV is written to <input_stem>_normalized.csv by default
    python openwrt_version_normalizer.py packages.csv
    python openwrt_version_normalizer.py packages.csv -o results.csv

    # Parse one or more raw version strings directly
    python openwrt_version_normalizer.py 1-r0-45c8168a 2021-07-18-bc9d317f-3
"""

from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


# ─────────────────────────────────────────────────────────────
#  Regular expressions for each "volatile" segment type
# ─────────────────────────────────────────────────────────────

# Timestamp embedded in a single hyphen-delimited token, e.g. 25.1023_224042
#   <2-digit-year>.<MMDD>_<HHMMSS>
RE_TIMESTAMP_TOKEN = re.compile(r"^\d{2}\.\d{4}_\d{6}$")

# Short git hash: exactly 7 or 8 lowercase hex characters
RE_GIT_HASH_SHORT = re.compile(r"^[0-9a-f]{7,8}$")

# Pure integer rebuild counter (trailing -N on a version string)
RE_REBUILD_COUNTER = re.compile(r"^\d+$")

# Date component tokens
RE_YEAR  = re.compile(r"^\d{4}$")
RE_MONTH = re.compile(r"^(0[1-9]|1[0-2])$")
RE_DAY   = re.compile(r"^(0[1-9]|[12]\d|3[01])$")


# ─────────────────────────────────────────────────────────────
#  Result dataclasses
# ─────────────────────────────────────────────────────────────

@dataclass
class VersionComponents:
    original: str
    version: str          # stable, CPE-safe
    extra_version: str    # volatile, build-unique (empty string if none)

    @property
    def is_split(self) -> bool:
        return bool(self.extra_version)

    def __str__(self) -> str:
        if self.extra_version:
            return f"Version={self.version!r}  ExtraVersion={self.extra_version!r}"
        return f"Version={self.version!r}  ExtraVersion=(none)"


@dataclass
class PackageRecord:
    package: str
    original_version: str
    version: str
    extra_version: str


# ─────────────────────────────────────────────────────────────
#  Core classification helpers
# ─────────────────────────────────────────────────────────────

def _is_timestamp_token(segment: str) -> bool:
    """Match standalone timestamp tokens like 25.1023_224042."""
    return bool(RE_TIMESTAMP_TOKEN.match(segment))


def _is_git_hash(segment: str) -> bool:
    """Match a short (7-8 char) lowercase hex git hash."""
    return bool(RE_GIT_HASH_SHORT.match(segment))


def _is_rebuild_counter(segment: str) -> bool:
    """Match a pure integer (rebuild counter like -2 or -3)."""
    return bool(RE_REBUILD_COUNTER.match(segment))


def _is_date_triplet(segments: List[str], idx: int) -> bool:
    """
    Return True when segments[idx:idx+3] look like a calendar date:
    YYYY - MM - DD  (e.g. 2021-07-18)
    """
    if idx + 2 >= len(segments):
        return False
    return bool(
        RE_YEAR.match(segments[idx])
        and RE_MONTH.match(segments[idx + 1])
        and RE_DAY.match(segments[idx + 2])
    )


# ─────────────────────────────────────────────────────────────
#  Main normalizer
# ─────────────────────────────────────────────────────────────

def normalize(version_string: str) -> VersionComponents:
    """
    Split an OpenWrt version string into stable (Version) and
    volatile (ExtraVersion) parts.

    Parameters
    ----------
    version_string : str
        Raw version as found in the package metadata.

    Returns
    -------
    VersionComponents
        .version       – deterministic portion, safe for CPE use
        .extra_version – volatile build suffix (empty string if none)
        .original      – the original input string
    """
    v = version_string.strip()

    # Fast path: no hyphens means nothing to split
    if "-" not in v:
        return VersionComponents(original=v, version=v, extra_version="")

    segments = v.split("-")
    stable: List[str] = []
    volatile: List[str] = []

    i = 0
    while i < len(segments):
        seg = segments[i]

        # 1. Timestamp token (e.g. 25.1023_224042) → always volatile
        if _is_timestamp_token(seg):
            volatile.append(seg)
            i += 1
            continue

        # 2. Calendar date triplet YYYY-MM-DD → always stable
        if _is_date_triplet(segments, i):
            stable.extend(segments[i:i + 3])
            i += 3
            continue

        # 3. Short git hash → volatile UNLESS it immediately follows a
        #    YYYY-MM-DD date (then it is the upstream release tag, e.g.
        #    bc9d317f in 2021-07-18-bc9d317f)
        if _is_git_hash(seg):
            after_date = (
                len(stable) >= 3
                and RE_YEAR.match(stable[-3])
                and RE_MONTH.match(stable[-2])
                and RE_DAY.match(stable[-1])
            )
            if after_date:
                stable.append(seg)   # upstream release hash → stable
            else:
                volatile.append(seg) # pure build hash → volatile
            i += 1
            continue

        # 4. Pure integer rebuild counter at the very END → volatile
        #    (integers mid-string are part of the version, e.g. r0)
        if _is_rebuild_counter(seg) and i == len(segments) - 1:
            if stable:
                volatile.append(seg)
            else:
                stable.append(seg)
            i += 1
            continue

        # 5. Everything else → stable
        stable.append(seg)
        i += 1

    version_out       = "-".join(stable) if stable else v
    extra_version_out = "-".join(volatile)

    return VersionComponents(
        original=v,
        version=version_out,
        extra_version=extra_version_out,
    )


# ─────────────────────────────────────────────────────────────
#  Convenience: process a list of (package, version) pairs
# ─────────────────────────────────────────────────────────────

def normalize_packages(
    records: List[tuple],
) -> List[PackageRecord]:
    """
    Normalize a list of (package_name, version_string) tuples.

    Parameters
    ----------
    records : list of (str, str)
        Each tuple is (package_name, raw_version).

    Returns
    -------
    list of PackageRecord
    """
    result = []
    for package, raw_version in records:
        c = normalize(raw_version)
        result.append(
            PackageRecord(
                package=package,
                original_version=raw_version,
                version=c.version,
                extra_version=c.extra_version,
            )
        )
    return result


# ─────────────────────────────────────────────────────────────
#  CSV helpers
# ─────────────────────────────────────────────────────────────

# Recognized column-name aliases (lower-cased)
_PKG_ALIASES     = {"pkgname", "package", "pkg_name", "pkg"}
_VERSION_ALIASES = {"version", "ver"}


def normalize_package_csv(
    csv_text: str,
    package_col: int = 0,
    version_col: int = 1,
    delimiter: str = ",",
    has_header: bool = False,
) -> str:
    """
    Accept a CSV string and return an enriched CSV with Version and
    ExtraVersion columns appended.

    When *has_header* is True the first row is inspected for the
    canonical column names ``PkgName`` and ``version`` (case-insensitive).
    If found, those columns are used regardless of their position.
    Fallback to *package_col* / *version_col* indices if not found.

    Recognised header aliases
    ─────────────────────────
    Package column : PkgName, package, pkg_name, pkg
    Version column : version, ver

    Parameters
    ----------
    csv_text    : raw CSV text
    package_col : fallback column index for package name (default 0)
    version_col : fallback column index for version string (default 1)
    delimiter   : field separator (default ',')
    has_header  : whether the first row is a header (default False)

    Returns
    -------
    str – CSV with columns: PkgName, OriginalVersion, Version, ExtraVersion
    """
    reader = csv.reader(io.StringIO(csv_text), delimiter=delimiter)
    rows   = list(reader)
    if not rows:
        return ""

    if has_header:
        header = [h.strip().lower() for h in rows[0]]
        for idx, col in enumerate(header):
            if col in _PKG_ALIASES:
                package_col = idx
            if col in _VERSION_ALIASES:
                version_col = idx
        data_rows = rows[1:]
    else:
        data_rows = rows

    out_rows: List[List[str]] = [
        ["PkgName", "OriginalVersion", "Version", "ExtraVersion"]
    ]

    for lineno, row in enumerate(data_rows, start=2 if has_header else 1):
        # Skip blank rows
        if not row or all(cell.strip() == "" for cell in row):
            continue
        # Guard against under-length rows
        if len(row) <= max(package_col, version_col):
            out_rows.append([
                row[package_col] if len(row) > package_col else "",
                "",
                "",
                f"ERROR: only {len(row)} column(s) on line {lineno}",
            ])
            continue
        pkg = row[package_col].strip()
        ver = row[version_col].strip()
        c   = normalize(ver)
        out_rows.append([pkg, ver, c.version, c.extra_version])

    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows(out_rows)
    return buf.getvalue()


def normalize_csv_file(
    input_path: "str | Path",
    output_path: "Optional[str | Path]" = None,
    delimiter: str = ",",
) -> Path:
    """
    Read a CSV file whose header row contains ``PkgName`` and ``version``
    columns, normalize every version string, and write results to an
    output CSV file.

    Parameters
    ----------
    input_path  : path to the input CSV file
    output_path : path for the output CSV file.
                  Defaults to <input_stem>_normalized.csv in the same
                  directory as the input file.
    delimiter   : field separator (default ',')

    Returns
    -------
    Path – the path where the output file was written

    Raises
    ------
    FileNotFoundError if input_path does not exist.
    ValueError        if neither PkgName nor version headers are found
                      and the file has fewer than 2 columns.
    """
    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    if output_path is None:
        output_path = input_path.with_name(
            f"{input_path.stem}_normalized{input_path.suffix}"
        )
    output_path = Path(output_path)

    csv_text = input_path.read_text(encoding="utf-8")
    result   = normalize_package_csv(csv_text, has_header=True, delimiter=delimiter)
    output_path.write_text(result, encoding="utf-8")
    return output_path


# ─────────────────────────────────────────────────────────────
#  Built-in demo data
# ─────────────────────────────────────────────────────────────

_DEMO_DATA = [
    ("mtk-base-files",  "1-25.1023_224042"),
    ("mtk-base-files",  "1-26.0224_021306"),
    ("mtk_factory_rw",  "1-r0-45c8168a"),
    ("mtk_factory_rw",  "1-r0-54307b0c"),
    ("mtkhnat_util",    "1-r0-45c8168a"),
    ("mtkhnat_util",    "1-r0-54307b0c"),
    ("odhcpd-ipv6only", "2021-07-18-bc9d317f-2"),
    ("odhcpd-ipv6only", "2021-07-18-bc9d317f-3"),
    ("wifi-profile",    "1-25.1023_224045"),
    ("wifi-profile",    "1-26.0224_021310"),
]


def _demo() -> None:
    print(f"{'PkgName':<22} {'OriginalVersion':<28} {'Version':<26} {'ExtraVersion'}")
    print("-" * 100)
    for pkg, ver in _DEMO_DATA:
        c = normalize(ver)
        print(f"{pkg:<22} {ver:<28} {c.version:<26} {c.extra_version}")


# ─────────────────────────────────────────────────────────────
#  CLI entry point
# ─────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="openwrt_version_normalizer",
        description=(
            "Normalize OpenWrt package version strings into stable (Version) "
            "and volatile (ExtraVersion) components.\n\n"
            "Run with no arguments to see a built-in demo.\n"
            "Pass a .csv file to process a file.  "
            "Pass raw version strings to parse them directly."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "CSV file requirements\n"
            "─────────────────────\n"
            "  • Must contain a header row.\n"
            "  • Header must include 'PkgName' and 'version' columns\n"
            "    (case-insensitive; aliases: package/pkg for name, ver for version).\n"
            "  • Columns may appear in any order.\n\n"
            "Examples\n"
            "────────\n"
            "  # Process a CSV file (output auto-named)\n"
            "  python openwrt_version_normalizer.py packages.csv\n\n"
            "  # Process a CSV file with explicit output path\n"
            "  python openwrt_version_normalizer.py packages.csv -o out.csv\n\n"
            "  # Parse raw version strings\n"
            "  python openwrt_version_normalizer.py 1-r0-45c8168a 2021-07-18-bc9d317f-3\n"
        ),
    )
    p.add_argument(
        "input",
        nargs="*",
        metavar="FILE_OR_VERSION",
        help=(
            "A CSV file path (must end in .csv) OR one or more raw version "
            "strings to parse. Omit entirely to run the built-in demo."
        ),
    )
    p.add_argument(
        "-o", "--output",
        metavar="OUTPUT_CSV",
        default=None,
        help="Output CSV file path (only used when processing a CSV file).",
    )
    p.add_argument(
        "-d", "--delimiter",
        metavar="CHAR",
        default=",",
        help="CSV field delimiter (default: comma).",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    # ── No arguments: run built-in demo ───────────────────────
    if not args.input:
        _demo()
        return 0

    # ── Single argument ending in .csv: file mode ─────────────
    if len(args.input) == 1 and args.input[0].lower().endswith(".csv"):
        input_path = Path(args.input[0])
        try:
            output_path = normalize_csv_file(
                input_path,
                output_path=args.output,
                delimiter=args.delimiter,
            )
        except FileNotFoundError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

        # Print a summary table to stdout
        result_text = output_path.read_text(encoding="utf-8")
        reader      = csv.reader(io.StringIO(result_text))
        rows        = list(reader)

        if rows:
            col_widths = [max(len(str(row[c])) for row in rows) for c in range(len(rows[0]))]
            sep        = "  ".join("-" * w for w in col_widths)
            for i, row in enumerate(rows):
                line = "  ".join(str(cell).ljust(col_widths[j]) for j, cell in enumerate(row))
                print(line)
                if i == 0:
                    print(sep)

        print(f"\nOutput written to: {output_path}")
        return 0

    # ── Multiple arguments (or single non-.csv): version strings ─
    for arg in args.input:
        c = normalize(arg)
        print(f"Input        : {c.original}")
        print(f"Version      : {c.version}")
        print(f"ExtraVersion : {c.extra_version if c.extra_version else '(none)'}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())

