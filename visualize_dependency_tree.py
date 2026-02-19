#!/usr/bin/env python3
"""
CLI utility to visualize package dependencies as an interactive tree.

Parses the dependencies section of sbom.json and generates an interactive
HTML tree where clicking a package reveals its dependencies.
"""

import argparse
import json
import re
import sys
from pathlib import Path


def extract_package_name(purl: str) -> str:
    """Extract package name from a PURL string."""
    match = re.match(r'pkg:[^/]+/([^@]+)@', purl)
    if match:
        return match.group(1)
    match = re.match(r'pkg:[^/]+/([^@?]+)', purl)
    if match:
        return match.group(1)
    return purl


def load_dependencies(sbom_path: Path) -> dict:
    """Load dependencies and build a lookup dict."""
    with open(sbom_path, 'r') as f:
        sbom = json.load(f)

    if 'dependencies' not in sbom:
        raise ValueError(f"No 'dependencies' section found in {sbom_path}")

    # Build dependency lookup: package_name -> [dependency_names]
    dep_map = {}
    all_packages = set()

    for dep_entry in sbom['dependencies']:
        ref = dep_entry.get('ref', '')

        # Skip firmware and generic entries
        if ref.startswith('pkg:firmware/') or ref.startswith('pkg:generic/'):
            continue

        ref_name = extract_package_name(ref)
        depends_on = dep_entry.get('dependsOn', [])

        dep_names = []
        for dep_purl in depends_on:
            if dep_purl.startswith('pkg:firmware/') or dep_purl.startswith('pkg:generic/'):
                continue
            dep_name = extract_package_name(dep_purl)
            dep_names.append(dep_name)
            all_packages.add(dep_name)

        dep_map[ref_name] = sorted(dep_names)
        all_packages.add(ref_name)

    return dep_map, sorted(all_packages)


def should_exclude(name: str, trim: bool) -> bool:
    """Check if a package should be excluded based on trim rules."""
    if not trim:
        return False
    # Exclude "openwrt", "libc", and all "kmod-*" packages
    if name in ('openwrt', 'libc'):
        return True
    if name.startswith('kmod-'):
        return True
    return False


def filter_dependencies(dep_map: dict, all_packages: list, trim: bool) -> tuple:
    """Filter out excluded packages."""
    if not trim:
        return dep_map, all_packages

    filtered_map = {}
    filtered_packages = set()

    for pkg, deps in dep_map.items():
        if should_exclude(pkg, trim):
            continue
        filtered_deps = [d for d in deps if not should_exclude(d, trim)]
        filtered_map[pkg] = filtered_deps
        filtered_packages.add(pkg)
        filtered_packages.update(filtered_deps)

    return filtered_map, sorted(filtered_packages)


def generate_html(dep_map: dict, all_packages: list, output_path: Path) -> None:
    """Generate interactive HTML tree."""

    # Convert dep_map to JSON for JavaScript
    dep_map_json = json.dumps(dep_map)

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Package Dependency Tree</title>
    <style>
        * {{
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f6fa;
            color: #2c3e50;
        }}
        h1 {{
            color: #2c3e50;
            margin-bottom: 5px;
        }}
        .subtitle {{
            color: #7f8c8d;
            margin-bottom: 20px;
        }}
        .container {{
            display: flex;
            gap: 20px;
            height: calc(100vh - 120px);
        }}
        .panel {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }}
        .package-list-panel {{
            width: 280px;
            flex-shrink: 0;
        }}
        .tree-panel {{
            flex: 1;
        }}
        .panel-header {{
            background: #3498db;
            color: white;
            padding: 12px 15px;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .panel-content {{
            padding: 10px;
            overflow-y: auto;
            flex: 1;
        }}
        .search-box {{
            padding: 10px;
            border-bottom: 1px solid #ecf0f1;
        }}
        .search-box input {{
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            outline: none;
        }}
        .search-box input:focus {{
            border-color: #3498db;
        }}
        .package-item {{
            padding: 8px 12px;
            cursor: pointer;
            border-radius: 4px;
            margin: 2px 0;
            transition: background 0.2s;
        }}
        .package-item:hover {{
            background: #ecf0f1;
        }}
        .package-item.selected {{
            background: #3498db;
            color: white;
        }}
        .package-item .dep-count {{
            float: right;
            background: #ecf0f1;
            color: #7f8c8d;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
        }}
        .package-item.selected .dep-count {{
            background: rgba(255,255,255,0.3);
            color: white;
        }}
        .breadcrumb {{
            padding: 10px 15px;
            background: #ecf0f1;
            border-bottom: 1px solid #ddd;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 5px;
        }}
        .breadcrumb-item {{
            color: #3498db;
            cursor: pointer;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        .breadcrumb-item:hover {{
            background: #d5dbdb;
        }}
        .breadcrumb-separator {{
            color: #95a5a6;
        }}
        .breadcrumb-current {{
            color: #2c3e50;
            font-weight: bold;
            padding: 4px 8px;
        }}
        .tree-node {{
            margin: 5px 0;
        }}
        .tree-label {{
            display: inline-flex;
            align-items: center;
            padding: 8px 12px;
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .tree-label:hover {{
            border-color: #3498db;
            box-shadow: 0 2px 5px rgba(52,152,219,0.2);
        }}
        .tree-label.has-deps {{
            border-left: 3px solid #3498db;
        }}
        .tree-label.no-deps {{
            border-left: 3px solid #95a5a6;
            color: #7f8c8d;
        }}
        .tree-label .icon {{
            margin-right: 8px;
            font-size: 12px;
            width: 16px;
            text-align: center;
        }}
        .tree-label.expanded .icon {{
            color: #e74c3c;
        }}
        .tree-children {{
            margin-left: 25px;
            padding-left: 15px;
            border-left: 2px solid #ecf0f1;
        }}
        .tree-children.hidden {{
            display: none;
        }}
        .empty-state {{
            text-align: center;
            padding: 40px;
            color: #95a5a6;
        }}
        .empty-state .icon {{
            font-size: 48px;
            margin-bottom: 10px;
        }}
        .stats {{
            font-size: 12px;
            color: rgba(255,255,255,0.8);
        }}
        .back-btn {{
            background: rgba(255,255,255,0.2);
            border: none;
            color: white;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }}
        .back-btn:hover {{
            background: rgba(255,255,255,0.3);
        }}
        .home-btn {{
            background: #e74c3c;
            border: none;
            color: white;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-left: 10px;
        }}
        .home-btn:hover {{
            background: #c0392b;
        }}
    </style>
</head>
<body>
    <h1>Package Dependency Tree</h1>
    <p class="subtitle">Click a package to explore its dependencies. Click dependencies to drill down.</p>

    <div class="container">
        <div class="panel package-list-panel">
            <div class="panel-header">
                <span>Packages</span>
                <span class="stats" id="package-count"></span>
            </div>
            <div class="search-box">
                <input type="text" id="package-search" placeholder="Filter packages..." onkeyup="filterPackages()">
            </div>
            <div class="panel-content" id="package-list"></div>
        </div>

        <div class="panel tree-panel">
            <div class="panel-header">
                <span>Dependency Tree</span>
                <div>
                    <button class="back-btn" onclick="expandAll()" id="expand-btn" style="display:none;">Expand All</button>
                    <button class="back-btn" onclick="collapseAll()" id="collapse-btn" style="display:none;">Collapse All</button>
                    <button class="home-btn" onclick="goHome()" id="home-btn" style="display:none;">Reset</button>
                </div>
            </div>
            <div class="breadcrumb" id="breadcrumb" style="display:none;"></div>
            <div class="panel-content" id="tree-view">
                <div class="empty-state">
                    <div class="icon">📦</div>
                    <div>Select a package from the list to view its dependencies</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const depMap = {dep_map_json};
        const allPackages = {json.dumps(all_packages)};

        let selectedPackage = null;
        let expandedNodes = new Set();  // Track expanded nodes by path

        function init() {{
            document.getElementById('package-count').textContent = allPackages.length + ' packages';
            renderPackageList(allPackages);
        }}

        function renderPackageList(packages) {{
            const container = document.getElementById('package-list');
            container.innerHTML = packages.map(pkg => {{
                const depCount = (depMap[pkg] || []).length;
                const selectedClass = pkg === selectedPackage ? 'selected' : '';
                return `<div class="package-item ${{selectedClass}}" onclick="selectPackage('${{pkg}}')">
                    ${{pkg}}
                    <span class="dep-count">${{depCount}}</span>
                </div>`;
            }}).join('');
        }}

        function filterPackages() {{
            const search = document.getElementById('package-search').value.toLowerCase();
            const filtered = allPackages.filter(pkg => pkg.toLowerCase().includes(search));
            renderPackageList(filtered);
        }}

        function selectPackage(pkg) {{
            selectedPackage = pkg;
            expandedNodes.clear();  // Reset expanded state for new package
            filterPackages();
            renderTree();
        }}

        function renderTree() {{
            const container = document.getElementById('tree-view');
            const breadcrumb = document.getElementById('breadcrumb');
            const expandBtn = document.getElementById('expand-btn');
            const collapseBtn = document.getElementById('collapse-btn');
            const homeBtn = document.getElementById('home-btn');

            if (!selectedPackage) {{
                container.innerHTML = `<div class="empty-state">
                    <div class="icon">📦</div>
                    <div>Select a package from the list to view its dependencies</div>
                </div>`;
                breadcrumb.style.display = 'none';
                expandBtn.style.display = 'none';
                collapseBtn.style.display = 'none';
                homeBtn.style.display = 'none';
                return;
            }}

            // Show header info
            breadcrumb.style.display = 'flex';
            breadcrumb.innerHTML = `<span class="breadcrumb-current">${{selectedPackage}}</span>
                <span style="margin-left:10px;color:#7f8c8d;font-size:12px;">
                    (click branches to expand/collapse)
                </span>`;
            expandBtn.style.display = 'inline-block';
            collapseBtn.style.display = 'inline-block';
            homeBtn.style.display = 'inline-block';

            const deps = depMap[selectedPackage] || [];

            if (deps.length === 0) {{
                container.innerHTML = `<div class="empty-state">
                    <div class="icon">🍃</div>
                    <div><strong>${{selectedPackage}}</strong> has no dependencies</div>
                </div>`;
                return;
            }}

            // Render the full tree starting from the root package
            let html = `<div style="margin-bottom:10px;color:#7f8c8d;">
                <strong>${{selectedPackage}}</strong> depends on ${{deps.length}} package(s):
            </div>`;

            html += renderSubtree(deps, selectedPackage, new Set());
            container.innerHTML = html;
        }}

        function renderSubtree(deps, parentPath, visited) {{
            let html = '';

            deps.forEach(dep => {{
                const nodePath = parentPath + '>' + dep;
                const depDeps = depMap[dep] || [];
                const hasDeps = depDeps.length > 0;
                const isExpanded = expandedNodes.has(nodePath);
                const isCircular = visited.has(dep);

                let labelClass = hasDeps ? 'has-deps' : 'no-deps';
                if (isExpanded) labelClass += ' expanded';

                let icon = '•';
                if (hasDeps && !isCircular) {{
                    icon = isExpanded ? '▼' : '▶';
                }} else if (isCircular) {{
                    icon = '↻';
                }}

                const circularNote = isCircular ? '<span style="margin-left:10px;color:#e74c3c;font-size:11px;">(circular)</span>' : '';
                const depCountNote = (hasDeps && !isCircular) ? `<span style="margin-left:10px;color:#95a5a6;font-size:11px;">(${{depDeps.length}} deps)</span>` : '';

                html += `<div class="tree-node">
                    <div class="tree-label ${{labelClass}}" onclick="toggleNode('${{nodePath.replace(/'/g, "\\'")}}')"  >
                        <span class="icon">${{icon}}</span>
                        ${{dep}}
                        ${{depCountNote}}
                        ${{circularNote}}
                    </div>`;

                // Render children if expanded and not circular
                if (isExpanded && hasDeps && !isCircular) {{
                    const newVisited = new Set(visited);
                    newVisited.add(dep);
                    html += `<div class="tree-children">`;
                    html += renderSubtree(depDeps, nodePath, newVisited);
                    html += `</div>`;
                }}

                html += `</div>`;
            }});

            return html;
        }}

        function toggleNode(nodePath) {{
            if (expandedNodes.has(nodePath)) {{
                // Collapse: remove this node and all children
                const toRemove = [];
                expandedNodes.forEach(path => {{
                    if (path === nodePath || path.startsWith(nodePath + '>')) {{
                        toRemove.push(path);
                    }}
                }});
                toRemove.forEach(path => expandedNodes.delete(path));
            }} else {{
                expandedNodes.add(nodePath);
            }}
            renderTree();
        }}

        function expandAll() {{
            // Recursively expand all nodes
            function expandRecursive(deps, parentPath, visited) {{
                deps.forEach(dep => {{
                    if (visited.has(dep)) return;  // Skip circular
                    const nodePath = parentPath + '>' + dep;
                    const depDeps = depMap[dep] || [];
                    if (depDeps.length > 0) {{
                        expandedNodes.add(nodePath);
                        const newVisited = new Set(visited);
                        newVisited.add(dep);
                        expandRecursive(depDeps, nodePath, newVisited);
                    }}
                }});
            }}

            if (selectedPackage) {{
                const deps = depMap[selectedPackage] || [];
                expandRecursive(deps, selectedPackage, new Set());
                renderTree();
            }}
        }}

        function collapseAll() {{
            expandedNodes.clear();
            renderTree();
        }}

        function goHome() {{
            selectedPackage = null;
            expandedNodes.clear();
            filterPackages();
            renderTree();
        }}

        init();
    </script>
</body>
</html>
'''

    with open(output_path, 'w') as f:
        f.write(html_content)


def main():
    parser = argparse.ArgumentParser(
        description="Visualize package dependencies as an interactive tree"
    )
    parser.add_argument(
        '-i', '--input',
        type=Path,
        default=Path('sbom.json'),
        help='Input SBOM file (default: sbom.json)'
    )
    parser.add_argument(
        '-o', '--output',
        type=Path,
        default=Path('package_dependency_tree.html'),
        help='Output HTML file (default: package_dependency_tree.html)'
    )
    parser.add_argument(
        '--trim',
        action='store_true',
        help='Exclude "openwrt" and all "kmod-*" packages'
    )

    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading SBOM from: {args.input}")

    try:
        dep_map, all_packages = load_dependencies(args.input)
        print(f"Found {len(all_packages)} packages")

        dep_map, all_packages = filter_dependencies(dep_map, all_packages, args.trim)
        if args.trim:
            print(f"After trim: {len(all_packages)} packages")

        generate_html(dep_map, all_packages, args.output)
        print(f"Tree saved to: {args.output}")

    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {args.input}: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
