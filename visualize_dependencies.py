#!/usr/bin/env python3
"""
CLI utility to visualize package dependencies from a CycloneDX SBOM.

Parses the dependencies section of sbom.json, builds a directed graph,
and generates an interactive HTML visualization using pyvis.
"""

import argparse
import json
import re
import sys
from pathlib import Path

import networkx as nx
from pyvis.network import Network


def extract_package_name(purl: str) -> str:
    """
    Extract package name from a PURL string.

    Examples:
        pkg:opkg/arp-scan@1.9.7-1 -> arp-scan
        pkg:generic/linux@5.4.213?... -> linux
        pkg:firmware/explorer-ii@1.0 -> explorer-ii
    """
    # Match pattern: pkg:<type>/<name>@<version>
    match = re.match(r'pkg:[^/]+/([^@]+)@', purl)
    if match:
        return match.group(1)
    # Fallback: try without version
    match = re.match(r'pkg:[^/]+/([^@?]+)', purl)
    if match:
        return match.group(1)
    return purl


def load_dependencies(sbom_path: Path) -> list:
    """Load and return the dependencies section from the SBOM."""
    with open(sbom_path, 'r') as f:
        sbom = json.load(f)

    if 'dependencies' not in sbom:
        raise ValueError(f"No 'dependencies' section found in {sbom_path}")

    return sbom['dependencies']


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


def build_graph(dependencies: list, trim: bool = False) -> nx.DiGraph:
    """
    Build a directed graph from the dependencies list.

    Args:
        dependencies: List of dependency objects from the SBOM
        trim: Exclude 'openwrt' and 'kmod-*' packages

    Returns:
        A NetworkX directed graph
    """
    G = nx.DiGraph()

    for dep_entry in dependencies:
        ref = dep_entry.get('ref', '')
        ref_name = extract_package_name(ref)

        # Skip firmware entries (e.g., "explorer-ii---openwrt21.02-z8106")
        if ref.startswith('pkg:firmware/'):
            continue

        # Skip generic entries (like linux kernel) as root
        if ref.startswith('pkg:generic/'):
            continue

        # Skip excluded packages when trim is enabled
        if should_exclude(ref_name, trim):
            continue

        depends_on = dep_entry.get('dependsOn', [])

        # Add the node
        G.add_node(ref_name)

        # Add edges for dependencies (excluding trimmed packages)
        for dep_purl in depends_on:
            dep_name = extract_package_name(dep_purl)
            if should_exclude(dep_name, trim):
                continue
            G.add_node(dep_name)
            # Edge direction: from package to its dependency
            G.add_edge(ref_name, dep_name)

    return G


def inject_search_ui(output_path: Path) -> None:
    """Inject search UI and JavaScript into the generated HTML file."""
    search_html = '''
    <style>
        #search-container {
            position: fixed;
            top: 10px;
            left: 10px;
            z-index: 1000;
            background: #1a1a1a;
            padding: 10px 15px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.5);
            font-family: Arial, sans-serif;
            border: 1px solid #333;
        }
        #search-input {
            padding: 8px 12px;
            font-size: 14px;
            border: 1px solid #444;
            border-radius: 4px;
            width: 200px;
            outline: none;
            background: #2a2a2a;
            color: #fff;
        }
        #search-input:focus {
            border-color: #3498db;
            box-shadow: 0 0 5px rgba(52,152,219,0.3);
        }
        #search-input::placeholder {
            color: #888;
        }
        #search-btn {
            padding: 8px 15px;
            font-size: 14px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-left: 5px;
        }
        #search-btn:hover {
            background: #2980b9;
        }
        #clear-btn {
            padding: 8px 15px;
            font-size: 14px;
            background: #555;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-left: 5px;
        }
        #clear-btn:hover {
            background: #666;
        }
        #search-results {
            margin-top: 8px;
            font-size: 12px;
            color: #aaa;
            max-height: 150px;
            overflow-y: auto;
        }
        .result-item {
            padding: 4px 8px;
            cursor: pointer;
            border-radius: 3px;
            color: #ddd;
        }
        .result-item:hover {
            background: #333;
        }
        /* Navigation buttons dark mode styling */
        div.vis-network div.vis-navigation div.vis-button {
            background-color: #333 !important;
            border: 1px solid #555 !important;
        }
        div.vis-network div.vis-navigation div.vis-button:hover {
            background-color: #444 !important;
            box-shadow: 0 0 5px #3498db !important;
        }
        div.vis-network div.vis-navigation div.vis-button.vis-up,
        div.vis-network div.vis-navigation div.vis-button.vis-down,
        div.vis-network div.vis-navigation div.vis-button.vis-left,
        div.vis-network div.vis-navigation div.vis-button.vis-right,
        div.vis-network div.vis-navigation div.vis-button.vis-zoomIn,
        div.vis-network div.vis-navigation div.vis-button.vis-zoomOut,
        div.vis-network div.vis-navigation div.vis-button.vis-zoomExtends {
            background-color: #333 !important;
            filter: invert(1) !important;
        }
        div.vis-network div.vis-navigation div.vis-button:active {
            background-color: #3498db !important;
        }
        /* Tooltip styling for dark mode */
        div.vis-tooltip {
            background-color: #1a1a1a !important;
            color: #fff !important;
            border: 1px solid #444 !important;
            border-radius: 4px !important;
            padding: 8px !important;
            font-family: Arial, sans-serif !important;
        }
    </style>
    <div id="search-container">
        <input type="text" id="search-input" placeholder="Search package..." onkeyup="if(event.key==='Enter')searchPackage()">
        <button id="search-btn" onclick="searchPackage()">Search</button>
        <button id="clear-btn" onclick="clearSearch()">Clear</button>
        <div id="search-results"></div>
    </div>
    <script>
        var originalColors = {};
        var originalSizes = {};

        function searchPackage() {
            var searchTerm = document.getElementById('search-input').value.toLowerCase().trim();
            var resultsDiv = document.getElementById('search-results');

            if (!searchTerm) {
                resultsDiv.innerHTML = '';
                return;
            }

            var allNodes = nodes.get();
            var matches = allNodes.filter(function(node) {
                return node.label.toLowerCase().includes(searchTerm);
            });

            if (matches.length === 0) {
                resultsDiv.innerHTML = '<div style="color:#e74c3c;">No packages found</div>';
                return;
            }

            // Show results list
            var html = '<div style="color:#27ae60;margin-bottom:5px;">' + matches.length + ' package(s) found:</div>';
            matches.slice(0, 20).forEach(function(node) {
                html += '<div class="result-item" onclick="focusNode(\\''+node.id+'\\')">'+node.label+'</div>';
            });
            if (matches.length > 20) {
                html += '<div style="color:#999;font-style:italic;">...and ' + (matches.length - 20) + ' more</div>';
            }
            resultsDiv.innerHTML = html;

            // Highlight matching nodes
            highlightNodes(matches.map(function(n) { return n.id; }));

            // Focus on first match
            if (matches.length === 1) {
                focusNode(matches[0].id);
            }
        }

        function highlightNodes(nodeIds) {
            var allNodes = nodes.get();
            var updates = [];

            allNodes.forEach(function(node) {
                if (!originalColors[node.id]) {
                    originalColors[node.id] = node.color;
                    originalSizes[node.id] = node.size;
                }

                if (nodeIds.includes(node.id)) {
                    updates.push({
                        id: node.id,
                        color: '#9b59b6',
                        size: originalSizes[node.id] * 2,
                        borderWidth: 3
                    });
                } else {
                    updates.push({
                        id: node.id,
                        color: '#333',
                        size: originalSizes[node.id] * 0.7
                    });
                }
            });

            nodes.update(updates);
        }

        function focusNode(nodeId) {
            var node = nodes.get(nodeId);
            if (node) {
                network.focus(nodeId, {
                    scale: 1.5,
                    animation: {
                        duration: 500,
                        easingFunction: 'easeInOutQuad'
                    }
                });
                network.selectNodes([nodeId]);
            }
        }

        function clearSearch() {
            document.getElementById('search-input').value = '';
            document.getElementById('search-results').innerHTML = '';

            // Restore original colors and sizes
            var allNodes = nodes.get();
            var updates = [];

            allNodes.forEach(function(node) {
                if (originalColors[node.id]) {
                    updates.push({
                        id: node.id,
                        color: originalColors[node.id],
                        size: originalSizes[node.id],
                        borderWidth: 1
                    });
                }
            });

            nodes.update(updates);
            network.fit();
        }
    </script>
'''

    with open(output_path, 'r') as f:
        html_content = f.read()

    # Insert search UI after <body> tag
    html_content = html_content.replace('<body>', '<body>\n' + search_html)

    with open(output_path, 'w') as f:
        f.write(html_content)


def create_visualization(G: nx.DiGraph, output_path: Path,
                         height: str = "900px", width: str = "100%",
                         physics: bool = True, trim: bool = False) -> None:
    """
    Create an interactive pyvis visualization of the graph.

    Args:
        G: The NetworkX directed graph
        output_path: Path for the output HTML file
        height: Height of the visualization
        width: Width of the visualization
        physics: Enable physics simulation for layout
        trim: Use tighter layout for trimmed graphs
    """
    # Create pyvis network (dark mode)
    net = Network(
        height=height,
        width=width,
        directed=True,
        bgcolor="#000000",
        font_color="#ffffff"
    )

    # Calculate node degrees for sizing
    in_degrees = dict(G.in_degree())
    out_degrees = dict(G.out_degree())

    # Color nodes based on their role
    # High in-degree = many packages depend on this (core library)
    # High out-degree = depends on many packages (application)
    max_in = max(in_degrees.values()) if in_degrees else 1

    for node in G.nodes():
        in_deg = in_degrees.get(node, 0)
        out_deg = out_degrees.get(node, 0)

        # Size based on importance (in-degree)
        size = 5 + (in_deg / max_in) * 20 if max_in > 0 else 8

        # Color coding (high contrast for dark mode):
        # - Red/Orange: High in-degree (core dependencies like libc)
        # - Blue: High out-degree (applications with many deps)
        # - Green: Leaf nodes (no dependents)
        if in_deg > 20:
            color = "#ff4757"  # Bright red - critical dependency
        elif in_deg > 5:
            color = "#ffa502"  # Bright orange - important dependency
        elif out_deg > 10:
            color = "#3498db"  # Blue - complex package
        elif in_deg == 0:
            color = "#2ecc71"  # Bright green - leaf/application
        else:
            color = "#a0a0a0"  # Light gray - intermediate

        title = f"{node}\nDepended on by: {in_deg} packages\nDepends on: {out_deg} packages"

        net.add_node(node, label=node, size=size, color=color, title=title)

    # Add edges
    for source, target in G.edges():
        net.add_edge(source, target, arrows='to')

    # Configure physics and options
    # Use tighter layout when trimmed (fewer nodes)
    if trim:
        gravity = -8000
        central_gravity = 0.3
        spring_length = 120
        spring_constant = 0.04
    else:
        gravity = -15000
        central_gravity = 0.1
        spring_length = 300
        spring_constant = 0.02

    net.set_options("""
    {
        "nodes": {
            "font": {
                "size": 10,
                "face": "arial"
            },
            "borderWidth": 1,
            "shadow": false
        },
        "edges": {
            "color": {
                "inherit": false,
                "color": "#444444",
                "highlight": "#3498db"
            },
            "smooth": {
                "type": "continuous",
                "forceDirection": "none"
            },
            "arrows": {
                "to": {
                    "enabled": true,
                    "scaleFactor": 0.5
                }
            }
        },
        "physics": {
            "enabled": %s,
            "barnesHut": {
                "gravitationalConstant": %d,
                "centralGravity": %s,
                "springLength": %d,
                "springConstant": %s,
                "damping": 0.09,
                "avoidOverlap": 0.5
            },
            "stabilization": {
                "enabled": true,
                "iterations": 1500,
                "updateInterval": 25
            }
        },
        "interaction": {
            "hover": true,
            "tooltipDelay": 200,
            "navigationButtons": true,
            "keyboard": {
                "enabled": true
            }
        }
    }
    """ % (str(physics).lower(), gravity, central_gravity, spring_length, spring_constant))

    # Save the visualization
    net.save_graph(str(output_path))

    # Inject search UI into the HTML
    inject_search_ui(output_path)

    print(f"Graph saved to: {output_path}")


def print_stats(G: nx.DiGraph) -> None:
    """Print statistics about the dependency graph."""
    print("\n=== Dependency Graph Statistics ===")
    print(f"Total packages (nodes): {G.number_of_nodes()}")
    print(f"Total dependencies (edges): {G.number_of_edges()}")

    # Most depended upon packages
    in_degrees = sorted(G.in_degree(), key=lambda x: x[1], reverse=True)
    print("\nTop 10 most depended-upon packages:")
    for name, degree in in_degrees[:10]:
        print(f"  {name}: {degree} dependents")

    # Packages with most dependencies
    out_degrees = sorted(G.out_degree(), key=lambda x: x[1], reverse=True)
    print("\nTop 10 packages with most dependencies:")
    for name, degree in out_degrees[:10]:
        print(f"  {name}: {degree} dependencies")

    # Leaf nodes (no dependents)
    leaves = [n for n, d in G.in_degree() if d == 0]
    print(f"\nLeaf packages (no dependents): {len(leaves)}")


def main():
    parser = argparse.ArgumentParser(
        description="Visualize package dependencies from a CycloneDX SBOM"
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
        default=Path('package_dependancy_graph.html'),
        help='Output HTML file (default: package_dependancy_graph.html)'
    )
    parser.add_argument(
        '--no-physics',
        action='store_true',
        help='Disable physics simulation (static layout)'
    )
    parser.add_argument(
        '--height',
        type=str,
        default='900px',
        help='Height of the visualization (default: 900px)'
    )
    parser.add_argument(
        '--width',
        type=str,
        default='100%%',
        help='Width of the visualization (default: 100%%)'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Print dependency statistics'
    )
    parser.add_argument(
        '--trim',
        action='store_true',
        help='Exclude "openwrt", "libc", and all "kmod-*" packages'
    )

    args = parser.parse_args()

    # Validate input file
    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading SBOM from: {args.input}")

    try:
        dependencies = load_dependencies(args.input)
        print(f"Found {len(dependencies)} dependency entries")

        G = build_graph(dependencies, trim=args.trim)
        print(f"Built graph with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
        if args.trim:
            print("(trimmed: excluded 'openwrt', 'libc', and 'kmod-*' packages)")

        if args.stats:
            print_stats(G)

        create_visualization(
            G,
            args.output,
            height=args.height,
            width=args.width,
            physics=not args.no_physics,
            trim=args.trim
        )

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
