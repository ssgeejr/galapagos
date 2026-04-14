#!/usr/bin/env python3
"""
KEV Lookup Helper Script
Compares KEV JSON files and generates summary.
"""

import json
import os
import sys
from datetime import datetime

BASE_DIR = "/opt/apps/kevctem"

def get_today_date():
    return datetime.now().strftime("%m%d%Y")

def load_json(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

def get_previous_kev_file(exclude_file):
    """Find the most recent kev-*.json file excluding the specified one."""
    files = [f for f in os.listdir(BASE_DIR) if f.startswith('kev-') and f.endswith('.json')]
    if not files:
        return None
    # Sort by date in filename
    files.sort(key=lambda x: x[4:12], reverse=True)
    for f in files:
        if os.path.join(BASE_DIR, f) != exclude_file:
            return os.path.join(BASE_DIR, f)
    return None

def compare_kevs(old_file, new_file):
    """Compare two KEV JSON files."""
    old_data = load_json(old_file)
    new_data = load_json(new_file)
    
    old_cves = {v['cveID']: v for v in old_data['vulnerabilities']}
    new_cves = {v['cveID']: v for v in new_data['vulnerabilities']}
    
    new_entries = [v for cve, v in new_cves.items() if cve not in old_cves]
    removed = [v for cve, v in old_cves.items() if cve not in new_cves]
    updated = []
    
    for cve, v in new_cves.items():
        if cve in old_cves:
            if v['dateAdded'] != old_cves[cve]['dateAdded'] or \
               v['requiredAction'] != old_cves[cve]['requiredAction'] or \
               v['dueDate'] != old_cves[cve]['dueDate']:
                updated.append((old_cves[cve], v))
    
    return {
        'old_count': len(old_cves),
        'new_count': len(new_cves),
        'new_entries': new_entries,
        'removed': removed,
        'updated': updated
    }

def get_vuln_type(vuln_name):
    """Extract vulnerability type from name."""
    if 'Code Injection' in vuln_name:
        return 'Code Injection'
    elif 'Buffer Overflow' in vuln_name:
        return 'Buffer Overflow'
    elif 'Deserialization' in vuln_name:
        return 'Deserialization'
    elif 'XSS' in vuln_name:
        return 'XSS'
    elif 'Information Disclosure' in vuln_name:
        return 'Info Disclosure'
    elif 'Improper Locking' in vuln_name:
        return 'Improper Locking'
    elif 'Out-of-Bounds' in vuln_name:
        return 'Out-of-Bounds'
    elif 'Memory' in vuln_name:
        return 'Memory'
    else:
        return vuln_name.split()[-1] if vuln_name else 'N/A'

def generate_markdown_summary(data, today_date):
    """Generate markdown summary."""
    lines = [
        f"# KEV Summary - {today_date}",
        "",
        f"**Old Count:** {data['old_count']}",
        f"**New Count:** {data['new_count']}",
        f"**New Entries:** {len(data['new_entries'])}",
        f"**Removed:** {len(data['removed'])}",
        f"**Updated:** {len(data['updated'])}",
        ""
    ]
    
    if data['new_entries']:
        lines.append(f"## New CVEs Added ({today_date})")
        lines.append("")
        lines.append("| CVE | Vendor | Product | Vulnerability Type |")
        lines.append("|-----|--------|---------|-------------------|")
        for v in data['new_entries']:
            vuln_type = get_vuln_type(v['vulnerabilityName'])
            lines.append(f"| {v['cveID']} | {v['vendorProject']} | {v['product']} | {vuln_type} |")
        lines.append("")
    
    if data['removed']:
        lines.append("## CVEs Removed")
        lines.append("")
        for v in data['removed']:
            lines.append(f"- {v['cveID']} - {v['vendorProject']} - {v['product']}")
        lines.append("")
    
    if data['updated']:
        lines.append("## CVEs Updated")
        lines.append("")
        for old, new in data['updated']:
            lines.append(f"- {new['cveID']} - Changes in dueDate/requiredAction")
        lines.append("")
    
    return "\n".join(lines)

def print_diff(old_file, new_file):
    """Print unified diff to stdout."""
    with open(old_file) as f:
        old_obj = json.load(f)
    with open(new_file) as f:
        new_obj = json.load(f)
    
    old_str = json.dumps(old_obj, indent=2, sort_keys=True)
    new_str = json.dumps(new_obj, indent=2, sort_keys=True)
    
    import difflib
    diff_lines = list(difflib.unified_diff(
        old_str.splitlines(keepends=True),
        new_str.splitlines(keepends=True),
        fromfile='old',
        tofile='new',
        lineterm=''
    ))
    
    # Print first 100 diff lines (no colors to avoid escape code issues)
    for line in diff_lines[:100]:
        print(line.rstrip())
    
    if len(diff_lines) > 100:
        print(f"\n... and {len(diff_lines) - 100} more diff lines")

def main():
    today = get_today_date()
    new_file = f"{BASE_DIR}/kev-{today}.json"
    
    # Download latest KEV
    print(f"Downloading latest KEV JSON...")
    import subprocess
    result = subprocess.run([
        "curl", "-s", 
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "-o", new_file
    ], capture_output=True)
    
    if result.returncode != 0:
        print(f"Error downloading KEV: {result.stderr.decode()}")
        sys.exit(1)
    
    print(f"Saved: {new_file}")
    
    # Get previous file (excluding the one we just downloaded)
    prev_file = get_previous_kev_file(new_file)
    
    if prev_file is None:
        print("No previous KEV file found. This is first run.")
        data = load_json(new_file)
        print(f"Total CVEs: {data['count']}")
        return
    
    print(f"Comparing with: {prev_file}")
    
    # Compare
    result = compare_kevs(prev_file, new_file)
    
    # Print summary
    print("\n" + "="*60)
    print("KEV COMPARISON SUMMARY")
    print("="*60)
    print(f"Old Count: {result['old_count']}")
    print(f"New Count: {result['new_count']}")
    print(f"New Entries: {len(result['new_entries'])}")
    print(f"Removed: {len(result['removed'])}")
    print(f"Updated: {len(result['updated'])}")
    
    # Print full diff
    print("\n" + "="*60)
    print("FULL DIFF (new vs old)")
    print("="*60)
    print_diff(prev_file, new_file)
    
    # Print CVE table to console
    if result['new_entries']:
        print("\n" + "="*60)
        print("NEW CVEs ADDED")
        print("="*60)
        print("| CVE | Vendor | Product | Vulnerability Type |")
        print("|-----|--------|---------|-------------------|")
        for v in result['new_entries']:
            vuln_type = get_vuln_type(v['vulnerabilityName'])
            print(f"| {v['cveID']} | {v['vendorProject']} | {v['product']} | {vuln_type} |")
    
    # Save markdown summary
    md_content = generate_markdown_summary(result, today)
    md_file = f"{BASE_DIR}/kev-summary-{today}.md"
    with open(md_file, 'w') as f:
        f.write(md_content)
    print(f"\nSaved summary to: {md_file}")
    
    print("\n" + "="*60)
    if len(result['new_entries']) == 0:
        print("No new KEVs today.")
    else:
        print("Run `cat kev-summary-*.md` to see full details.")

if __name__ == "__main__":
    main()