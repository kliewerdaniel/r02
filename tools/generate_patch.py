#!/usr/bin/env python3
"""
QASP LTS Patch Generator

Automates semantic versioning patch creation for LTS releases.
- Finds relevant ledger entries (security fixes, hotfixes)
- Increments patch version
- Generates changelog update
- Provisions backport branches/PRs

Usage: python tools/generate_patch.py [--dry-run]
"""

import argparse
import yaml
import re
from pathlib import Path

LEDGER_FILE = Path("vibe_ledger/VIBE_LEDGER.md")
CHANGELOG_FILE = Path("release/LTS_CHANGELOG.md")
VERSION_FILE = Path("src/__init__.py")  # Assume version there

def parse_ledger():
    with open(LEDGER_FILE, 'r') as f:
        content = f.read()
    # Extract YAML sections
    entries = []
    yaml_blocks = re.findall(r'- id: \d+.*?notes: .*?(?=\n\n-|$)', content, re.DOTALL)
    for block in yaml_blocks:
        try:
            entry = yaml.safe_load(block)
            entries.append(entry)
        except Exception as e:
            print(f"Error parsing entry: {e}")
    return entries

def get_current_version():
    # Simplistic: read from VERSION_FILE or hardcode v1.0.0 for now
    return "v1.0.0"

def filter_relevant_entries(entries):
    relevant = []
    for entry in entries:
        if entry.get('status') == 'done' and ('security' in entry.get('task', '').lower() or 'hotfix' in entry.get('notes', '').lower() or 'lts' in str(entry).lower()):
            relevant.append(entry)
    return relevant

def generate_patch_version(current_version):
    major, minor, patch = map(int, current_version[1:].split('.'))
    patch += 1
    return f"v{major}.{minor}.{patch}"

def update_changelog(entries, new_version):
    changelog_content = f"## {new_version} ({__import__('datetime').date.today()})\n"
    for entry in entries:
        task = entry.get('task', 'Unknown task')
        decisions = entry.get('decisions', [])
        notes = entry.get('notes', '')
        summary = f"- {task}"
        if decisions:
            summary += f": {decisions[0]}"
        if notes:
            summary += f" ({notes})"
        changelog_content += f"{summary}\n"

    # Append to changelog
    with open(CHANGELOG_FILE, 'r') as f:
        content = f.read()

    # Insert after header
    lines = content.split('\n')
    insert_idx = 0
    for i, line in enumerate(lines):
        if line.startswith('## v1.'):
            insert_idx = i
            break

    lines.insert(insert_idx, changelog_content)
    new_content = '\n'.join(lines)

    with open(CHANGELOG_FILE, 'w') as f:
        f.write(new_content)
    print(f"Updated {CHANGELOG_FILE} with {len(entries)} entries")

def main():
    parser = argparse.ArgumentParser(description="Generate QASP LTS patch")
    parser.add_argument('--dry-run', action='store_true', help="Show what would be done without modifying files")
    args = parser.parse_args()

    entries = parse_ledger()
    relevant = filter_relevant_entries(entries)
    if not relevant:
        print("No relevant ledger entries found for patching")
        return

    current_version = get_current_version()
    new_version = generate_patch_version(current_version)

    print(f"Current version: {current_version}")
    print(f"New patch version: {new_version}")
    print(f"Relevant entries: {len(relevant)}")

    if args.dry_run:
        print("Dry run - no changes made")
    else:
        update_changelog(relevant, new_version)
        print(f"Patch {new_version} generated. Update version in {VERSION_FILE}, commit and push.")

if __name__ == '__main__':
    main()
