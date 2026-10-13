#!/usr/bin/env python3
"""
Compare two BloodHound CE JSON output sets for enumeration completeness.

Usage:
    python3 compare_output.py <original_dir> <original_prefix> <modified_dir> <modified_prefix>

Example:
    python3 compare_output.py \
        /home/kali/bloodhound-ce-original original_test_20261012235742 \
        /home/kali/bloodhound-ce-throttled_other modified_test_20261013001047
"""
import json
import os
import sys
import glob


TYPES = ['users', 'groups', 'computers', 'containers', 'gpos', 'ous', 'domains']


def find_files(directory, prefix, obj_type):
    """Find the main file and any rotated parts (_01, _02, ...) for a type."""
    base = os.path.join(directory, '%s_%s.json' % (prefix, obj_type))
    files = []
    if os.path.isfile(base):
        files.append(base)
    idx = 1
    while True:
        part = os.path.join(directory, '%s_%s_%02d.json' % (prefix, obj_type, idx))
        if not os.path.isfile(part):
            break
        files.append(part)
        idx += 1
    return files


def load_objects(files):
    """Load all data entries from one or more BloodHound JSON files."""
    entries = []
    for path in files:
        with open(path, 'r', encoding='utf-8') as f:
            payload = json.load(f)
        entries.extend(payload.get('data') or [])
    return entries


def extract_ids(entries):
    """Extract (objectid, name) pairs from entries."""
    result = {}
    for entry in entries:
        props = entry.get('Properties') or {}
        oid = props.get('objectid') or props.get('objectsid', '')
        name = props.get('name', props.get('distinguishedname', '(unknown)'))
        if oid:
            result[oid] = name
    return result


def main():
    if len(sys.argv) != 5:
        print(__doc__.strip())
        sys.exit(1)

    orig_dir, orig_prefix, mod_dir, mod_prefix = sys.argv[1:5]

    print('=' * 72)
    print('BloodHound Output Comparison')
    print('=' * 72)
    print('Original : %s/%s_*.json' % (orig_dir, orig_prefix))
    print('Modified : %s/%s_*.json' % (mod_dir, mod_prefix))
    print()

    all_match = True

    for obj_type in TYPES:
        orig_files = find_files(orig_dir, orig_prefix, obj_type)
        mod_files = find_files(mod_dir, mod_prefix, obj_type)

        if not orig_files:
            print('[%s] SKIP - no original files found' % obj_type)
            continue
        if not mod_files:
            print('[%s] SKIP - no modified files found' % obj_type)
            continue

        print('-' * 72)
        print('[%s]' % obj_type)
        print('  Original files: %s' % ', '.join(os.path.basename(f) for f in orig_files))
        print('  Modified files: %s' % ', '.join(os.path.basename(f) for f in mod_files))

        orig_entries = load_objects(orig_files)
        mod_entries = load_objects(mod_files)

        print('  Original count: %d' % len(orig_entries))
        print('  Modified count: %d' % len(mod_entries))

        orig_ids = extract_ids(orig_entries)
        mod_ids = extract_ids(mod_entries)

        orig_set = set(orig_ids.keys())
        mod_set = set(mod_ids.keys())

        common = orig_set & mod_set
        only_orig = orig_set - mod_set
        only_mod = mod_set - orig_set

        print('  Unique IDs - original: %d, modified: %d, common: %d' % (
            len(orig_set), len(mod_set), len(common)))

        if only_orig:
            all_match = False
            print('  MISSING from modified (%d):' % len(only_orig))
            for oid in sorted(only_orig):
                print('    %s  (%s)' % (oid, orig_ids[oid]))
        if only_mod:
            all_match = False
            print('  EXTRA in modified (%d):' % len(only_mod))
            for oid in sorted(only_mod):
                print('    %s  (%s)' % (oid, mod_ids[oid]))

        if not only_orig and not only_mod:
            print('  MATCH')

        # Check for duplicates
        if len(orig_entries) != len(orig_set):
            print('  WARNING: original has %d duplicate IDs' % (len(orig_entries) - len(orig_set)))
        if len(mod_entries) != len(mod_set):
            print('  WARNING: modified has %d duplicate IDs' % (len(mod_entries) - len(mod_set)))

        print()

    print('=' * 72)
    if all_match:
        print('RESULT: ALL TYPES MATCH - enumeration is complete')
    else:
        print('RESULT: DIFFERENCES FOUND - see details above')
    print('=' * 72)


if __name__ == '__main__':
    main()
