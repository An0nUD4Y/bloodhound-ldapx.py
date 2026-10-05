####################
#
# Copyright (c) 2018 Fox-IT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################
import datetime
import json
import logging
import os
import time

from bloodhound.ad.utils import CollectionException


def checkpoint_path(prefix):
    """
    Path of the resume file for this output prefix.
    """
    if prefix:
        return prefix + '_resume.json'
    return 'bloodhound_resume.json'


def output_filename(prefix, timestamp, basename):
    """
    BloodHound JSON path. An empty prefix matches the historical naming.
    """
    if prefix:
        return prefix + '_' + timestamp + basename
    return timestamp + basename


def guid_filter(search_filter, guid_prefix):
    """
    AND an objectGUID prefix slice onto a search filter. The backslash is an
    LDAP hex escape and must be sent with auto_escape disabled.
    """
    if not guid_prefix:
        return search_filter
    return '(&%s(objectGUID=\\%s*))' % (search_filter, guid_prefix)


GUID_SLICES = ['%02x' % i for i in range(256)]


def slice_output_path(filename, prefix):
    return '%s.%s' % (filename, prefix)


def remove_output(path):
    for name in (path, path + '.partial'):
        try:
            os.remove(name)
        except OSError:
            pass


def concat_slice_files(filename, meta_type, paths, extra_rows=None):
    """
    Join finished slice files and any extra objects into the phase JSON file.
    """
    rows = []
    for path in paths:
        with open(path, 'r', encoding='utf-8') as handle:
            payload = json.load(handle)
        rows.extend(payload.get('data') or [])
    rows.extend(extra_rows or [])
    payload = {
        'data': rows,
        'meta': {
            'methods': 0,
            'type': meta_type,
            'count': len(rows),
            'version': 6,
        },
    }
    partial = filename + '.partial'
    with open(partial, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle)
        handle.flush()
        try:
            os.fsync(handle.fileno())
        except OSError:
            pass
    os.replace(partial, filename)
    """
    BloodHound JSON path. An empty prefix matches the historical naming.
    """
    if prefix:
        return prefix + '_' + timestamp + basename
    return timestamp + basename


def _stem(filename):
    if filename.endswith('.json'):
        return filename[:-len('.json')]
    return filename


def phase_part_paths(filename):
    """
    The finished file plus any rotated _01, _02, ... parts that exist.
    """
    paths = [filename]
    stem = _stem(filename)
    number = 1
    while True:
        part = '%s_%02d.json' % (stem, number)
        if not os.path.isfile(part):
            break
        paths.append(part)
        number += 1
    return paths


def _load_output(path, meta_type):
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    rows = payload.get('data')
    meta = payload.get('meta') or {}
    if not isinstance(rows, list):
        return None
    if meta.get('type') != meta_type:
        return None
    if meta.get('count') != len(rows):
        return None
    return len(rows)


def valid_phase_count(filename, meta_type):
    """
    Total objects when every part of this phase is complete JSON, else None.
    """
    if not os.path.isfile(filename):
        return None
    total = 0
    for path in phase_part_paths(filename):
        count = _load_output(path, meta_type)
        if count is None:
            return None
        total += count
    return total


def clear_phase_outputs(filename):
    """
    Remove a previous attempt at this phase, including an unfinished partial.
    """
    names = [filename, filename + '.partial']
    stem = _stem(filename)
    number = 1
    while True:
        part = '%s_%02d.json' % (stem, number)
        partial = part + '.partial'
        if not os.path.exists(part) and not os.path.exists(partial):
            break
        names.append(part)
        names.append(partial)
        number += 1
    for name in names:
        try:
            os.remove(name)
        except OSError:
            pass


def prepare_phase(resume, phase, filename, meta_type):
    """
    False when this phase is already stored and its JSON checks out.
    """
    if resume is not None and resume.phase_done(phase):
        count = valid_phase_count(filename, meta_type)
        if count is None:
            logging.warning('%s was marked done but %s is incomplete. Collecting it again.', phase, filename)
        else:
            logging.info('Skipping %s, %s is complete (%d objects)', phase, filename, count)
            return False
    logging.info('Collecting %s', phase)
    clear_phase_outputs(filename)
    return True


def finish_phase(resume, phase, status):
    if resume is not None and status and status[0]:
        resume.mark(phase)


class CollectionResume(object):
    """
    Remembers which collection phases have been written so a later run can
    continue after the last finished JSON file.
    """

    def __init__(self, path, domain, collection, timestamp, prefix, phases, schema_map, slices=None):
        self.path = path
        self.domain = domain
        self.collection = collection
        self.timestamp = timestamp
        self.prefix = prefix
        self.phases = list(phases)
        self.schema_map = dict(schema_map or {})
        self.slices = dict(slices or {})

    @staticmethod
    def _discover_prefix():
        """
        When --resume is given without --outputprefix, use the only checkpoint
        in the working directory.
        """
        found = []
        try:
            names = os.listdir('.')
        except OSError as exc:
            raise CollectionException('Could not list the working directory for a resume checkpoint (%s)' % exc)
        for name in names:
            if name == 'bloodhound_resume.json':
                found.append('')
            elif name.endswith('_resume.json'):
                found.append(name[:-len('_resume.json')])
        if not found:
            return ''
        if len(found) == 1:
            return found[0]
        labels = [name or 'bloodhound_resume.json' for name in sorted(found)]
        raise CollectionException(
            'More than one resume checkpoint is in this directory (%s). Pass --outputprefix to choose one.' % ', '.join(labels))

    @classmethod
    def open(cls, prefix, domain, collection, resume):
        if resume and not prefix:
            prefix = cls._discover_prefix()
        path = checkpoint_path(prefix)
        domain_name = (domain or '').upper()
        methods = sorted(set(collection))
        stored_prefix = prefix or ''
        if resume:
            if not os.path.isfile(path):
                raise CollectionException('No resume checkpoint at %s' % path)
            try:
                with open(path, 'r', encoding='utf-8') as handle:
                    data = json.load(handle)
            except (OSError, ValueError) as exc:
                raise CollectionException('Could not read resume checkpoint %s (%s)' % (path, exc))
            saved_domain = str(data.get('domain') or '').upper()
            saved_methods = sorted(data.get('collection') or [])
            if saved_domain != domain_name:
                raise CollectionException('Resume checkpoint is for %s, not %s' % (saved_domain or 'an unknown domain', domain_name or 'an unknown domain'))
            if saved_methods != methods:
                raise CollectionException(
                    'Resume checkpoint collection is %s, not %s' % (
                        ', '.join(saved_methods) or 'empty',
                        ', '.join(methods) or 'empty'))
            if (data.get('prefix') or '') != stored_prefix:
                raise CollectionException('Resume checkpoint prefix does not match --outputprefix')
            timestamp = data.get('timestamp')
            if not timestamp:
                raise CollectionException('Resume checkpoint has no output timestamp')
            state = cls(path, saved_domain, saved_methods, timestamp, stored_prefix, data.get('phases') or [], data.get('schema_map') or {}, data.get('slices') or {})
            if stored_prefix:
                logging.info('Resuming collection from %s (output prefix %s)', path, stored_prefix)
            else:
                logging.info('Resuming collection from %s', path)
            return state
        timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S') + '_'
        state = cls(path, domain_name, methods, timestamp, stored_prefix, [], {})
        state.save()
        return state

    def has_schema(self):
        return 'schema' in self.phases and bool(self.schema_map)

    def phase_done(self, phase):
        return phase in self.phases

    def set_schema(self, guid_map):
        self.schema_map = dict(guid_map)

    def mark(self, phase):
        if phase not in self.phases:
            self.phases.append(phase)
        self.save()

    def slice_done(self, phase, prefix):
        return prefix in self.slices.get(phase, [])

    def mark_slice(self, phase, prefix):
        done = self.slices.setdefault(phase, [])
        if prefix not in done:
            done.append(prefix)
        self.save()

    def save(self):
        payload = {
            'domain': self.domain,
            'collection': self.collection,
            'timestamp': self.timestamp,
            'prefix': self.prefix,
            'phases': self.phases,
            'schema_map': self.schema_map,
            'slices': self.slices,
        }
        partial = self.path + '.partial'
        with open(partial, 'w', encoding='utf-8') as handle:
            json.dump(payload, handle)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        os.replace(partial, self.path)
