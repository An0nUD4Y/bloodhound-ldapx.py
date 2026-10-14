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

import logging
import queue
import threading
import calendar
from bloodhound.ad.utils import ADUtils, AceResolver, CollectionException, ldap_search_count
from bloodhound.ad.computer import ADComputer
from bloodhound.ad.structures import LDAP_SID
from bloodhound.enumeration.acls import AclEnumerator, parse_binary_acl
from bloodhound.enumeration.outputworker import OutputWorker
from bloodhound.enumeration.resume import (
    GUID_SLICES, concat_slice_files, finish_phase, output_filename, prepare_phase,
    remove_output, slice_output_path,
)

class MembershipEnumerator(object):
    """
    Class to enumerate memberships in the domain.
    Contains the dumping functions which
    methods from the bloodhound.ad module.
    """
    def __init__(self, addomain, addc, collect, disable_pooling):
        """
        Membership enumeration. Enumerates all groups/users/other memberships.
        """
        self.addomain = addomain
        self.addc = addc
        # Store collection methods specified
        self.collect = collect
        self.disable_pooling = disable_pooling
        self.aclenumerator = AclEnumerator(addomain, addc, collect)
        self.aceresolver = AceResolver(addomain, addomain.objectresolver)
        self.result_q = None
        self.resume = None
        self._writer_thread = None
        self._search_mark = None

    def _start_writer(self, worker, args):
        status = []

        def run():
            try:
                status.append(worker(*args))
            except Exception:
                logging.exception('Failed while writing collection output')
                status.append(False)

        self._writer_thread = threading.Thread(target=run)
        self._writer_thread.daemon = True
        self._writer_thread.start()
        return status

    def _finish_writer(self, phase, status):
        self.result_q.join()
        if self._writer_thread is not None:
            self._writer_thread.join()
        finish_phase(self.resume, phase, status)
        if self._search_mark is not None:
            logging.info('%s: %d LDAP searches', phase, ldap_search_count() - self._search_mark)

    def _close_acl_pool(self):
        if getattr(self, '_acl_pool_open', False):
            self.aclenumerator.pool.close()
            self.aclenumerator.pool.join()
            self._acl_pool_open = False

    def _end_writer(self):
        self._close_acl_pool()
        self.result_q.put(None)
        self.result_q.join()
        if self._writer_thread is not None:
            self._writer_thread.join()

    def _emit(self, obj):
        if getattr(self, '_capture', False):
            self._captured.append(obj)
        else:
            self.result_q.put(obj)

    def _collect(self, phase, filename, meta_type, fetch, fill, extras=None, count_filter=None):
        """
        Run one output phase. With --partition-ldap, each objectGUID slice is
        its own file and a finished slice is skipped on resume.  When
        --partition-threshold is set and a count query shows fewer objects
        than the threshold, slicing is skipped for this phase.
        """
        skip_slicing = not getattr(self.addc, 'partition_ldap', False)
        if not skip_slicing:
            threshold = getattr(self.addc, 'partition_threshold', 0)
            if threshold > 0 and count_filter is not None:
                count, exceeds = self.addc.count_exceeds(count_filter, threshold)
                if not exceeds:
                    logging.info('%s: %d objects (threshold %d), using single query',
                                 phase, count, threshold)
                    skip_slicing = True
                else:
                    logging.info('%s: >%d objects, using GUID slicing (256 queries)',
                                 phase, threshold)

        if skip_slicing:
            self.result_q = queue.Queue()
            status = self._start_writer(OutputWorker.membership_write_worker, (self.result_q, meta_type, filename))
            fill(fetch(None))
            if extras:
                extras()
            self._close_acl_pool()
            self.result_q.put(None)
            self._finish_writer(phase, status)
            return

        slice_files = []
        for prefix in GUID_SLICES:
            path = slice_output_path(filename, prefix)
            if self.resume is not None and self.resume.slice_done(phase, prefix) and os.path.isfile(path):
                logging.info('Skipping %s slice %s (%d/256)', phase, prefix, len(slice_files) + 1)
                slice_files.append(path)
                continue
            remove_output(path)
            logging.info('Collecting %s slice %s (%d/256)', phase, prefix, len(slice_files) + 1)
            self.result_q = queue.Queue()
            status = self._start_writer(OutputWorker.membership_write_worker, (self.result_q, meta_type, path))
            fill(fetch(prefix))
            self._end_writer()
            if not status or not status[0]:
                raise CollectionException('Could not write %s slice %s' % (phase, prefix))
            if self.resume is not None:
                self.resume.mark_slice(phase, prefix)
            slice_files.append(path)
        extra_rows = []
        if extras:
            self._captured = []
            self._capture = True
            extras()
            self._capture = False
            extra_rows = self._captured
        concat_slice_files(filename, meta_type, slice_files, extra_rows)
        if self.resume is not None:
            self.resume.mark(phase)
        if self._search_mark is not None:
            logging.info('%s: %d LDAP searches', phase, ldap_search_count() - self._search_mark)

    def get_membership(self, member):
        """
        Attempt to resolve the membership (DN) of a group to an object
        Moved to addomain logic since we need DN resolving in other files
        """
        return self.addomain.get_dn_from_cache_or_ldap(member)

    @staticmethod
    def get_primary_membership(entry):
        """
        Construct primary membership from RID to SID (BloodHound 3.0 only)
        """
        try:
            primarygroupid = int(entry['attributes']['primaryGroupID'])
        except (TypeError, KeyError):
            # Doesn't have a primarygroupid, means it is probably a Group instead of a user
            return None
        try:
            objectsid = entry['attributes']['objectSid']
        except KeyError:
            return None
        return '%s-%d' % ('-'.join(objectsid.split('-')[:-1]), primarygroupid)

    @staticmethod
    def add_user_properties(user, entry):
        """
        Resolve properties for user objects
        """
        props = user['Properties']
        # print entry
        # Is user enabled? Checked by seeing if the UAC flag 2 (ACCOUNT_DISABLED) is not set
        props['enabled'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 2 == 0
        props['lastlogon'] = ADUtils.win_timestamp_to_unix(
            ADUtils.get_entry_property(entry, 'lastLogon', default=-1, raw=True)
        )
        props['lastlogontimestamp'] = ADUtils.win_timestamp_to_unix(
            ADUtils.get_entry_property(entry, 'lastlogontimestamp', default=-1, raw=True)
        )
        if props['lastlogontimestamp'] == 0:
            props['lastlogontimestamp'] = -1
        props['pwdlastset'] = ADUtils.win_timestamp_to_unix(
            ADUtils.get_entry_property(entry, 'pwdLastSet', default=-1, raw=True)
        )
        props['dontreqpreauth'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00400000 == 0x00400000
        props['pwdneverexpires'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00010000 == 0x00010000
        props['sensitive'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00100000 == 0x00100000
        props['serviceprincipalnames'] = ADUtils.get_entry_property(entry, 'servicePrincipalName', [])
        props['hasspn'] = len(props['serviceprincipalnames']) > 0
        props['displayname'] = ADUtils.get_entry_property(entry, 'displayName')
        props['email'] = ADUtils.get_entry_property(entry, 'mail')
        props['title'] = ADUtils.get_entry_property(entry, 'title')
        props['homedirectory'] = ADUtils.get_entry_property(entry, 'homeDirectory')
        props['description'] = ADUtils.get_entry_property(entry, 'description')
        props['userpassword'] = ADUtils.ensure_string(ADUtils.get_entry_property(entry, 'userPassword'))
        props['admincount'] = ADUtils.get_entry_property(entry, 'adminCount', 0) == 1
        if len(ADUtils.get_entry_property(entry, 'msDS-AllowedToDelegateTo', [])) > 0:
            props['allowedtodelegate'] = ADUtils.get_entry_property(entry, 'msDS-AllowedToDelegateTo', [])
        props['sidhistory'] = [LDAP_SID(bsid).formatCanonical() for bsid in ADUtils.get_entry_property(entry, 'sIDHistory', [])]
        # v4 props
        whencreated = ADUtils.get_entry_property(entry, 'whencreated', default=0)
        if isinstance(whencreated, int):
            props['whencreated'] = whencreated
        else:
            props['whencreated'] = calendar.timegm(whencreated.timetuple())
        props['unixpassword'] = ADUtils.ensure_string(ADUtils.get_entry_property(entry, 'unixuserpassword'))
        props['unicodepassword'] = ADUtils.ensure_string(ADUtils.get_entry_property(entry, 'unicodepwd'))
        props['logonscript'] = ADUtils.ensure_string(ADUtils.get_entry_property(entry, 'scriptpath'))
        props['samaccountname'] = ADUtils.ensure_string(ADUtils.get_entry_property(entry, 'sAMAccountName'))
        # Non-default schema?
        # props['sfupassword'] = ADUtils.ensure_string(ADUtils.get_entry_property(entry, 'msSFU30Password'))
        props['sfupassword'] = None

    def _fill_users(self, entries, with_properties, acl):
        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()
            self._acl_pool_open = True
        for entry in entries:
            self._process_user(entry, with_properties, acl)

    def _process_user(self, entry, with_properties, acl):
        resolved_entry = ADUtils.resolve_ad_entry(entry)
        if resolved_entry['type'] == 'trustaccount':
            return
        user = {
            "AllowedToDelegate": [],
            "ObjectIdentifier": ADUtils.get_entry_property(entry, 'objectSid'),
            "PrimaryGroupSID": MembershipEnumerator.get_primary_membership(entry),
            "ContainedBy": None,
            "Properties": {
                "name": resolved_entry['principal'],
                "domain": self.addomain.domain.upper(),
                "domainsid": self.addomain.domain_object.sid,
                "highvalue": False,
                "distinguishedname": ADUtils.get_entry_property(entry, 'distinguishedName').upper(),
                "unconstraineddelegation": ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00080000 == 0x00080000,
                "trustedtoauth": ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x01000000 == 0x01000000,
                "passwordnotreqd": ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00000020 == 0x00000020
            },
            "Aces": [],
            "SPNTargets": [],
            "HasSIDHistory": [],
            "IsDeleted": ADUtils.get_entry_property(entry, 'isDeleted', default=False)
        }
        if with_properties:
            MembershipEnumerator.add_user_properties(user, entry)
            if 'allowedtodelegate' in user['Properties']:
                delegatehosts_cache = []
                for host in user['Properties']['allowedtodelegate']:
                    try:
                        target = host.split('/')[1]
                    except IndexError:
                        logging.warning('Invalid delegation target: %s', host)
                        continue
                    try:
                        object_sid = self.addomain.computersidcache.get(target.lower())
                        user['AllowedToDelegate'].append({
                            'ObjectIdentifier': object_sid,
                            'ObjectType': ADUtils.resolve_ad_entry(
                                self.addomain.objectresolver.resolve_sid(object_sid)
                            )['type'],
                        })
                    except KeyError:
                        object_sam = target.upper().split(".")[0].split("\\")[0]
                        if object_sam in delegatehosts_cache:
                            continue
                        delegatehosts_cache.append(object_sam)
                        object_entry = self.addomain.objectresolver.resolve_samname(object_sam + '*', allow_filter=True)
                        if object_entry:
                            object_resolved = ADUtils.resolve_ad_entry(object_entry[0])
                            user['AllowedToDelegate'].append({
                                'ObjectIdentifier': object_resolved['objectid'],
                                'ObjectType': object_resolved['type'],
                            })
            if len(user['Properties']['sidhistory']) > 0:
                for historysid in user['Properties']['sidhistory']:
                    user['HasSIDHistory'].append(self.aceresolver.resolve_sid(historysid))
        if ADUtils.get_entry_property(entry, 'msDS-GroupMSAMembership', default=b'', raw=True) != b'':
            self.parse_gmsa(user, entry)
        linkentry = {
            "ObjectIdentifier": resolved_entry['objectid'],
            "ObjectType": resolved_entry['type'].capitalize()
        }
        self.addomain.dncache[entry['dn'].upper()] = linkentry
        if acl:
            if self.disable_pooling:
                self.process_acldata(parse_binary_acl(user, 'user', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map))
            else:
                self.aclenumerator.pool.apply_async(parse_binary_acl, args=(user, 'user', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map), callback=self.process_acldata)
        else:
            self.result_q.put(user)

    def enumerate_users(self, timestamp="", fileNamePrefix=""):
        filename = output_filename(fileNamePrefix, timestamp, 'users.json')
        if not prepare_phase(self.resume, 'users', filename, 'users'):
            return
        self._search_mark = ldap_search_count()

        # Should we include extra properties in the query?
        with_properties = 'objectprops' in self.collect
        acl = 'acl' in self.collect
        entries = self.addc.get_users(include_properties=with_properties, acl=acl)
        if self.addc.partition_ldap:
            self._collect(
                'users', filename, 'users',
                lambda prefix: self.addc.get_users(include_properties=with_properties, acl=acl, guid_prefix=prefix),
                lambda found: self._fill_users(found, with_properties, acl),
                self.write_default_users,
                count_filter='(&(objectCategory=person)(objectClass=user))')
            return

        logging.debug('Writing users to file: %s', filename)

        # Use a separate queue for processing the results
        self.result_q = queue.Queue()
        writer_status = self._start_writer(OutputWorker.membership_write_worker, (self.result_q, 'users', filename))

        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()
            self._acl_pool_open = True

        # This loops over a generator, results are fetched from LDAP on the go
        for entry in entries:
            self._process_user(entry, with_properties, acl)

        self.write_default_users()

        # If we are parsing ACLs, close the parsing pool first
        # then close the result queue and join it
        if acl and not self.disable_pooling:
            self.aclenumerator.pool.close()
            self.aclenumerator.pool.join()
            self.result_q.put(None)
        else:
            self.result_q.put(None)
        self._finish_writer('users', writer_status)

        logging.debug('Finished writing users')

    def _fill_groups(self, entries, with_properties, acl, is_highvalue):
        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()
            self._acl_pool_open = True
        for entry in entries:
            self._process_group(entry, with_properties, acl, is_highvalue)

    def _process_group(self, entry, with_properties, acl, is_highvalue):
        resolved_entry = ADUtils.resolve_ad_entry(entry)
        sid = ADUtils.get_entry_property(entry, 'objectSid')
        if not sid:
            logging.warning('Could not determine SID for group %s', ADUtils.get_entry_property(entry, 'distinguishedName'))
            return
        group = {
            "ObjectIdentifier": sid,
            "Properties": {
                "domain": self.addomain.domain.upper(),
                "domainsid": self.addomain.domain_object.sid,
                "highvalue": is_highvalue(sid),
                "name": resolved_entry['principal'],
                "distinguishedname": ADUtils.get_entry_property(entry, 'distinguishedName').upper()
            },
            "ContainedBy": None,
            "Members": [],
            "Aces": [],
            "IsDeleted": ADUtils.get_entry_property(entry, 'isDeleted', default=False)
        }
        if sid in ADUtils.WELLKNOWN_SIDS:
            group['ObjectIdentifier'] = '%s-%s' % (self.addomain.domain.upper(), sid)
        if with_properties:
            group['Properties']['admincount'] = ADUtils.get_entry_property(entry, 'adminCount', default=0) == 1
            group['Properties']['description'] = ADUtils.get_entry_property(entry, 'description')
            group['Properties']['samaccountname'] = ADUtils.get_entry_property(entry, 'sAMAccountName')
            whencreated = ADUtils.get_entry_property(entry, 'whencreated', default=0)
            if isinstance(whencreated, int):
                group['Properties']['whencreated'] = whencreated
            else:
                group['Properties']['whencreated'] = calendar.timegm(whencreated.timetuple())
        for member in ADUtils.get_entry_property(entry, 'member', []):
            resolved_member = self.get_membership(member)
            if resolved_member:
                group['Members'].append(resolved_member)
        link_output = {
            "ObjectIdentifier": group['ObjectIdentifier'],
            "ObjectType": 'Group'
        }
        self.addomain.dncache[ADUtils.get_entry_property(entry, 'distinguishedName').upper()] = link_output
        if acl:
            if self.disable_pooling:
                self.process_acldata(parse_binary_acl(group, 'group', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map))
            else:
                self.aclenumerator.pool.apply_async(parse_binary_acl, args=(group, 'group', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map), callback=self.process_acldata)
        else:
            self.result_q.put(group)

    def enumerate_groups(self, timestamp="", fileNamePrefix=""):

        highvalue = ["S-1-5-32-544", "S-1-5-32-550", "S-1-5-32-549", "S-1-5-32-551", "S-1-5-32-548"]

        def is_highvalue(sid):
            if sid.endswith("-512") or sid.endswith("-516") or sid.endswith("-519"):
                return True
            if sid in highvalue:
                return True
            return False

        # Should we include extra properties in the query?
        with_properties = 'objectprops' in self.collect
        acl = 'acl' in self.collect
        filename = output_filename(fileNamePrefix, timestamp, 'groups.json')
        if not prepare_phase(self.resume, 'groups', filename, 'groups'):
            return
        self._search_mark = ldap_search_count()
        if self.addc.partition_ldap:
            self._collect(
                'groups', filename, 'groups',
                lambda prefix: self.addc.get_groups(include_properties=with_properties, acl=acl, guid_prefix=prefix),
                lambda found: self._fill_groups(found, with_properties, acl, is_highvalue),
                self.write_default_groups,
                count_filter='(objectClass=group)')
            return
        entries = self.addc.get_groups(include_properties=with_properties, acl=acl)

        logging.debug('Writing groups to file: %s', filename)

        # Use a separate queue for processing the results
        self.result_q = queue.Queue()
        writer_status = self._start_writer(OutputWorker.membership_write_worker, (self.result_q, 'groups', filename))

        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()
            self._acl_pool_open = True

        for entry in entries:
            self._process_group(entry, with_properties, acl, is_highvalue)

        self.write_default_groups()

        # If we are parsing ACLs, close the parsing pool first
        # then close the result queue and join it
        if acl and not self.disable_pooling:
            self.aclenumerator.pool.close()
            self.aclenumerator.pool.join()
            self.result_q.put(None)
        else:
            self.result_q.put(None)
        self._finish_writer('groups', writer_status)

        logging.debug('Finished writing groups')

    def _fill_computers(self, entries, acl):
        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()
            self._acl_pool_open = True
        for entry in entries:
            self._process_computer(entry, acl)

    def _process_computer(self, entry, acl):
        if 'attributes' not in entry:
            return
        hostname = ADUtils.get_entry_property(entry, 'dNSHostName')
        samname = ADUtils.get_entry_property(entry, 'sAMAccountName')
        if not hostname:
            logging.debug('Invalid computer object without hostname: %s', samname)
            hostname = ''
        cobject = ADComputer(hostname=hostname, samname=samname, ad=self.addomain, addc=self.addc, objectsid=entry['attributes']['objectSid'])
        cobject.primarygroup = MembershipEnumerator.get_primary_membership(entry)
        computer = cobject.get_bloodhound_data(entry, self.collect, skip_acl=True)
        if acl:
            if self.disable_pooling:
                self.process_acldata(parse_binary_acl(computer, 'computer', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map))
            else:
                self.aclenumerator.pool.apply_async(parse_binary_acl, args=(computer, 'computer', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map), callback=self.process_acldata)
        else:
            self.result_q.put(computer)

    def enumerate_computers_dconly(self,timestamp ="", fileNamePrefix=""):
        '''
        Enumerate computer objects. This function is only used if no
        collection was requested that required connecting to computers anyway.
        '''
        filename = output_filename(fileNamePrefix, timestamp, 'computers.json')
        if not prepare_phase(self.resume, 'computers', filename, 'computers'):
            return
        self._search_mark = ldap_search_count()
        with_properties = 'objectprops' in self.collect
        acl = 'acl' in self.collect
        if self.addc.partition_ldap:
            self._collect(
                'computers', filename, 'computers',
                lambda prefix: self.addc.get_computers(include_properties=with_properties, acl=acl, guid_prefix=prefix),
                lambda found: self._fill_computers(found, acl),
                count_filter='(sAMAccountType=805306369)')
            return

        entries = self.addc.get_computers(include_properties=with_properties, acl=acl)

        logging.debug('Writing computers ACL to file: %s', filename)

        # Use a separate queue for processing the results
        self.result_q = queue.Queue()
        writer_status = self._start_writer(OutputWorker.membership_write_worker, (self.result_q, 'computers', filename))

        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()

        # This loops over the cached entries
        for entry in entries:
            self._process_computer(entry, acl)

        # If we are parsing ACLs, close the parsing pool first
        # then close the result queue and join it
        if acl and not self.disable_pooling:
            self.aclenumerator.pool.close()
            self.aclenumerator.pool.join()
            self.result_q.put(None)
        else:
            self.result_q.put(None)
        self._finish_writer('computers', writer_status)

        logging.debug('Finished writing computers')

    def _fill_gpos(self, entries, with_properties, acl):
        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()
            self._acl_pool_open = True
        for entry in entries:
            self._process_gpo(entry, with_properties, acl)

    def _process_gpo(self, entry, with_properties, acl):
        try:
            guid = entry['attributes']['objectGUID'][1:-1].upper()
        except KeyError:
            logging.warning('Could not determine GUID for GPO %s', entry['attributes']['distinguishedName'])
            return
        gpo = {
            "ObjectIdentifier": guid,
            "Properties": {
                "domain": self.addomain.domain.upper(),
                "name": '%s@%s' % (ADUtils.get_entry_property(entry, 'displayName', '').upper(), self.addomain.domain.upper()),
                "distinguishedname": ADUtils.get_entry_property(entry, 'distinguishedName', '').upper(),
                "domainsid": self.addomain.domain_object.sid,
                "highvalue": False,
                "gpcpath": ADUtils.get_entry_property(entry, 'gPCFileSysPath', '').upper(),
            },
            "IsDeleted": False,
            "IsACLProtected": False,
            "Aces": [],
        }
        if with_properties:
            gpo["Properties"]["description"] = ADUtils.get_entry_property(entry, 'description', '')
            whencreated = ADUtils.get_entry_property(entry, 'whencreated', default=0)
            if isinstance(whencreated, int):
                gpo['Properties']['whencreated'] = whencreated
            else:
                gpo['Properties']['whencreated'] = calendar.timegm(whencreated.timetuple())
        link_output = {
            "ObjectIdentifier": gpo['ObjectIdentifier'],
            "ObjectType": "GPO",
        }
        self.addomain.dncache[ADUtils.get_entry_property(entry, 'distinguishedName').upper()] = link_output
        if acl:
            if self.disable_pooling:
                self.process_acldata(parse_binary_acl(gpo, 'gpo', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map))
            else:
                self.aclenumerator.pool.apply_async(parse_binary_acl, args=(gpo, 'gpo', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map), callback=self.process_acldata)
        else:
            self.result_q.put(gpo)

    def enumerate_gpos(self, timestamp ="", fileNamePrefix=""):
        filename = output_filename(fileNamePrefix, timestamp, 'gpos.json')
        if not prepare_phase(self.resume, 'gpos', filename, 'gpos'):
            return
        self._search_mark = ldap_search_count()

        with_properties = 'objectprops' in self.collect
        acl = 'acl' in self.collect
        if self.addc.partition_ldap:
            self._collect(
                'gpos', filename, 'gpos',
                lambda prefix: self.addc.get_gpos(include_properties=with_properties, acl=acl, guid_prefix=prefix),
                lambda found: self._fill_gpos(found, with_properties, acl),
                count_filter='(objectCategory=groupPolicyContainer)')
            return
        entries = self.addc.get_gpos(include_properties=with_properties, acl=acl)

        logging.debug('Writing GPOs to file: %s', filename)

        # Use a separate queue for processing the results
        self.result_q = queue.Queue()
        writer_status = self._start_writer(OutputWorker.membership_write_worker, (self.result_q, 'gpos', filename))

        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()

        for entry in entries:
            self._process_gpo(entry, with_properties, acl)

            # self.write_default_groups()

        # If we are parsing ACLs, close the parsing pool first
        # then close the result queue and join it
        if acl and not self.disable_pooling:
            self.aclenumerator.pool.close()
            self.aclenumerator.pool.join()
            self.result_q.put(None)
        else:
            self.result_q.put(None)
        self._finish_writer('gpos', writer_status)

        logging.debug('Finished writing GPO')

    def _process_ou(self, entry, with_properties, acl):
        try:
            guid = entry['attributes']['objectGUID'][1:-1].upper()
        except KeyError:
            logging.warning('Could not determine GUID for OU %s', entry['attributes']['distinguishedName'])
            return
        ou = {
                "ObjectIdentifier": guid,
                "Properties": {
                    "domain": self.addomain.domain.upper(),
                    "name": '%s@%s' % (ADUtils.get_entry_property(entry, 'name').upper(), self.addomain.domain.upper()),
                    "distinguishedname": ADUtils.get_entry_property(entry, 'distinguishedName').upper(),
                    "domainsid": self.addomain.domain_object.sid,
                    "highvalue": False,
                    # Ref: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/08090b22-bc16-49f4-8e10-f27a8fb16d18
                    "blocksinheritance": ADUtils.get_entry_property(entry, 'gPOptions', 0) == 1,
                },
                "IsDeleted": False,
                "IsACLProtected": False,
                "Aces": [],
                "Links": [],
                "ChildObjects": [],
                "GPOChanges": {
                    "AffectedComputers": [],
                    "DcomUsers": [],
                    "LocalAdmins": [],
                    "PSRemoteUsers": [],
                    "RemoteDesktopUsers": []
                },
        }

        
        if with_properties:
            ou["Properties"]["description"] = ADUtils.get_entry_property(entry, 'description')
            whencreated = ADUtils.get_entry_property(entry, 'whencreated', default=0)
            if isinstance(whencreated, int):
                ou['Properties']['whencreated'] = whencreated
            else:
                ou['Properties']['whencreated'] = calendar.timegm(whencreated.timetuple())
        
        for childentry in self.addc.get_childobjects(ou["Properties"]["distinguishedname"]):
            resolved_childentry = ADUtils.resolve_ad_entry(childentry)
            # Skip children with empty ID because it breaks ingestion
            if not resolved_childentry['objectid']:
                continue
            out_object = {
                "ObjectIdentifier":resolved_childentry['objectid'],
                "ObjectType":resolved_childentry['type']
            }
            ou["ChildObjects"].append(out_object)
        
        for gplink_dn, option in ADUtils.parse_gplink_string(ADUtils.get_entry_property(entry, 'gPLink', '')):
            if option == 0 or option == 2:
                link = dict()
                link['IsEnforced'] = option == 2
                try:
                    link['GUID'] = self.get_membership(gplink_dn.upper())['ObjectIdentifier']
                    if not link['GUID']:
                        continue
                    ou['Links'].append(link)
                except TypeError:
                    logging.warning('Could not resolve GPO link to {0}'.format(gplink_dn))
        
        # Create cache entry for links
        link_output = {
            "ObjectIdentifier": ou['ObjectIdentifier'],
            "ObjectType": 'OU'
        }
        self.addomain.dncache[ADUtils.get_entry_property(entry, 'distinguishedName').upper()] = link_output

        # If we are enumerating ACLs, we break out of the loop here
        # this is because parsing ACLs is computationally heavy and therefor is done in subprocesses
        if acl:
            if self.disable_pooling:
                # Debug mode, don't run this pooled since it hides exceptions
                self.process_acldata(parse_binary_acl(ou, 'organizational-unit', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map))
            else:
                # Process ACLs in separate processes, then call the processing function to resolve entries and write them to file
                self.aclenumerator.pool.apply_async(parse_binary_acl, args=(ou, 'organizational-unit', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map), callback=self.process_acldata)
        else:
            # Write it to the queue -> write to file in separate thread
            # this is solely for consistency with acl parsing, the performance improvement is probably minimal
            self.result_q.put(ou)

    def _process_container(self, entry, with_properties, acl):
        if ADUtils.is_filtered_container(ADUtils.get_entry_property(entry, 'distinguishedName')):
            return
        try:
            guid = entry['attributes']['objectGUID'][1:-1].upper()
        except KeyError:
            logging.warning('Could not determine GUID for container %s', entry['attributes']['distinguishedName'])
            return
        container = {
                "ObjectIdentifier": guid,
                "Properties": {
                    "domain": self.addomain.domain.upper(),
                    "name": '%s@%s' % (ADUtils.get_entry_property(entry, 'name').upper(), self.addomain.domain.upper()),
                    "distinguishedname": ADUtils.get_entry_property(entry, 'distinguishedName').upper(),
                    "domainsid": self.addomain.domain_object.sid,
                    "highvalue": False,
                },
                "IsDeleted": False,
                "IsACLProtected": False,
                "ContainedBy": None,
                "Aces": [],
                "ChildObjects": [],
        }

        
        if with_properties:
            container["Properties"]["description"] = ADUtils.get_entry_property(entry, 'description', '')
            whencreated = ADUtils.get_entry_property(entry, 'whencreated', default=0)
            if isinstance(whencreated, int):
                container["Properties"]["whencreated"] = whencreated
            else:
                container["Properties"]["whencreated"] =  calendar.timegm(whencreated.timetuple())
        
        for childentry in self.addc.get_childobjects(container["Properties"]["distinguishedname"]):
            if ADUtils.is_filtered_container_child(ADUtils.get_entry_property(childentry, 'distinguishedName')):
                continue
            resolved_childentry = ADUtils.resolve_ad_entry(childentry)
            # Skip children with empty ID because it breaks ingestion
            if not resolved_childentry['objectid']:
                continue
            childobject = {
                "ObjectIdentifier":resolved_childentry['objectid'],
                "ObjectType":resolved_childentry['type']
            }
            container["ChildObjects"].append(childobject)
        
        # Create cache entry for links
        link_output = {
            "ObjectIdentifier": container['ObjectIdentifier'],
            "ObjectType": 'container'
        }
        self.addomain.dncache[ADUtils.get_entry_property(entry, 'distinguishedName').upper()] = link_output

        # If we are enumerating ACLs, we break out of the loop here
        # this is because parsing ACLs is computationally heavy and therefor is done in subprocesses
        if acl:
            if self.disable_pooling:
                # Debug mode, don't run this pooled since it hides exceptions
                self.process_acldata(parse_binary_acl(container, 'container', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map))
            else:
                # Process ACLs in separate processes, then call the processing function to resolve entries and write them to file
                self.aclenumerator.pool.apply_async(parse_binary_acl, args=(container, 'container', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True), self.addc.objecttype_guid_map), callback=self.process_acldata)
        else:
            # Write it to the queue -> write to file in separate thread
            # this is solely for consistency with acl parsing, the performance improvement is probably minimal
            self.result_q.put(container)

    def _fill_ous(self, entries, with_properties, acl):
        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()
            self._acl_pool_open = True
        for entry in entries:
            self._process_ou(entry, with_properties, acl)

    def _fill_containers(self, entries, with_properties, acl):
        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()
            self._acl_pool_open = True
        for entry in entries:
            self._process_container(entry, with_properties, acl)

    def enumerate_ous(self, timestamp ="", fileNamePrefix=""):
        filename = output_filename(fileNamePrefix, timestamp, 'ous.json')
        if not prepare_phase(self.resume, 'ous', filename, 'ous'):
            return
        self._search_mark = ldap_search_count()
        with_properties = 'objectprops' in self.collect
        acl = 'acl' in self.collect
        if self.addc.partition_ldap:
            self._collect(
                'ous', filename, 'ous',
                lambda prefix: self.addc.get_ous(include_properties=with_properties, acl=acl, guid_prefix=prefix),
                lambda found: self._fill_ous(found, with_properties, acl),
                count_filter='(objectCategory=organizationalUnit)')
            return
        entries = self.addc.get_ous(include_properties=with_properties, acl=acl)

        logging.debug('Writing OU to file: %s', filename)

        # Use a separate queue for processing the results
        self.result_q = queue.Queue()
        writer_status = self._start_writer(OutputWorker.membership_write_worker, (self.result_q, 'ous', filename))

        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()

        for entry in entries:
            self._process_ou(entry, with_properties, acl)

            # self.write_default_groups()

        # If we are parsing ACLs, close the parsing pool first
        # then close the result queue and join it
        if acl and not self.disable_pooling:
            self.aclenumerator.pool.close()
            self.aclenumerator.pool.join()
            self.result_q.put(None)
        else:
            self.result_q.put(None)
        self._finish_writer('ous', writer_status)

        logging.debug('Finished writing OU')

    def enumerate_containers(self, timestamp ="", fileNamePrefix=""):
        filename = output_filename(fileNamePrefix, timestamp, 'containers.json')
        if not prepare_phase(self.resume, 'containers', filename, 'containers'):
            return
        self._search_mark = ldap_search_count()
        with_properties = 'objectprops' in self.collect
        acl = 'acl' in self.collect
        if self.addc.partition_ldap:
            self._collect(
                'containers', filename, 'containers',
                lambda prefix: self.addc.get_containers(include_properties=with_properties, acl=acl, guid_prefix=prefix),
                lambda found: self._fill_containers(found, with_properties, acl),
                count_filter='(&(objectCategory=container)(objectClass=container))')
            return
        entries = self.addc.get_containers(include_properties=with_properties, acl=acl)

        logging.debug('Writing containers to file: %s', filename)

        # Use a separate queue for processing the results
        self.result_q = queue.Queue()
        writer_status = self._start_writer(OutputWorker.membership_write_worker, (self.result_q, 'containers', filename))

        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()

        for entry in entries:
            self._process_container(entry, with_properties, acl)

        # If we are parsing ACLs, close the parsing pool first
        # then close the result queue and join it
        if acl and not self.disable_pooling:
            self.aclenumerator.pool.close()
            self.aclenumerator.pool.join()
            self.result_q.put(None)
        else:
            self.result_q.put(None)
        self._finish_writer('containers', writer_status)

        logging.debug('Finished writing containers')

    def parse_gmsa(self, user, entry):
        """
        Parse GMSA DACL which states which users can read the password
        """
        _, aces = parse_binary_acl(user, 'user', ADUtils.get_entry_property(entry, 'msDS-GroupMSAMembership', raw=True), self.addc.objecttype_guid_map)
        processed_aces = self.aceresolver.resolve_aces(aces)
        for ace in processed_aces:
            if ace['RightName'] == 'Owner':
                continue
            ace['RightName'] = 'ReadGMSAPassword'
            user['Aces'].append(ace)

    def process_acldata(self, result):
        """
        Process ACLs that resulted from parsing with cstruct
        """
        data, aces = result
        # Parse aces
        data['Aces'] += self.aceresolver.resolve_aces(aces)
        self.result_q.put(data)

    def write_default_users(self):
        """
        Write built-in users to users.json file
        """

        domainsid = self.addomain.domain_object.sid
        domainname = self.addomain.domain.upper()

        user = {
            "AllowedToDelegate": [],
            "ObjectIdentifier": "%s-S-1-5-20" % domainname,
            "PrimaryGroupSID": None,
            "Properties": {
                "domain": domainname,
                "domainsid": self.addomain.domain_object.sid,
                "name": "NT AUTHORITY@%s" % domainname,
                "highvalue": False,
            },
            "Aces": [],
            "SPNTargets": [],
            "HasSIDHistory": [],
            "IsDeleted": False,
            "ContainedBy": None,
            "IsACLProtected": False,
        }
        self._emit(user)


    def write_default_groups(self):
        """
        Put default groups in the groups.json file
        """

        # Domain controllers
        rootdomain = self.addc.get_root_domain().upper()
        entries = self.addc.get_domain_controllers()

        group = {
            "IsDeleted": False,
            "IsACLProtected": False,
            "ContainedBy": None,
            "ObjectIdentifier": "%s-S-1-5-9" % rootdomain,
            "Properties": {
                "domain": rootdomain.upper(),
                "name": "ENTERPRISE DOMAIN CONTROLLERS@%s" % rootdomain,
            },
            "Members": [],
            "Aces": []
        }
        for entry in entries:
            resolved_entry = ADUtils.resolve_ad_entry(entry)
            memberdata = {
                "ObjectIdentifier": resolved_entry['objectid'],
                "ObjectType": resolved_entry['type'].capitalize()
            }
            group["Members"].append(memberdata)
        self._emit(group)

        domainsid = self.addomain.domain_object.sid
        domainname = self.addomain.domain.upper()

        # Everyone
        evgroup = {
            "IsDeleted": False,
            "IsACLProtected": False,
            "ContainedBy": None,
            "ObjectIdentifier": "%s-S-1-1-0" % domainname,
            "Properties": {
                "domain": domainname,
                "domainsid": self.addomain.domain_object.sid,
                "name": "EVERYONE@%s" % domainname,
            },
            "Members": [],
            "Aces": []
        }
        self._emit(evgroup)

        # Authenticated users
        augroup = {
            "IsDeleted": False,
            "IsACLProtected": False,
            "ContainedBy": None,
            "ObjectIdentifier": "%s-S-1-5-11" % domainname,
            "Properties": {
                "domain": domainname,
                "domainsid": self.addomain.domain_object.sid,
                "name": "AUTHENTICATED USERS@%s" % domainname,
            },
            "Members": [],
            "Aces": []
        }
        self._emit(augroup)

        # Interactive
        iugroup = {
            "IsDeleted": False,
            "IsACLProtected": False,
            "ContainedBy": None,
            "ObjectIdentifier": "%s-S-1-5-4" % domainname,
            "Properties": {
                "domain": domainname,
                "domainsid": self.addomain.domain_object.sid,
                "name": "INTERACTIVE@%s" % domainname,
            },
            "Members": [],
            "Aces": []
        }
        self._emit(iugroup)

    def do_container_collection(self, timestamp="", fileNamePrefix=""):
        self.enumerate_gpos(timestamp, fileNamePrefix)
        self.enumerate_ous(timestamp, fileNamePrefix)
        self.enumerate_containers(timestamp, fileNamePrefix)

    def enumerate_memberships(self, timestamp="", fileNamePrefix=""):
        """
        Run appropriate enumeration tasks
        """
        self.enumerate_users(timestamp, fileNamePrefix)
        self.enumerate_groups(timestamp, fileNamePrefix)
        if 'container' in self.collect:
            self.do_container_collection(timestamp, fileNamePrefix)
        if not ('localadmin' in self.collect
                or 'session' in self.collect
                or 'loggedon' in self.collect
                or 'experimental' in self.collect):
            self.enumerate_computers_dconly(timestamp, fileNamePrefix)
