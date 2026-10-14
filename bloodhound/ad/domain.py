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
import traceback
import codecs
import json
import ldap3
import ipaddress

from uuid import UUID
from dns import resolver
from ldap3 import ALL_ATTRIBUTES, BASE, SUBTREE, LEVEL
from ldap3.core.exceptions import LDAPKeyError, LDAPAttributeError, LDAPCursorError, LDAPNoSuchObjectResult, LDAPSocketReceiveError, LDAPSocketSendError, LDAPCommunicationError
from ldap3.protocol.microsoft import security_descriptor_control
from bloodhound.ad.utils import ADUtils, DNSCache, SidCache, SamCache, CollectionException, get_ldap_pacer, ldap_search_count
from bloodhound.ad.computer import ADComputer
from bloodhound.enumeration.objectresolver import ObjectResolver
from bloodhound.enumeration.resume import GUID_SLICES, guid_filter

# Consecutive failures of the same LDAP page before the run stops.
_LDAP_SEARCH_ATTEMPTS = 5
_PAGED_RESULTS_OID = '1.2.840.113556.1.4.319'


def _paging_cookie_rejected(message):
    """
    True when Active Directory discarded the paged result set. That happens
    when the LDAP connection dies and the next page is sent on a new one.
    """
    text = str(message or '')
    return (
        'Error processing control' in text
        or '00002040' in text
        or 'UNAVAIL_EXTENSION' in text
        or 'unavailableCriticalExtension' in text
    )


def _next_page_cookie(result):
    """
    Cookie for the following page, or None when this page was the last one.
    """
    if not result:
        return None
    controls = result.get('controls') or {}
    try:
        cookie = controls[_PAGED_RESULTS_OID]['value']['cookie']
    except (KeyError, TypeError):
        return None
    if cookie is None or cookie == b'' or cookie == '':
        return None
    return cookie

"""
Active Directory Domain Controller
"""
class ADDC(ADComputer):
    def __init__(self, hostname=None, ad=None):
        ADComputer.__init__(self, hostname)
        self.ad = ad
        # Primary LDAP connection
        self.ldap = None
        # Secondary LDAP connection
        self.resolverldap = None
        # GC LDAP connection
        self.gcldap = None
        # Initialize GUID map
        self.objecttype_guid_map = dict()
        self.partition_ldap = False

    def ldap_connect(self, protocol=None, resolver=False):
        """
        Connect to the LDAP service
        """
        if not protocol:
            protocol = self.ad.ldap_default_protocol

        logging.info('Connecting to LDAP server: %s' % self.hostname)
        logging.debug('Using protocol %s' % protocol)

        if self.ad.ldap_listener is not None:
            # ldapx mode: connect to the local ldapx listener. Skip DNS
            # resolution and the anonymous connectivity probes - the listener
            # forwards everything to the real DC (possibly via SOCKS).
            logging.debug('Using ldapx listener at %s:%d' % self.ad.ldap_listener)
            ldap = self.ad.auth.getLDAPConnection(hostname=self.hostname,
                                                  ip=self.ad.ldap_listener[0],
                                                  baseDN=self.ad.baseDN, protocol='ldap')
            if resolver:
                self.resolverldap = ldap
            else:
                self.ldap = ldap
            return ldap is not None

        ip = None
        # Convert the hostname to an IP, this prevents ldap3 from doing it
        # which doesn't use our custom nameservers
        try:
            q = self.ad.dnsresolver.resolve(self.hostname, 'A', tcp=self.ad.dns_tcp)
            for rdata in q:
                logging.debug('LDAP server IPv4: %s', str(rdata.address))
                logging.debug('Testing resolved hostname connectivity %s', rdata.address)
                try:
                    _tmp_serv = ldap3.Server(rdata.address, connect_timeout=5)
                    _conn = ldap3.Connection(_tmp_serv)
                    _bind = _conn.bind()
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    continue
                else:
                    if _conn:
                        logging.debug('Successful connection to LDAP server on IP: %s', rdata.address)
                        ip = rdata.address
        except:
            logging.debug('No A records found')

        try:
            q6 = self.ad.dnsresolver.resolve(self.hostname, 'AAAA', tcp=self.ad.dns_tcp)
            for rdata in q6:
                logging.debug('LDAP server IPv6: %s', str(rdata.address))
                logging.info('Testing resolved hostname connectivity %s', rdata.address)
                try:
                    logging.info('Trying LDAP connection to %s', rdata.address)
                    _tmp_serv = ldap3.Server(rdata.address, connect_timeout=5)
                    _conn = ldap3.Connection(_tmp_serv)
                    _bind = _conn.bind()
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    continue
                except ldap3.core.exceptions.LDAPInvalidServerError:
                    logging.error('LDAP3 did not like address: %s', rdata.address)
                    continue
                else:
                    if _conn:
                        logging.debug('Successful connection to: %s', rdata.address)
                        ip = f'[{rdata.address}]'
        except:
            logging.debug('No AAAA records found')

        if not ip:
            logging.error('Failed to resolve LDAP server IP')
            return False

        ldap = self.ad.auth.getLDAPConnection(hostname=self.hostname, ip=ip,
                                              baseDN=self.ad.baseDN, protocol=protocol)
        if resolver:
            self.resolverldap = ldap
        else:
            self.ldap = ldap
        return ldap is not None

    def gc_connect(self, protocol='ldap'):
        """
        Connect to the global catalog
        """
        if self.ad.gc_listener is not None:
            # ldapx mode: connect to the local ldapx GC listener, skip DNS
            logging.info('Connecting to GC LDAP server via ldapx listener: %s' % self.hostname)
            logging.debug('Using ldapx GC listener at %s:%d' % self.ad.gc_listener)
            self.gcldap = self.ad.auth.getLDAPConnection(hostname=self.hostname,
                                                         ip=self.ad.gc_listener[0],
                                                         gc=True,
                                                         baseDN=self.ad.baseDN, protocol='ldap')
            return self.gcldap is not None

        if self.hostname in self.ad.gcs():
            # This server is a Global Catalog
            initial_server = self.hostname
        else:
            # Pick the first GC server
            try:
                initial_server = self.ad.gcs()[0]
            except IndexError:
                logging.error('Could not find a Global Catalog in this domain!'\
                              ' Resolving will be unreliable in forests with multiple domains')
                return False
        ip = None
        dns_errors = (resolver.NXDOMAIN, resolver.Timeout, resolver.NoAnswer, resolver.NoNameservers)
        try:
            # Convert the hostname to an IP, this prevents ldap3 from doing it
            # which doesn't use our custom nameservers
            logging.info('Connecting to GC LDAP server: %s' % initial_server)
            q = self.ad.dnsresolver.query(initial_server, tcp=self.ad.dns_tcp)
            for r in q:
                ip = r.address
        except dns_errors:
            for server in self.ad.gcs():
                # Skip the one we already tried
                if server == initial_server:
                    continue
                try:
                    # Convert the hostname to an IP, this prevents ldap3 from doing it
                    # which doesn't use our custom nameservers
                    logging.info('Connecting to GC LDAP server: %s' % server)
                    q = self.ad.dnsresolver.query(server, tcp=self.ad.dns_tcp)
                    for r in q:
                        ip = r.address
                        break
                except dns_errors:
                    continue

        if ip is None:
            logging.error('Could not resolve the IP address of any Global Catalog server')
            return False

        self.gcldap = self.ad.auth.getLDAPConnection(hostname=self.hostname, ip=ip, gc=True,
                                                     baseDN=self.ad.baseDN, protocol=protocol)
        return self.gcldap is not None

    def search(self, search_filter='(objectClass=*)',attributes=None, search_base=None, generator=True, use_gc=False, use_resolver=False, query_sd=False, search_scope=SUBTREE, progress_label='LDAP', auto_escape=True):
        """
        Search for objects in LDAP or Global Catalog LDAP.

        Pages are requested one at a time. A later page sends the paging
        cookie from the previous page, so a long wait does not request that
        page again. After a socket failure the same cookie is sent on the
        new connection. If the domain controller rejects it, the search stops
        instead of reading the result set again from the start.
        """
        if self.ldap is None and not use_resolver:
            if not self.ldap_connect(resolver=use_resolver):
                raise CollectionException('Could not connect to LDAP server %s' % self.hostname)
        if self.resolverldap is None and use_resolver:
            if not self.ldap_connect(resolver=use_resolver):
                raise CollectionException('Could not connect to LDAP server %s' % self.hostname)
        if search_base is None:
            search_base = self.ad.search_baseDN or self.ad.baseDN
        if attributes is None or attributes == []:
            attributes = ALL_ATTRIBUTES
        if query_sd:
            # Set SD flags to only query for DACL and Owner
            controls = security_descriptor_control(sdflags=0x05)
        else:
            controls = None

        # If we don't query the GC, don't accept an empty search base
        if search_base == "" and not use_gc:
            search_base = self.ad.baseDN

        if use_gc and self.gcldap is None:
            raise CollectionException('No connection to a Global Catalog server is available')

        try:
            for entry in self._iter_paged(search_base, search_filter, attributes, search_scope, controls, 200, use_gc, use_resolver, progress_label, auto_escape):
                yield entry
        except LDAPNoSuchObjectResult:
            # This may indicate the object doesn't exist or access is denied
            logging.warning('LDAP Server reported that the search in %s for %s does not exist.', search_base, search_filter)

    def _ldap_handle(self, use_gc, use_resolver):
        if use_gc:
            return self.gcldap
        if use_resolver:
            return self.resolverldap
        return self.ldap

    def _iter_paged(self, search_base, search_filter, attributes, search_scope, controls, paged_size, use_gc, use_resolver, progress_label='LDAP', auto_escape=True):
        """
        Yield every entry of a paged search. The paging cookie is kept and
        sent with the next page. After a socket failure the same cookie is
        sent again. A rejected cookie stops the search; pages that already
        succeeded are not requested again.
        """
        cookie = None
        page = 0
        failures = 0
        collected = 0
        while True:
            page += 1
            searcher = self._ldap_handle(use_gc, use_resolver)
            logging.debug('LDAP page %d for %s (%s paging cookie)', page, search_filter, 'with' if cookie else 'without')
            try:
                searcher.search(search_base=search_base,
                                search_filter=search_filter,
                                search_scope=search_scope,
                                attributes=attributes,
                                controls=controls,
                                paged_size=paged_size,
                                paged_cookie=cookie,
                                auto_escape=auto_escape)
            except LDAPNoSuchObjectResult:
                raise
            except (LDAPSocketReceiveError, LDAPSocketSendError, LDAPCommunicationError):
                failures += 1
                self._resume_search(search_filter, use_gc, use_resolver, collected, failures)
                page -= 1
                continue
            result = searcher.result or {}
            if result.get('result') not in (0, None):
                message = result.get('message') or result.get('description') or ''
                if cookie and _paging_cookie_rejected(message):
                    raise CollectionException(
                        'The domain controller rejected the paging cookie while collecting %s '
                        '(%d object(s) already read). The remaining pages were not read again from the start.'
                        % (search_filter, collected))
                raise CollectionException('LDAP search %s failed: %s' % (search_filter, message or result))
            entries = list(searcher.response or [])
            page_entries = []
            for entry in entries:
                if entry.get('type') != 'searchResEntry':
                    continue
                page_entries.append(entry)
            collected += len(page_entries)
            if get_ldap_pacer() is not None:
                logging.info('%s page %d, %d objects', progress_label, page, collected)
            for entry in page_entries:
                yield entry
            new_cookie = _next_page_cookie(result)
            if not new_cookie:
                logging.debug('LDAP page %d for %s was the last page (%d object(s))', page, search_filter, collected)
                return
            cookie = new_cookie
            failures = 0

    def _resume_search(self, search_filter, use_gc, use_resolver, collected, attempt):
        """
        Reconnect and let the caller send the same paging cookie again.
        """
        if attempt >= _LDAP_SEARCH_ATTEMPTS:
            raise CollectionException(
                'LDAP search did not finish after %d attempts (%d object(s) already read) for %s. '
                'Refusing to read the remaining pages again from the start.' % (attempt, collected, search_filter))
        logging.warning(
            'Connection lost during LDAP search (%d object(s) already read). '
            'Reconnecting and continuing %s from the current page (attempt %d of %d)',
            collected, search_filter, attempt + 1, _LDAP_SEARCH_ATTEMPTS)
        if use_gc:
            reconnected = self.gc_connect()
        else:
            reconnected = self.ldap_connect(resolver=use_resolver)
        if not reconnected:
            raise CollectionException('Could not reconnect to LDAP while collecting %s' % search_filter)


    def ldap_get_single(self, qobject, attributes=None, use_gc=False, use_resolver=False, _attempt=1):
        """
        Get a single object, requires full DN to object.
        This function supports searching both in the local directory and the Global Catalog.
        The connection to the GC should already be established before calling this function.
        """
        if use_gc:
            searcher = self.gcldap
        else:
            # If this request comes from the resolver thread, use that
            if use_resolver:
                searcher = self.resolverldap
            else:
                searcher = self.ldap
        if attributes is None or attributes == []:
            attributes = ALL_ATTRIBUTES
        try:
            sresult = searcher.extend.standard.paged_search(qobject,
                                                            '(objectClass=*)',
                                                            search_scope=BASE,
                                                            attributes=attributes,
                                                            paged_size=10,
                                                            generator=False)
        except (LDAPSocketReceiveError, LDAPSocketSendError, LDAPCommunicationError):
            self._resume_search(qobject, use_gc, use_resolver, 0, _attempt)
            return self.ldap_get_single(qobject, attributes, use_gc, use_resolver, _attempt=_attempt + 1)
        except LDAPNoSuchObjectResult:
            # This may indicate the object doesn't exist or access is denied
            logging.warning('LDAP Server reported that the object %s does not exist.', qobject)
            return None
        for e in sresult:
            if e['type'] != 'searchResEntry':
                continue
            return e

    def get_domain_controllers(self):
        entries = self.search('(userAccountControl:1.2.840.113556.1.4.803:=8192)',
                              ['dnshostname', 'samaccounttype', 'samaccountname',
                               'serviceprincipalname', 'objectSid'])

        return entries


    def get_netbios_name(self, context):
        try:
            entries = self.search('(ncname=%s)' % context,
                                  ['nETBIOSName'],
                                  search_base="CN=Partitions,%s" % self.ldap.server.info.other['configurationNamingContext'][0])
            return next(entries)
        except (LDAPAttributeError, LDAPCursorError) as e:
            logging.warning('Could not determine NetBiosname of the domain: %s', str(e))
        except StopIteration:
            logging.warning('Could not determine NetBiosname of the domain: no partition entry for %s', context)
        return None

    def get_objecttype(self):
        """
        Function to get objecttype GUID
        """
        logging.info('Collecting schema')
        started = ldap_search_count()
        resume = getattr(self, 'resume', None)
        if resume is not None and resume.schema_map and not resume.has_schema():
            self.objecttype_guid_map = dict(resume.schema_map)
        else:
            self.objecttype_guid_map = dict()

        if self.ldap is None:
            self.ldap_connect()

        prefixes = GUID_SLICES if self.partition_ldap else [None]
        for prefix in prefixes:
            if prefix and resume is not None and resume.slice_done('schema', prefix):
                logging.info('Skipping schema slice %s', prefix)
                continue
            if prefix:
                logging.info('Collecting schema slice %s', prefix)
            for res in self._iter_paged(self.ldap.server.info.other['schemaNamingContext'][0],
                                        guid_filter('(objectClass=*)', prefix),
                                        ['name', 'schemaidguid'],
                                        SUBTREE,
                                        None,
                                        100,
                                        False,
                                        False,
                                        'Schema',
                                        auto_escape=prefix is None):
                if res['attributes']['schemaIDGUID']:
                    guid = str(UUID(bytes_le=res['attributes']['schemaIDGUID']))
                    self.objecttype_guid_map[res['attributes']['name'].lower()] = guid
            if prefix and resume is not None:
                resume.set_schema(self.objecttype_guid_map)
                resume.mark_slice('schema', prefix)

        self._note_schema_features()
        logging.info('Schema: %d LDAP searches', ldap_search_count() - started)
        if resume is not None:
            resume.set_schema(self.objecttype_guid_map)
            resume.mark('schema')

    def restore_objecttype(self, guid_map):
        """
        Use a schema map saved in the resume checkpoint.
        """
        self.objecttype_guid_map = dict(guid_map)
        self._note_schema_features()

    def _note_schema_features(self):
        if 'ms-mcs-admpwdexpirationtime' in self.objecttype_guid_map:
            logging.debug('Found LAPS attributes in schema')
            self.ad.has_laps = True
        if 'ms-laps-passwordexpirationtime' in self.objecttype_guid_map:
            logging.debug('Found LAPSv2 attributes in schema')
            self.ad.has_lapsv2 = True
        if not self.ad.has_laps and not self.ad.has_lapsv2:
            logging.debug('No LAPS attributes found in schema')

        if 'ms-ds-key-credential-link' in self.objecttype_guid_map:
            logging.debug('Found KeyCredentialLink attributes in schema')
            self.ad.has_keycredlink = True
        else:
            logging.debug('No KeyCredentialLink attributes found in schema')

    def get_domains(self, acl=False):
        """
        Function to get domains. This should only return the current domain.
        """
        entries = self.search('(objectClass=domain)',
                              [],
                              generator=True,
                              query_sd=acl)

        entriesNum = 0
        for entry in entries:
            entriesNum += 1
            # Todo: actually use these objects instead of discarding them
            # means rewriting other functions
            domain_object = ADDomain.fromLDAP(entry['attributes']['distinguishedName'], entry['attributes']['objectSid'])
            self.ad.domain_object = domain_object
            self.ad.domains[entry['attributes']['distinguishedName']] = entry
            try:
                nbentry = self.get_netbios_name(entry['attributes']['distinguishedName'])
                if nbentry is not None:
                    self.ad.nbdomains[nbentry['attributes']['nETBIOSName']] = entry
            except IndexError:
                pass

        if entriesNum == 0:
            # Raise exception if we somehow managed to authenticate but the domain is wrong
            # prevents confusing exceptions later
            actualdn = self.ldap.server.info.other['defaultNamingContext'][0]
            actualdomain = ADUtils.ldap2domain(actualdn)
            logging.error('Could not find the requested domain %s on this DC, LDAP server reports is domain as %s (you may want to try that?)', self.ad.domain, actualdomain)
            raise CollectionException("Specified domain was not found in LDAP")

        logging.info('Found %u domains', entriesNum)

        return entries

    def get_forest_domains(self):
        """
        Function which searches the LDAP references in order to find domains.
        I'm not sure if this is the best function but couldn't find anything better.

        This searches the configuration, which is present only once in the forest but is replicated
        to every DC.
        """
        entries = self.search('(objectClass=crossRef)',
                              ['nETBIOSName', 'systemFlags', 'nCName', 'name'],
                              search_base="CN=Partitions,%s" % self.ldap.server.info.other['configurationNamingContext'][0],
                              generator=True)

        entriesNum = 0
        for entry in entries:
            # Ensure systemFlags entry is not empty before running the naming context check.
            if not entry['attributes']['systemFlags']:
                continue
            # This is a naming context, but not a domain
            if not entry['attributes']['systemFlags'] & 2:
                continue
            entry['attributes']['distinguishedName'] = entry['attributes']['nCName']
            entriesNum += 1
            # Todo: actually use these objects instead of discarding them
            # means rewriting other functions
            d = ADDomain.fromLDAP(entry['attributes']['nCName'])
            # We don't want to add our own domain since this entry doesn't contain the sid
            # which we need later on
            if entry['attributes']['nCName'] not in self.ad.domains:
                self.ad.domains[entry['attributes']['nCName']] = entry
                self.ad.nbdomains[entry['attributes']['nETBIOSName']] = entry

        # Store this number so we can easily determine if we are in a multi-domain
        # forest later on.
        self.ad.num_domains = entriesNum
        logging.info('Found %u domains in the forest', entriesNum)

    def get_cache_items(self):
        self.get_objecttype()
        self.get_forest_domains()
        self.gc_connect()
        sidcache = {}
        dncache = {}
        for nc, domain in self.ad.domains.items():
            logging.info('Processing domain %s', domain['attributes']['name'])
            query = '(|(&(objectCategory=person)(objectClass=user))(objectClass=group)(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))))'
            entries = self.search(query,
                                  use_gc=True,
                                  use_resolver=True,
                                  attributes=['sAMAccountName', 'distinguishedName', 'sAMAccountType', 'objectSid', 'name'],
                                  search_base=nc,
                                  generator=True)
            for lentry in entries:
                resolved_entry = ADUtils.resolve_ad_entry(lentry)
                cacheitem = {
                    "ObjectIdentifier": resolved_entry['objectid'],
                    "ObjectType": resolved_entry['type'].capitalize()
                }
                sidcache[resolved_entry['objectid']] = cacheitem
                dncache[ADUtils.get_entry_property(lentry, 'distinguishedName').upper()] = cacheitem
        return dncache, sidcache

    def count_exceeds(self, search_filter, threshold):
        search_base = self.ad.search_baseDN or self.ad.baseDN
        self.ldap.search(
            search_base,
            search_filter,
            attributes=['objectGUID'],
            search_scope=SUBTREE,
            paged_size=threshold + 1,
        )
        entries = [e for e in (self.ldap.response or [])
                   if e.get('type', '') != 'searchResRef']
        return len(entries), len(entries) > threshold

    def get_groups(self, include_properties=False, acl=False, guid_prefix=None):
        properties = ['distinguishedName', 'samaccountname', 'samaccounttype', 'objectsid', 'member']
        if include_properties:
            properties += ['adminCount', 'description', 'whencreated']
        if acl:
            properties += ['nTSecurityDescriptor']
        entries = self.search(guid_filter('(objectClass=group)', guid_prefix),
                              properties,
                              generator=True,
                              query_sd=acl,
                              auto_escape=guid_prefix is None)
        return entries

    def get_gpos(self, include_properties=False, acl=False, guid_prefix=None):
        properties = ['distinguishedName', 'name', 'objectGUID', 'gPCFileSysPath', 'displayName']
        if include_properties:
            properties += ['description', 'whencreated']
        if acl:
            properties += ['nTSecurityDescriptor']
        entries = self.search(guid_filter('(objectCategory=groupPolicyContainer)', guid_prefix),
                              properties,
                              generator=True,
                              query_sd=acl,
                              auto_escape=guid_prefix is None)
        return entries

    def get_ous(self, include_properties=False, acl=False, guid_prefix=None):
        properties = ['distinguishedName', 'name', 'objectGUID', 'gPLink', 'gPOptions']
        if include_properties:
            properties += ['description', 'whencreated']
        if acl:
            properties += ['nTSecurityDescriptor']
        entries = self.search(guid_filter('(objectCategory=organizationalUnit)', guid_prefix),
                              properties,
                              generator=True,
                              query_sd=acl,
                              auto_escape=guid_prefix is None)
        return entries

    def get_containers(self, include_properties=False, acl=False, dn='', guid_prefix=None):
        properties = ['distinguishedName', 'name', 'objectGUID', 'isCriticalSystemObject','objectClass', 'objectCategory']
        if include_properties:
            properties += ['description', 'whencreated']
        if acl:
            properties += ['nTSecurityDescriptor']
        entries = self.search(guid_filter('(&(objectCategory=container)(objectClass=container))', guid_prefix),
                              properties,
                              generator=True,
                              query_sd=acl,
                              search_base=dn,
                              auto_escape=guid_prefix is None)
        return entries

    def get_users(self, include_properties=False, acl=False, guid_prefix=None):

        properties = ['sAMAccountName', 'distinguishedName', 'sAMAccountType',
                      'objectSid', 'primaryGroupID', 'isDeleted', 'objectClass']
        if 'ms-DS-GroupMSAMembership'.lower() in self.objecttype_guid_map:
            properties.append('msDS-GroupMSAMembership')

        if include_properties:
            properties += ['servicePrincipalName', 'userAccountControl', 'displayName',
                           'lastLogon', 'lastLogonTimestamp', 'pwdLastSet', 'mail', 'title', 'homeDirectory',
                           'description', 'userPassword', 'adminCount', 'msDS-AllowedToDelegateTo', 'sIDHistory',
                           'whencreated', 'unicodepwd', 'scriptpath']
            if 'unixuserpassword' in self.objecttype_guid_map:
                properties.append('unixuserpassword')
        if acl:
            properties.append('nTSecurityDescriptor')

        # Query for MSA only if server supports it
        if 'msDS-GroupManagedServiceAccount' in self.ldap.server.schema.object_classes:
            gmsa_filter = '(objectClass=msDS-GroupManagedServiceAccount)'
        else:
            logging.debug('No support for GMSA, skipping in query')
            gmsa_filter = ''

        if 'msDS-ManagedServiceAccount' in self.ldap.server.schema.object_classes:
            smsa_filter = '(objectClass=msDS-ManagedServiceAccount)'
        else:
            logging.debug('No support for SMSA, skipping in query')
            smsa_filter = ''

        if gmsa_filter or smsa_filter:
            query = '(|(&(objectCategory=person)(objectClass=user)){}{})'.format(gmsa_filter, smsa_filter)
        else:
            query = '(&(objectCategory=person)(objectClass=user))'
        entries = self.search(guid_filter(query, guid_prefix),
                              properties,
                              generator=True,
                              query_sd=acl,
                              auto_escape=guid_prefix is None)
        return entries


    def get_computers(self, include_properties=False, acl=False, guid_prefix=None):
        """
        Get all computer objects. This purely gets them using LDAP. This function is used directly in case of DCOnly enum,
        or used to create a cache in case of computer enumeration later on.
        """
        properties = ['samaccountname', 'userAccountControl', 'distinguishedname',
                      'dnshostname', 'samaccounttype', 'objectSid', 'primaryGroupID',
                      'isDeleted']
        if include_properties:
            properties += ['servicePrincipalName', 'msDS-AllowedToDelegateTo', 'sIDHistory', 'whencreated',
                           'lastLogon', 'lastLogonTimestamp', 'pwdLastSet', 'operatingSystem', 'description',
                           'operatingSystemServicePack', 'operatingSystemVersion']
            # Difference between guid map which maps the lowercase schema object name and the property name itself
            if 'ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity'.lower() in self.objecttype_guid_map:
                properties.append('msDS-AllowedToActOnBehalfOfOtherIdentity')
            if self.ad.has_laps:
                properties.append('ms-mcs-admpwdexpirationtime')
            if self.ad.has_lapsv2:
                properties.append('mslaps-passwordexpirationtime')
        if acl:
            # Also collect LAPS expiration time since this matters for reporting (no LAPS = no ACL reported)
            if self.ad.has_laps:
                properties.append('ms-mcs-admpwdexpirationtime')
            if self.ad.has_lapsv2:
                properties.append('mslaps-passwordexpirationtime')
            properties.append('nTSecurityDescriptor')

        # Exclude MSA only if server supports it
        if 'msDS-GroupManagedServiceAccount' in self.ldap.server.schema.object_classes:
            gmsa_filter = '(!(objectClass=msDS-GroupManagedServiceAccount))'
        else:
            gmsa_filter = ''

        if 'msDS-ManagedServiceAccount' in self.ldap.server.schema.object_classes:
            smsa_filter = '(!(objectClass=msDS-ManagedServiceAccount))'
        else:
            smsa_filter = ''

        if gmsa_filter or smsa_filter:
            query = '(&(sAMAccountType=805306369){}{})'.format(gmsa_filter, smsa_filter)
        else:
            query = '(&(sAMAccountType=805306369))'

        entries = self.search(guid_filter(query, guid_prefix),
                              properties,
                              generator=True,
                              query_sd=acl,
                              auto_escape=guid_prefix is None)

        return entries

    def get_computers_withcache(self, include_properties=False, acl=False):
        """
        Get all computer objects. This is the function used when we do computer enumeration, in which case these
        items are cached first. Calls the function with generator above to create the list.
        """

        entries = self.get_computers(include_properties, acl)

        entriesNum = 0
        for entry in entries:
            entriesNum += 1
            # Resolve it first for DN cache
            resolved_entry = ADUtils.resolve_ad_entry(entry)
            cacheitem = {
                "ObjectIdentifier": resolved_entry['objectid'],
                "ObjectType": resolved_entry['type'].capitalize()
            }
            self.ad.dncache[ADUtils.get_entry_property(entry, 'distinguishedName', '').upper()] = cacheitem
            # This list is used to process computers later on
            self.ad.computers[ADUtils.get_entry_property(entry, 'distinguishedName', '')] = entry
            self.ad.computersidcache.put(ADUtils.get_entry_property(entry, 'dNSHostname', '').lower(), entry['attributes']['objectSid'])

        logging.info('Found %u computers', entriesNum)

        return entries

    def get_memberships(self):
        entries = self.search('(|(memberof=*)(primarygroupid=*))',
                              ['samaccountname', 'distinguishedname',
                               'dnshostname', 'samaccounttype', 'primarygroupid',
                               'memberof'],
                              generator=False)
        return entries

    def get_sessions(self):
        entries = self.search('(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))',
                              ['homedirectory', 'scriptpath', 'profilepath'])
        return entries

    def get_childobjects(self, dn, use_resolver=True):
        entries = self.search('(|(objectClass=container)(objectClass=organizationalUnit)(sAMAccountType=805306369)(objectClass=group)(&(objectCategory=person)(objectClass=user)))',
                              attributes=['objectSid', 'objectClass', 'objectGUID', 'distinguishedName', 'sAMAccountName', 'sAMAccountType'],
                              search_base=dn,
                              search_scope=LEVEL,
                              use_resolver=use_resolver)
                              
        return entries

    def get_trusts(self):
        entries = self.search('(objectClass=trustedDomain)',
                              attributes=['flatName', 'name', 'securityIdentifier', 'trustAttributes', 'trustDirection', 'trustType'],
                              generator=True)
        return entries

    def prefetch_info(self, props=False, acls=False, cache_computers=False, skip_schema=False):
        if not skip_schema:
            self.get_objecttype()
        started = ldap_search_count()
        self.get_domains(acl=acls)
        self.get_forest_domains()
        logging.info('Domain lookup: %d LDAP searches', ldap_search_count() - started)
        if cache_computers:
            started = ldap_search_count()
            self.get_computers_withcache(include_properties=props, acl=acls)
            logging.info('Computer cache: %d LDAP searches', ldap_search_count() - started)

    def get_root_domain(self):
        return ADUtils.ldap2domain(self.ldap.server.info.other['configurationNamingContext'][0])


"""
Active Directory data and cache
"""
class AD(object):

    def __init__(self, domain=None, auth=None, nameserver=None, dns_tcp=False, dns_timeout=3.0, use_ldaps=False):
        self.domain = domain
        # Object of type ADDomain, added later
        self.domain_object = None
        self.auth = auth
        # List of DCs for this domain. Contains just one DC since
        # we query for the primary DC specifically
        self._dcs = []
        # Kerberos servers
        self._kdcs = []
        # Global catalog servers
        self._gcs = []

        self.domains = {}
        self.nbdomains = {}
        self.groups = {} # Groups by DN
        self.groups_dnmap = {} # Group mapping from gid to DN
        self.computers = {}
        self.users = {} # Users by DN

        # Create a resolver object
        self.dnsresolver = resolver.Resolver()
        if nameserver:
            self.dnsresolver.nameservers = [nameserver]
        # Resolve DNS over TCP?
        self.dns_tcp = dns_tcp
        # Give it a cache to prevent duplicate lookups
        self.dnsresolver.cache = resolver.Cache()
        # Default timeout after 3 seconds if the DNS servers
        # do not come up with an answer
        self.dnsresolver.timeout = float(dns_timeout)
        self.dnsresolver.lifetime = float(dns_timeout)
        # Also create a custom cache for both forward and backward lookups
        # this cache is thread-safe
        self.dnscache = DNSCache()
        # Create a thread-safe SID lookup cache
        self.sidcache = SidCache()
        # Create a thread-safe SAM lookup cache
        self.samcache = SamCache()
        # DN cache dict - use generic cache for all objects
        # holds only direct bloodhound output
        self.dncache = {}
        self.newsidcache = SidCache()
        # Create SID cache for computer accounts
        self.computersidcache = SidCache()
        # Object Resolver, initialized later
        self.objectresolver = None
        # Number of domains within the forest
        self.num_domains = 1
        # Does the schema have laps properties
        self.has_laps = False
        # Does the schema have lapsv2 properties
        self.has_lapsv2 = False
        # Does the schema have msDS-KeyCredentialLink
        self.has_keycredlink = False
        if domain is not None:
            self.baseDN = ADUtils.domain2ldap(domain)
        else:
            self.baseDN = None
        if use_ldaps:
            self.ldap_default_protocol = 'ldaps'
        else:
            self.ldap_default_protocol = 'ldap'
        # ldapx mode: local (host, port) listeners. When set, ldap_connect and
        # gc_connect dial these instead of resolving and probing the DC.
        self.ldap_listener = None
        self.gc_listener = None
        self.search_baseDN = None

    def realm(self):
        if self.domain is not None:
            return self.domain.upper()
        else:
            return None

    def override_dc(self, dcname):
        self._dcs = [dcname]

    def override_gc(self, gcname):
        self._gcs = [gcname]

    def dcs(self):
        return self._dcs

    def gcs(self):
        return self._gcs

    def kdcs(self):
        return self._kdcs

    def create_objectresolver(self, addc):
        self.objectresolver = ObjectResolver(addomain=self, addc=addc)

    def load_cachefile(self, cachefile):
        with codecs.open(cachefile, 'r', 'utf-8') as cfile:
            cachedata = json.load(cfile)
        self.dncache = cachedata['dncache']
        self.newsidcache.load(cachedata['sidcache'])
        logging.info('Loaded cached DNs and SIDs from cachefile')

    def save_cachefile(self, cachefile):
        pass

    def dns_resolve(self, domain=None, options=None):
        logging.debug('Querying domain controller information from DNS')

        basequery = '_ldap._tcp.pdc._msdcs'
        ad_domain = None

        if domain:
            logging.debug('Using domain hint: %s' % str(domain))
            query = '_ldap._tcp.pdc._msdcs.%s.' % domain
        else:
            # Assume a DNS search domain is (correctly) configured on the host
            # in which case the resolver will autocomplete our request
            query = basequery

        try:

            q = self.dnsresolver.query(query, 'SRV', tcp=self.dns_tcp)

            if str(q.qname).lower().startswith('_ldap._tcp.pdc._msdcs'):
                ad_domain = str(q.qname).lower()[len(basequery):].strip('.')
                logging.info('Found AD domain: %s' % ad_domain)

                self.domain = ad_domain
                if not self.auth.domain:
                    self.auth.domain = ad_domain
                if not self.auth.userdomain:
                    self.auth.userdomain = ad_domain
                self.baseDN = ADUtils.domain2ldap(ad_domain)

            for r in q:
                dc = str(r.target).rstrip('.')
                logging.debug('Found primary DC: %s' % dc)
                if dc not in self._dcs:
                    self._dcs.append(dc)

        except resolver.NXDOMAIN:
            pass

        try:
            q = self.dnsresolver.query(query.replace('pdc','gc'), 'SRV', tcp=self.dns_tcp)
            for r in q:
                gc = str(r.target).rstrip('.')
                logging.debug('Found Global Catalog server: %s' % gc)
                if gc not in self._gcs:
                    self._gcs.append(gc)

        except resolver.NXDOMAIN:
            # Only show warning if we don't already have a GC specified manually
            if options and not options.global_catalog:
                if not options.disable_autogc:
                    logging.warning('Could not find a global catalog server, assuming the primary DC has this role\n'
                                    'If this gives errors, either specify a hostname with -gc or disable gc resolution with --disable-autogc')
                    self._gcs = self._dcs
                else:
                    logging.warning('Could not find a global catalog server. Please specify one with -gc')

        try:
            kquery = query.replace('pdc','dc').replace('_ldap','_kerberos')
            q = self.dnsresolver.query(kquery, 'SRV', tcp=self.dns_tcp)
            # TODO: Get the additional records here to get the DC ip immediately
            for r in q:
                kdc = str(r.target).rstrip('.')
                logging.debug('Found KDC for enumeration domain: %s' % str(r.target).rstrip('.'))
                if kdc not in self._kdcs:
                    self._kdcs.append(kdc)
                    self.auth.kdc = self._kdcs[0]
        except resolver.NXDOMAIN:
            pass

        # Fix for below in case domain was not found via DNS
        if not ad_domain:
            if domain:
                ad_domain = domain
            else:
                ad_domain = 'unknown'

        if self.auth.userdomain and self.auth.userdomain.lower() != ad_domain.lower():
            # Resolve KDC for user auth domain
            kquery = '_kerberos._tcp.dc._msdcs.%s.' % self.auth.userdomain
            q = self.dnsresolver.query(kquery, 'SRV', tcp=self.dns_tcp)
            for r in q:
                kdc = str(r.target).rstrip('.')
                logging.debug('Found KDC for user: %s' % str(r.target).rstrip('.'))
                self.auth.userdomain_kdc = kdc
        else:
            self.auth.userdomain_kdc = self.auth.kdc

        return True


    def get_domain_by_name(self, name):
        for domain, entry in self.domains.items():
            if 'name' in entry['attributes']:
                if entry['attributes']['name'].upper() == name.upper():
                    return entry
        # Also try domains by NETBIOS definition
        for domain, entry in self.nbdomains.items():
            if domain.upper() == name.upper():
                return entry
        return None


    def get_dn_from_cache_or_ldap(self, distinguishedname):
        try:
            linkentry = self.dncache[distinguishedname.upper()]
        except KeyError:
            use_gc = ADUtils.ldap2domain(distinguishedname).lower() != self.domain.lower()
            qobject = self.objectresolver.resolve_distinguishedname(distinguishedname, use_gc=use_gc)
            if qobject is None:
                return None
            resolved_entry = ADUtils.resolve_ad_entry(qobject)
            if not resolved_entry['objectid']:
                return None
            linkentry = {
                "ObjectIdentifier": resolved_entry['objectid'],
                "ObjectType": resolved_entry['type'].capitalize()
            }
            self.dncache[distinguishedname.upper()] = linkentry
        return linkentry

"""
Active Directory Domain
"""
class ADDomain(object):
    def __init__(self, name=None, netbios_name=None, sid=None, distinguishedname=None):
        self.name = name
        self.netbios_name = netbios_name
        self.sid = sid
        self.distinguishedname = distinguishedname


    @staticmethod
    def fromLDAP(identifier, sid=None):
        dns_name = ADUtils.ldap2domain(identifier)
        return ADDomain(name=dns_name, sid=sid, distinguishedname=identifier)
