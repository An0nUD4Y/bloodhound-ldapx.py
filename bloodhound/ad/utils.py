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
import logging
import socket
import threading
import time
import random
import re
import dns
from dns import resolver, reversename
from bloodhound.ad.structures import LDAP_SID
from bloodhound.ad.dumpntlm import DumpNtlm
from impacket.dcerpc.v5 import transport, wkst

"""
"""
class ADUtils(object):
    WELLKNOWN_SIDS = {
        "S-1-0": ("Null Authority", "USER"),
        "S-1-0-0": ("Nobody", "USER"),
        "S-1-1": ("World Authority", "USER"),
        "S-1-1-0": ("Everyone", "GROUP"),
        "S-1-2": ("Local Authority", "USER"),
        "S-1-2-0": ("Local", "GROUP"),
        "S-1-2-1": ("Console Logon", "GROUP"),
        "S-1-3": ("Creator Authority", "USER"),
        "S-1-3-0": ("Creator Owner", "USER"),
        "S-1-3-1": ("Creator Group", "GROUP"),
        "S-1-3-2": ("Creator Owner Server", "COMPUTER"),
        "S-1-3-3": ("Creator Group Server", "COMPUTER"),
        "S-1-3-4": ("Owner Rights", "GROUP"),
        "S-1-4": ("Non-unique Authority", "USER"),
        "S-1-5": ("NT Authority", "USER"),
        "S-1-5-1": ("Dialup", "GROUP"),
        "S-1-5-2": ("Network", "GROUP"),
        "S-1-5-3": ("Batch", "GROUP"),
        "S-1-5-4": ("Interactive", "GROUP"),
        "S-1-5-6": ("Service", "GROUP"),
        "S-1-5-7": ("Anonymous", "GROUP"),
        "S-1-5-8": ("Proxy", "GROUP"),
        "S-1-5-9": ("Enterprise Domain Controllers", "GROUP"),
        "S-1-5-10": ("Principal Self", "USER"),
        "S-1-5-11": ("Authenticated Users", "GROUP"),
        "S-1-5-12": ("Restricted Code", "GROUP"),
        "S-1-5-13": ("Terminal Server Users", "GROUP"),
        "S-1-5-14": ("Remote Interactive Logon", "GROUP"),
        "S-1-5-15": ("This Organization", "GROUP"),
        "S-1-5-17": ("IUSR", "USER"),
        "S-1-5-18": ("Local System", "USER"),
        "S-1-5-19": ("NT Authority", "USER"),
        "S-1-5-20": ("Network Service", "USER"),
        "S-1-5-80-0": ("All Services ", "GROUP"),
        "S-1-5-32-544": ("Administrators", "GROUP"),
        "S-1-5-32-545": ("Users", "GROUP"),
        "S-1-5-32-546": ("Guests", "GROUP"),
        "S-1-5-32-547": ("Power Users", "GROUP"),
        "S-1-5-32-548": ("Account Operators", "GROUP"),
        "S-1-5-32-549": ("Server Operators", "GROUP"),
        "S-1-5-32-550": ("Print Operators", "GROUP"),
        "S-1-5-32-551": ("Backup Operators", "GROUP"),
        "S-1-5-32-552": ("Replicators", "GROUP"),
        "S-1-5-32-554": ("Pre-Windows 2000 Compatible Access", "GROUP"),
        "S-1-5-32-555": ("Remote Desktop Users", "GROUP"),
        "S-1-5-32-556": ("Network Configuration Operators", "GROUP"),
        "S-1-5-32-557": ("Incoming Forest Trust Builders", "GROUP"),
        "S-1-5-32-558": ("Performance Monitor Users", "GROUP"),
        "S-1-5-32-559": ("Performance Log Users", "GROUP"),
        "S-1-5-32-560": ("Windows Authorization Access Group", "GROUP"),
        "S-1-5-32-561": ("Terminal Server License Servers", "GROUP"),
        "S-1-5-32-562": ("Distributed COM Users", "GROUP"),
        "S-1-5-32-568": ("IIS_IUSRS", "GROUP"),
        "S-1-5-32-569": ("Cryptographic Operators", "GROUP"),
        "S-1-5-32-573": ("Event Log Readers", "GROUP"),
        "S-1-5-32-574": ("Certificate Service DCOM Access", "GROUP"),
        "S-1-5-32-575": ("RDS Remote Access Servers", "GROUP"),
        "S-1-5-32-576": ("RDS Endpoint Servers", "GROUP"),
        "S-1-5-32-577": ("RDS Management Servers", "GROUP"),
        "S-1-5-32-578": ("Hyper-V Administrators", "GROUP"),
        "S-1-5-32-579": ("Access Control Assistance Operators", "GROUP"),
        "S-1-5-32-580": ("Access Control Assistance Operators", "GROUP"),
        "S-1-5-32-582": ("Storage Replica Administrators", "GROUP")
    }

    FUNCTIONAL_LEVELS = {
        0: "2000 Mixed/Native",
        1: "2003 Interim",
        2: "2003",
        3: "2008",
        4: "2008 R2",
        5: "2012",
        6: "2012 R2",
        7: "2016"
    }

    xml_sid_rex = re.compile('<UserId>(S-[0-9\\-]+)</UserId>')
    xml_logontype_rex = re.compile('<LogonType>([A-Za-z0-9]+)</LogonType>')

    @staticmethod
    def domain2ldap(domain):
        return 'DC=' + ',DC='.join(str(domain).rstrip('.').split('.'))


    @staticmethod
    def ldap2domain(ldap):
        return re.sub(',DC=', '.', ldap[ldap.find('DC='):], flags=re.I)[3:]


    @staticmethod
    def tcp_ping(host, port, timeout=1.0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()
            return True
        except KeyboardInterrupt:
            raise
        except:
            return False

    @staticmethod
    def ip2host(ip, resolver=resolver, use_tcp=False):
        result = ip
        try:
            addr = reversename.from_address(ip)
        except dns.exception.SyntaxError:
            logging.warning('DNS: invalid address: %s' % ip)
            return result

        try:
            answer = str(resolver.query(addr, 'PTR', tcp=use_tcp)[0])
            result = answer.rstrip('.')
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
            pass
        except:
            logging.warning('DNS lookup failed: %s' % addr)
            pass

        return result

    @staticmethod
    def rpc_get_hostname(ip, adauth):
        '''
        Authenticated hostname resolution. Requires admin rights.
        Currently not in use - does not respect authentication stack
        '''
        result = ip

        binding = r'ncacn_np:%s[\PIPE\wkssvc]' % ip
        rpctransportWkst = transport.DCERPCTransportFactory(binding)
        if hasattr(rpctransportWkst, 'set_credentials'):
            rpctransportWkst.set_credentials(adauth.username, adauth.password, 
                                adauth.domain, adauth.lm_hash, adauth.nt_hash, adauth.aes_key)
            rpctransportWkst.set_kerberos(False, adauth.kdc) # not supported yet
        dce = rpctransportWkst.get_dce_rpc()

        try:
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)
            resp = wkst.hNetrWkstaGetInfo(dce, 100)

            result = resp['WkstaInfo']['WkstaInfo100']['wki100_computername'][:-1]
            domain_name = resp['WkstaInfo']['WkstaInfo100']['wki100_langroup'][:-1]
            if '.' in domain_name: # not workgroup
                result = '.'.join([result, domain_name])

            dce.disconnect()
        except:
            logging.warning('WkstaGetInfo failed: %s' % ip)
            pass

        return result

    @staticmethod
    def get_ntlm_hostname(ip):
        '''
        Unauthenticated hostname resolution with NTLM challenge/response
        '''
        def parse_info(info):
            if not info:
                return info
            if 'dns_host' in info:
                return info['dns_host'].lower()
            elif 'name' in info:
                result = info['name']
                if 'dns_domain' in info and '.' in info['dns_domain']:
                    result = '.'.join((result, info['dns_domain']))
                return result.lower()
            return None
        
        try:
            ntlm_dumper = DumpNtlm(ip, ip, 445)
            hostname = parse_info(ntlm_dumper.GetInfo())
            if hostname:
                return hostname
        except:
            pass

        try:
            ntlm_dumper = DumpNtlm(ip, ip, 139)
            hostname = parse_info(ntlm_dumper.GetInfo())
            if hostname:
                return hostname
        except:
            pass

        try:
            ntlm_dumper = DumpNtlm(ip, ip, 135)
            hostname = parse_info(ntlm_dumper.GetInfo())
            if hostname:
                return hostname
        except:
            pass

        return ip

    # Translate the binary SID from LDAP into human-readable form
    @staticmethod
    def formatSid(siddata):
        return LDAP_SID(siddata).formatCanonical()

    # Translate SidType to strings accepted by BloodHound
    @staticmethod
    def translateSidType(sidType):
        if sidType == 1:
            return 'User'
        if sidType == 2:
            return 'Group'
        # sidType 4 means "alias", this is actually a Domain Local Group
        if sidType == 4:
            return 'Group'
        if sidType == 9:
            return 'Computer'
        if sidType == 5:
            return 'Wellknown'
        # Can be a (by BloudHound) unsupported type
        # must not be an empty string since this breaks our CSV files
        return 'Unknown'

    @staticmethod
    def is_dc(entry):
        """
        Check whether the computer object is a Domain Controller
        """
        uac = ADUtils.get_entry_property(entry, 'userAccountControl', default=0)
        return uac & 0x00002000 == 0x00002000

    @staticmethod
    def resolve_ad_entry(entry):
        """
        Translate an LDAP entry into a dictionary containing the
        information used by BloodHound
        """
        resolved = {}
        dn = ''
        domain = ''

        account = ADUtils.get_entry_property(entry, 'sAMAccountName', '')
        dn = ADUtils.get_entry_property(entry, 'distinguishedName', '')
        if dn != '':
            domain = ADUtils.ldap2domain(dn)
        resolved['objectid'] = ADUtils.get_entry_property(entry, 'objectSid', '')
        resolved['principal'] = ('%s@%s' % (account, domain)).upper()
        if not ADUtils.get_entry_property(entry, 'sAMAccountName'):
            if 'ForeignSecurityPrincipals' in dn and not 'container' in ADUtils.get_entry_property(entry, 'objectClass', []):
                resolved['principal'] = domain.upper()
                resolved['type'] = 'foreignsecurityprincipal'
                ename = ADUtils.get_entry_property(entry, 'name')
                if ename:
                    # Fix wellknown entries
                    if ename in ADUtils.WELLKNOWN_SIDS:
                        name, sidtype = ADUtils.WELLKNOWN_SIDS[ename]
                        resolved['type'] = sidtype.capitalize()
                        resolved['principal'] = ('%s@%s' % (name, domain)).upper()
                        # Well-known have the domain prefix since 3.0
                        resolved['objectid'] = '%s-%s' % (domain.upper(), resolved['objectid'])
                    else:
                        # Foreign security principal
                        resolved['objectid'] = ename
            elif ADUtils.get_entry_property(entry, 'objectGUID'):
                resolved['objectid'] = ADUtils.get_entry_property(entry, 'objectGUID', '').upper()[1:-1]
                resolved['principal'] = ('%s@%s' % (ADUtils.get_entry_property(entry, 'name', ''), domain)).upper()
                object_class = ADUtils.get_entry_property(entry, 'objectClass', [])
                if 'organizationalUnit' in object_class:
                    resolved['type'] = 'OU'
                elif 'container' in object_class:
                    resolved['type'] = 'Container'
                else:
                    resolved['type'] = 'Base'
            else:
                resolved['type'] = 'Base'
        else:
            accountType = ADUtils.get_entry_property(entry, 'sAMAccountType')
            object_class = ADUtils.get_entry_property(entry, 'objectClass', [])
            if accountType in [268435456, 268435457, 536870912, 536870913]:
                resolved['type'] = 'Group'
            elif accountType in [805306368] or \
                 'msDS-GroupManagedServiceAccount' in object_class or \
                 'msDS-ManagedServiceAccount' in object_class:
                resolved['type'] = 'User'
            elif accountType in [805306369]:
                resolved['type'] = 'Computer'
                short_name = account.rstrip('$')
                resolved['principal'] = ('%s.%s' % (short_name, domain)).upper()
            elif accountType in [805306370]:
                resolved['type'] = 'trustaccount'
            else:
                resolved['type'] = 'Domain'

        return resolved

    @staticmethod
    def resolve_sid_entry(entry, domain):
        """
        Convert LsarLookupSids entries to entries for the SID cache, which should match
        the format from the resolve_ad_entry function.
        """
        resolved = {}
        account = entry['Name']

        resolved['principal'] = ('%s@%s' % (account, domain)).upper()
        resolved['type'] = ADUtils.translateSidType(entry['Use']).lower()

        # Computer accounts have a different type
        if resolved['type'] == 'computer':
            short_name = account.rstrip('$')
            resolved['principal'] = ('%s.%s' % (short_name, domain)).upper()

        return resolved

    @staticmethod
    def get_entry_property(entry, prop, default=None, raw=False):
        """
        Simple wrapper that gets an attribute from ldap3 dictionary,
        converting empty values to the default specified. This is primarily
        for output to JSON
        """
        if entry is None:
            return default
        try:
            if raw:
                value = entry['raw_attributes'][prop]
            else:
                value = entry['attributes'][prop]
        # Doesn't exist
        except KeyError:
            return default
        # Empty -> return default
        if value == []:
            return default
        try:
            # One value and we don't expect a list -> return the first value
            if len(value) == 1 and default != []:
                return value[0]
        except TypeError:
            # Value doesn't have a len() attribute, so we skip this
            pass
        return value

    @staticmethod
    def win_timestamp_to_unix(seconds):
        """
        Convert Windows timestamp (100 ns since 1 Jan 1601) to
        unix timestamp.
        """
        seconds = int(seconds)
        if seconds == 0:
            return 0
        return int((seconds - 116444736000000000) / 10000000)

    @staticmethod
    def parse_task_xml(xml):
        """
        Parse scheduled task XML and extract the user and logon type with
        regex. Is not a good way to parse XMLs but saves us the whole parsing
        overhead.
        """
        res = ADUtils.xml_sid_rex.search(xml)
        if not res:
            return None
        sid = res.group(1)
        res = ADUtils.xml_logontype_rex.search(xml)
        if not res:
            return None
        logon_type = res.group(1)
        return (sid, logon_type)

    @staticmethod
    def ensure_string(data):
        """
        Sometimes properties can contain binary data. Since we can't assume encoding, make
        sure it can be outputted as json
        """
        if isinstance(data, bytes):
            data = repr(data)
        elif isinstance(data, list):
            data = list(map(lambda x: repr(x) if isinstance(x, bytes) else x,data))
        return data

    @staticmethod
    def is_filtered_container(containerdn):
        if not containerdn:
            return False
        if "CN=DOMAINUPDATES,CN=SYSTEM,DC=" in containerdn.upper():
            return True
        if "CN=POLICIES,CN=SYSTEM,DC=" in containerdn.upper() and (containerdn.upper().startswith('CN=USER') or containerdn.upper().startswith('CN=MACHINE')):
            return True
        return False

    @staticmethod
    def is_filtered_container_child(containerdn):
        if not containerdn:
            return False
        if "CN=PROGRAM DATA,DC=" in containerdn.upper():
            return True
        if "CN=SYSTEM,DC=" in containerdn.upper():
            return True
        return False

    @staticmethod
    def parse_gplink_string(linkstr):
        '''
        Parse GP Link string according to MS-GPOL
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/08090b22-bc16-49f4-8e10-f27a8fb16d18
        '''
        if not linkstr:
            return
        for links in linkstr.split('LDAP://')[1:]:
            dn, options = links.rstrip('][ ').split(';')
            yield dn, int(options)

class AceResolver(object):
    """
    This class resolves ACEs containing rights, acetype and a SID to Aces containing
    BloodHound principals, which can be outputted to json.
    This is mostly a wrapper around the sid resolver calls
    """
    def __init__(self, addomain, resolver):
        self.addomain = addomain
        self.resolver = resolver

    def resolve_aces(self, aces):
        aces_out = []
        for ace in aces:
            out = {
                'RightName': ace['rightname'],
                'IsInherited': ace['inherited']
            }
            # Is it a well-known sid?
            if ace['sid'] in ADUtils.WELLKNOWN_SIDS:
                out['PrincipalSID'] = u'%s-%s' % (self.addomain.domain.upper(), ace['sid'])
                out['PrincipalType'] = ADUtils.WELLKNOWN_SIDS[ace['sid']][1].capitalize()
            else:
                try:
                    linkitem = self.addomain.newsidcache.get(ace['sid'])
                except KeyError:
                    # Look it up instead
                    # Is this SID part of the current domain? If not, use GC
                    use_gc = not ace['sid'].startswith(self.addomain.domain_object.sid)
                    ldapentry = self.resolver.resolve_sid(ace['sid'], use_gc)
                    # Couldn't resolve...
                    if not ldapentry:
                        logging.debug('Could not resolve SID: %s', ace['sid'])
                        # Fake it
                        entry = {
                            'type': 'Base',
                            'objectid': ace['sid']
                        }
                    else:
                        entry = ADUtils.resolve_ad_entry(ldapentry)
                    linkitem = {
                        "ObjectIdentifier": entry['objectid'],
                        "ObjectType": entry['type'].capitalize()
                    }
                    # Entries are cached regardless of validity - unresolvable sids
                    # are not likely to be resolved the second time and this saves traffic
                    self.addomain.newsidcache.put(ace['sid'], linkitem)
                out['PrincipalSID'] = ace['sid']
                out['PrincipalType'] = linkitem['ObjectType']
            aces_out.append(out)
        return aces_out

    def resolve_sid(self, sid):
        # Resolve SIDs for SID history purposes
        out = {}
        # Is it a well-known sid?
        if sid in ADUtils.WELLKNOWN_SIDS:
            out['ObjectIdentifier'] = u'%s-%s' % (self.addomain.domain.upper(), sid)
            out['ObjectType'] = ADUtils.WELLKNOWN_SIDS[sid][1].capitalize()
        else:
            try:
                linkitem = self.addomain.newsidcache.get(sid)
            except KeyError:
                # Look it up instead
                # Is this SID part of the current domain? If not, use GC
                use_gc = not sid.startswith(self.addomain.domain_object.sid)
                ldapentry = self.resolver.resolve_sid(sid, use_gc)
                # Couldn't resolve...
                if not ldapentry:
                    logging.debug('Could not resolve SID: %s', sid)
                    # Fake it
                    entry = {
                        'type': 'Base',
                        'objectid':sid
                    }
                else:
                    entry = ADUtils.resolve_ad_entry(ldapentry)
                linkitem = {
                    "ObjectIdentifier": entry['objectid'],
                    "ObjectType": entry['type'].capitalize()
                }
                # Entries are cached regardless of validity - unresolvable sids
                # are not likely to be resolved the second time and this saves traffic
                self.addomain.newsidcache.put(sid, linkitem)
            out['ObjectIdentifier'] = sid
            out['ObjectType'] = linkitem['ObjectType']
        return out

class DNSCache(object):
    """
    A cache used for caching forward and backward DNS at the same time.
    This cache is used to avoid PTR queries when forward lookups are already done
    """
    def __init__(self):
        self.lock = threading.Lock()
        self._cache = {}

    # Get an entry from the cache
    def get(self, entry):
        with self.lock:
            return self._cache[entry]

    # Put a forward lookup in the cache, this also
    # puts the reverse lookup in the cache
    def put(self, entry, value):
        with self.lock:
            self._cache[entry] = value
            self._cache[value] = entry

    # Put a reverse lookup in the cache. Forward lookup
    # is not added since reverse is considered less reliable
    def put_single(self, entry, value):
        with self.lock:
            self._cache[entry] = value

class SidCache(object):
    """
    Generic cache for caching SID lookups
    """
    def __init__(self):
        self.lock = threading.Lock()
        self._cache = {}

    # Get an entry from the cache
    def get(self, entry):
        with self.lock:
            return self._cache[entry]

    # Put a forward lookup in the cache, this also
    # puts the reverse lookup in the cache
    def put(self, entry, value):
        with self.lock:
            self._cache[entry] = value

    # Overwrite cache from disk
    def load(self, cache):
        self._cache = cache

class SamCache(SidCache):
    """
    Cache for mapping SAM names to principals.
    Identical to the SidCache in behaviour
    """
    pass

class CollectionException(Exception):
    pass


def parse_ldap_interval(value, flag='--ldap-interval'):
    """
    Parse a duration flag into seconds (float).

    A plain number is seconds. A trailing 's', 'm' or 'h' sets the unit.
    Raises ValueError on anything else, so the caller can turn it into a
    parser.error() instead of a traceback.
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        raise ValueError('%s cannot be empty' % flag)
    units = {'s': 1.0, 'm': 60.0, 'h': 3600.0}
    unit = 1.0
    if text[-1] in units:
        unit = units[text[-1]]
        text = text[:-1]
    try:
        amount = float(text)
    except ValueError:
        raise ValueError('Invalid %s %r (use e.g. 300, 300s, 5m, 1h)' % (flag, value))
    seconds = amount * unit
    if seconds <= 0:
        raise ValueError('%s must be greater than 0' % flag)
    return seconds


def parse_throttle(value):
    """
    Parse --throttle into milliseconds.

    A plain number is milliseconds. Suffixes ms, s, m and h set the unit
    (500, 500ms, 2s, 1m, 1h).
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        raise ValueError('--throttle cannot be empty')
    if text.endswith('ms'):
        unit = 1.0
        text = text[:-2]
    elif text.endswith('h'):
        unit = 3600000.0
        text = text[:-1]
    elif text.endswith('m'):
        unit = 60000.0
        text = text[:-1]
    elif text.endswith('s'):
        unit = 1000.0
        text = text[:-1]
    else:
        unit = 1.0
    try:
        amount = float(text)
    except ValueError:
        raise ValueError('Invalid --throttle %r (use e.g. 500, 500ms, 2s, 1m, 1h)' % value)
    milliseconds = amount * unit
    if milliseconds <= 0:
        raise ValueError('--throttle must be greater than 0')
    return milliseconds


def format_duration(seconds):
    """Human readable duration for log/help lines, e.g. 5m0s or 1h2m."""
    seconds = int(round(seconds))
    if seconds < 60:
        return '%ds' % seconds
    if seconds < 3600:
        return '%dm%ds' % (seconds // 60, seconds % 60)
    hours, rem = divmod(seconds, 3600)
    return '%dh%dm' % (hours, rem // 60)


def _continuation_page(kwargs):
    """
    True when this search sends the paging cookie from the previous page.
    """
    cookie = kwargs.get('paged_cookie')
    return cookie not in (None, b'', '')


class LdapQueryPacer(object):
    """
    Serializes and slows down LDAP searches so a collection run trickles
    requests to the DC instead of bursting them.

    `--ldap-interval` waits before a new search and before each member;range=
    follow-up. `--ldap-page-interval` waits before a continuation page. The
    first search of the run is immediate. Jitter only adds time.

    One lock serializes all callers (main, resolver and GC connections, plus
    the computer resolver threads) so nothing slips a search into the gap. The
    lock is reentrant because ldap3 resolves member;range= attributes with a
    nested Connection.search inside the outer search call.
    """
    def __init__(self, interval, jitter_pct, page_interval=0, page_jitter_pct=0):
        self.interval = float(interval or 0)
        self.jitter = max(0.0, min(100.0, float(jitter_pct or 0))) / 100.0
        self.page_interval = float(page_interval or 0)
        self.page_jitter = max(0.0, min(100.0, float(page_jitter_pct or 0))) / 100.0
        self._lock = threading.RLock()
        self._last_finish = None

    def _sleep_until(self, target):
        # Sleep in short slices so Ctrl+C is responsive during a multi-minute
        # gap and the caller's finally blocks (stopping ldapx) still run.
        remaining = target - time.monotonic()
        while remaining > 0:
            time.sleep(min(1.0, remaining))
            remaining = target - time.monotonic()

    def _pause(self, base, jitter, is_page):
        if self._last_finish is None or base <= 0:
            return
        extra = base * jitter * random.random()
        total = base + extra
        label = 'page' if is_page else 'search'
        logging.debug('LDAP %s pacing: %.1fs delay (base %.1fs + jitter %.1fs)', label, total, base, extra)
        self._sleep_until(self._last_finish + total)

    def run(self, func, *args, **kwargs):
        with self._lock:
            if _continuation_page(kwargs):
                self._pause(self.page_interval, self.page_jitter, is_page=True)
            else:
                self._pause(self.interval, self.jitter, is_page=False)
            try:
                return func(*args, **kwargs)
            finally:
                self._last_finish = time.monotonic()

    def _describe_one(self, label, base, jitter):
        text = '%s at least %s apart' % (label, format_duration(base))
        if jitter > 0:
            text += ', plus 0-%d%% jitter' % int(round(jitter * 100))
        return text

    def describe(self):
        parts = []
        if self.interval > 0:
            parts.append(self._describe_one('New LDAP searches', self.interval, self.jitter))
        if self.page_interval > 0:
            parts.append(self._describe_one('LDAP pages', self.page_interval, self.page_jitter))
        return '. '.join(parts)


class HostCallPacer(object):
    """
    Spaces host RPC calls across worker threads. Jitter moves the wait both
    below and above the throttle, and the result is never negative.
    """
    def __init__(self, throttle_ms, jitter_pct):
        self.throttle = float(throttle_ms) / 1000.0
        self.jitter = max(0.0, min(100.0, float(jitter_pct or 0))) / 100.0
        self._lock = threading.RLock()
        self._last_finish = None

    def _sleep_until(self, target):
        remaining = target - time.monotonic()
        while remaining > 0:
            time.sleep(min(1.0, remaining))
            remaining = target - time.monotonic()

    def run(self, func, *args, **kwargs):
        with self._lock:
            tw = _TIME_WINDOW
            if tw is not None:
                tw.wait_if_outside()
            if self._last_finish is not None and self.throttle > 0:
                span = self.throttle * self.jitter
                jitter_val = random.uniform(-span, span)
                delay = self.throttle + jitter_val
                if delay < 0:
                    delay = 0
                logging.debug('Host pacing: %.0fms delay (base %.0fms + jitter %+.0fms)',
                              delay * 1000, self.throttle * 1000, jitter_val * 1000)
                self._sleep_until(self._last_finish + delay)
            try:
                return func(*args, **kwargs)
            finally:
                self._last_finish = time.monotonic()

    def describe(self):
        if self.throttle < 1:
            text = 'Host calls at least %d ms apart' % int(round(self.throttle * 1000))
        else:
            text = 'Host calls at least %s apart' % format_duration(self.throttle)
        if self.jitter > 0:
            text += ', plus or minus 0-%d%% jitter' % int(round(self.jitter * 100))
        return text


# Process-wide pacer, search counter, and a guard so Connection.search is only wrapped once.
_LDAP_PACER = None
_HOST_PACER = None
_LDAP_SEARCHES = 0
_SEARCH_WRAPPED = False


def get_ldap_pacer():
    return _LDAP_PACER


def ldap_search_count():
    return _LDAP_SEARCHES


def install_ldap_search_counter():
    """
    Count every LDAP search, and send it through the pacer when one is active.
    """
    global _SEARCH_WRAPPED
    if _SEARCH_WRAPPED:
        return
    import ldap3
    original = ldap3.Connection.search

    def _counted_search(self, *args, **kwargs):
        global _LDAP_SEARCHES
        _LDAP_SEARCHES += 1
        tw = _TIME_WINDOW
        if tw is not None:
            tw.wait_if_outside()
        pacer = _LDAP_PACER
        if pacer is None:
            return original(self, *args, **kwargs)
        return pacer.run(original, self, *args, **kwargs)

    ldap3.Connection.search = _counted_search
    _SEARCH_WRAPPED = True


def install_ldap_pacing(interval, jitter_pct, page_interval=0, page_jitter_pct=0):
    """
    Turn on LDAP pacing for the whole process and wrap ldap3.Connection.search
    so every search request goes through the pacer. Must be called before any
    LDAP connection is opened. Returns the active LdapQueryPacer.
    """
    global _LDAP_PACER
    _LDAP_PACER = LdapQueryPacer(interval, jitter_pct, page_interval, page_jitter_pct)
    install_ldap_search_counter()
    return _LDAP_PACER


def install_host_pacing(throttle_ms, jitter_pct):
    """
    Space host RPC calls. Returns the active HostCallPacer.
    """
    global _HOST_PACER
    _HOST_PACER = HostCallPacer(throttle_ms, jitter_pct)
    return _HOST_PACER


_TIME_WINDOW = None


def parse_run_time(value):
    value = value.strip()
    if len(value) != 4 or not value.isdigit():
        raise ValueError('Time must be HHMM (e.g. 0900, 1730), got: %s' % value)
    hour, minute = int(value[:2]), int(value[2:])
    if hour > 23 or minute > 59:
        raise ValueError('Invalid time %s (hour 0-23, minute 0-59)' % value)
    return hour, minute


def parse_run_jitter(value):
    value = value.strip().lower()
    m = re.match(r'^(\d+(?:\.\d+)?)\s*(s|m|h)?$', value)
    if not m:
        raise ValueError('Invalid jitter duration: %s (use e.g. 15m, 30s, 1h)' % value)
    num = float(m.group(1))
    unit = m.group(2) or 'm'
    if unit == 's':
        return num / 60.0
    elif unit == 'h':
        return num * 60.0
    return num


class TimeWindow(object):
    def __init__(self, start_hour, start_minute, end_hour, end_minute,
                 allowed_days, jitter_minutes=0):
        self.start = (start_hour, start_minute)
        self.end = (end_hour, end_minute)
        self.allowed_days = set(allowed_days)
        self.jitter_minutes = jitter_minutes
        self._current_start_jitter = 0
        self._current_end_jitter = 0
        self._jitter_rolled_for_date = None

    def _roll_jitter_if_new_day(self):
        today = datetime.date.today()
        if self._jitter_rolled_for_date != today:
            if self.jitter_minutes > 0:
                self._current_start_jitter = random.uniform(
                    -self.jitter_minutes, self.jitter_minutes)
                self._current_end_jitter = random.uniform(
                    -self.jitter_minutes, self.jitter_minutes)
            else:
                self._current_start_jitter = 0
                self._current_end_jitter = 0
            self._jitter_rolled_for_date = today

    def _effective_times_today(self):
        self._roll_jitter_if_new_day()
        now = datetime.datetime.now()
        start = now.replace(hour=self.start[0], minute=self.start[1],
                            second=0, microsecond=0)
        start += datetime.timedelta(minutes=self._current_start_jitter)
        end = now.replace(hour=self.end[0], minute=self.end[1],
                          second=0, microsecond=0)
        end += datetime.timedelta(minutes=self._current_end_jitter)
        return start, end

    def _random_effective_times(self, dt):
        if self.jitter_minutes > 0:
            sj = random.uniform(-self.jitter_minutes, self.jitter_minutes)
            ej = random.uniform(-self.jitter_minutes, self.jitter_minutes)
        else:
            sj, ej = 0, 0
        start = dt.replace(hour=self.start[0], minute=self.start[1],
                           second=0, microsecond=0)
        start += datetime.timedelta(minutes=sj)
        end = dt.replace(hour=self.end[0], minute=self.end[1],
                         second=0, microsecond=0)
        end += datetime.timedelta(minutes=ej)
        return start, end

    def is_inside(self, now=None):
        if now is None:
            now = datetime.datetime.now()
        if now.isoweekday() not in self.allowed_days:
            return False
        start, end = self._effective_times_today()
        return start <= now <= end

    def next_window_start(self, now=None):
        if now is None:
            now = datetime.datetime.now()
        for day_offset in range(8):
            candidate = now + datetime.timedelta(days=day_offset)
            if candidate.isoweekday() not in self.allowed_days:
                continue
            if day_offset == 0:
                start, _ = self._effective_times_today()
            else:
                start, _ = self._random_effective_times(candidate)
            if start > now:
                return start
        return None

    def wait_if_outside(self):
        now = datetime.datetime.now()
        if self.is_inside(now):
            return
        next_start = self.next_window_start(now)
        if next_start is None:
            return
        day_name = next_start.strftime('%A')
        time_str = next_start.strftime('%H:%M')
        sleep_seconds = (next_start - now).total_seconds()
        if sleep_seconds <= 0:
            return
        logging.info(
            'Outside run window. Sleeping until %s %s (%s)',
            day_name, time_str, format_duration(sleep_seconds))
        target = time.monotonic() + sleep_seconds
        while time.monotonic() < target:
            time.sleep(min(1.0, target - time.monotonic()))
        logging.info('Run window opened. Resuming collection.')

    def describe(self):
        day_names = {1: 'Mon', 2: 'Tue', 3: 'Wed', 4: 'Thu',
                     5: 'Fri', 6: 'Sat', 7: 'Sun'}
        days = ', '.join(day_names[d] for d in sorted(self.allowed_days))
        text = 'Run window: %s %02d%02d-%02d%02d' % (
            days, self.start[0], self.start[1],
            self.end[0], self.end[1])
        if self.jitter_minutes > 0:
            if self.jitter_minutes >= 60:
                text += ' (jitter +/-%s)' % format_duration(self.jitter_minutes * 60)
            else:
                text += ' (jitter +/-%.0fm)' % self.jitter_minutes
        return text

def install_time_window(start_hour, start_minute, end_hour, end_minute,
                        allowed_days, jitter_minutes=0):
    global _TIME_WINDOW
    _TIME_WINDOW = TimeWindow(start_hour, start_minute, end_hour, end_minute,
                              allowed_days, jitter_minutes)
    return _TIME_WINDOW


def get_time_window():
    return _TIME_WINDOW


def get_host_pacer():
    return _HOST_PACER


def call_host(func, *args, **kwargs):
    """
    Run a host RPC. When --throttle is set, calls are spaced across workers.
    """
    pacer = _HOST_PACER
    if pacer is None:
        return func(*args, **kwargs)
    return pacer.run(func, *args, **kwargs)


def enable_tcp_keepalive(sock):
    """
    Turn on TCP keepalive on a bound LDAP socket so a long pacing gap does not
    get the connection dropped as idle. Best-effort: unsupported platforms or
    socket types are ignored.
    """
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except (OSError, AttributeError):
        return
    # 30s idle before the first probe, then probes every 15s.
    if hasattr(socket, 'SIO_KEEPALIVE_VALS'):
        try:
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 15000))
            return
        except (OSError, AttributeError, ValueError):
            pass
    for opt, value in (('TCP_KEEPIDLE', 30), ('TCP_KEEPINTVL', 15), ('TCP_KEEPCNT', 4)):
        level = getattr(socket, 'IPPROTO_TCP', socket.SOL_SOCKET)
        name = getattr(socket, opt, None)
        if name is not None:
            try:
                sock.setsockopt(level, name, value)
            except (OSError, AttributeError):
                pass
