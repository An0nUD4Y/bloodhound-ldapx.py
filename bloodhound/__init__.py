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

import os, sys, logging, argparse, getpass, time, re, textwrap
from zipfile import ZipFile
from bloodhound.ad.domain import AD, ADDC
from bloodhound.ad.authentication import ADAuthentication, enable_kerberos_socks, disable_kerberos_socks
from bloodhound.ad.utils import ADUtils, CollectionException, parse_ldap_interval, parse_throttle, install_ldap_pacing, install_ldap_search_counter, install_host_pacing, install_ldap_binary_filter, ldap_search_count
from bloodhound.ad.obfuscation import (
    LdapxObfuscator, parse_ldapx_options, install_ldapx_obfuscation,
    enable_ldap_socks, disable_ldap_socks, warn_dangerous_attrlist,
)
from bloodhound.enumeration.computers import ComputerEnumerator
from bloodhound.enumeration.memberships import MembershipEnumerator
from bloodhound.enumeration.domains import DomainEnumerator
from bloodhound.enumeration.resume import CollectionResume


class BloodHoundHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """
    Wrap argument help as usual. A blank line in a help string starts a new
    paragraph, so a Note stays separate from the description of the flag.
    """

    def _split_lines(self, text, width):
        if '\n' not in text:
            return super(BloodHoundHelpFormatter, self)._split_lines(text, width)
        lines = []
        for part in text.split('\n'):
            part = part.strip()
            if not part:
                if lines and lines[-1] != '':
                    lines.append('')
                continue
            lines.extend(textwrap.wrap(part, width))
        return lines


def parse_host_port(value, default_port=None):
    """
    Split a HOST:PORT string. If no port is present, default_port is used
    (required unless default_port is given).
    """
    if ':' in value:
        host, port = value.rsplit(':', 1)
        try:
            return host, int(port)
        except ValueError:
            raise CollectionException('Invalid port in address: %s' % value)
    if default_port is None:
        raise CollectionException('Address %s requires an explicit port' % value)
    return value, default_port


def is_ip_or_localhost(value):
    """
    True when value cannot be used as a Kerberos SPN hostname.
    """
    if value.lower() in ('localhost', 'localhost.localdomain'):
        return True
    return re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value) is not None


def _first_attr(value):
    if value is None or value == '':
        return None
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def discover_dc_info(host, port, use_ldaps=False):
    """
    Read dnsHostName and defaultNamingContext from the target DC's RootDSE.
    Used with --target when no usable DC FQDN was supplied with -dc.
    """
    import ssl
    import ldap3
    from ldap3 import Tls

    kwargs = dict(host=host, port=int(port), use_ssl=use_ldaps, get_info=ldap3.ALL, connect_timeout=10)
    if use_ldaps:
        kwargs['tls'] = Tls(validate=ssl.CERT_NONE)
    server = ldap3.Server(**kwargs)
    conn = ldap3.Connection(server, receive_timeout=20)
    dns_host = None
    default_nc = None
    try:
        conn.open(read_server_info=True)
        info = conn.server.info
        if info is not None and getattr(info, 'other', None):
            dns_host = _first_attr(info.other.get('dnsHostName'))
            default_nc = _first_attr(info.other.get('defaultNamingContext'))
        if dns_host is None or default_nc is None:
            if conn.search('', '(objectClass=*)', search_scope=ldap3.BASE,
                           attributes=['dnsHostName', 'defaultNamingContext']) and conn.response:
                attrs = conn.response[0].get('attributes', {})
                dns_host = dns_host or _first_attr(attrs.get('dnsHostName'))
                default_nc = default_nc or _first_attr(attrs.get('defaultNamingContext'))
    finally:
        try:
            conn.unbind()
        except Exception:
            pass
    return dns_host, default_nc


"""
BloodHound.py is a Python port of BloodHound, designed to run on Linux and Windows.
"""
class BloodHound(object):
    def __init__(self, ad):
        self.ad = ad
        self.ldap = None
        self.pdc = None
        self.sessions = []


    def connect(self):
        if len(self.ad.dcs()) == 0:
            logging.error('Could not find a domain controller. Consider specifying a domain and/or DNS server.')
            sys.exit(1)

        if not self.ad.baseDN:
            logging.error('Could not figure out the domain to query. Please specify this manually with -d')
            sys.exit(1)

        pdc = self.ad.dcs()[0]
        logging.debug('Using LDAP server: %s', pdc)
        logging.debug('Using base DN: %s', self.ad.baseDN)

        if len(self.ad.kdcs()) > 0:
            kdc = self.ad.auth.kdc
            logging.debug('Using kerberos KDC: %s', kdc)
            logging.debug('Using kerberos realm: %s', self.ad.realm())

        # Create a domain controller object
        self.pdc = ADDC(pdc, self.ad)
        # Create an object resolver
        self.ad.create_objectresolver(self.pdc)


    def run(self, collect, num_workers=10, disable_pooling=False, timestamp="", computerfile="", cachefile=None, exclude_dcs=False, fileNamePrefix="", resume=None, partition_ldap=False):
        start_time = time.time()
        install_ldap_search_counter()
        if partition_ldap:
            # Slices 80-ff put a non-UTF-8 byte in the filter. ldap3 crashes
            # while logging that byte, before the search is sent.
            install_ldap_binary_filter()
        self.resume = resume
        self.pdc.partition_ldap = partition_ldap
        if resume is not None:
            timestamp = resume.timestamp
            # The checkpoint prefix is what the output files were named with.
            fileNamePrefix = resume.prefix or None
            self.pdc.resume = resume
        if cachefile:
            self.ad.load_cachefile(cachefile)

        # Check early if we should enumerate computers as well
        do_computer_enum = any(method in collect for method in ['localadmin', 'session', 'loggedon', 'experimental', 'rdp', 'dcom', 'psremote'])
        skip_schema = resume is not None and resume.has_schema()
        cache_computers = do_computer_enum and not (resume is not None and resume.phase_done('hosts'))
        if skip_schema:
            logging.info('Skipping schema, checkpoint has %d types', len(resume.schema_map))
            self.pdc.restore_objecttype(resume.schema_map)

        if 'group' in collect or 'objectprops' in collect or 'acl' in collect:
            # Fetch domains for later, computers if needed
            self.pdc.prefetch_info('objectprops' in collect, 'acl' in collect, cache_computers=cache_computers, skip_schema=skip_schema)
            # Initialize enumerator
            membership_enum = MembershipEnumerator(self.ad, self.pdc, collect, disable_pooling)
            membership_enum.resume = resume
            membership_enum.enumerate_memberships(timestamp=timestamp, fileNamePrefix=fileNamePrefix)
        elif 'container' in collect:
            # Fetch domains for later, computers if needed
            self.pdc.prefetch_info('objectprops' in collect, 'acl' in collect, cache_computers=cache_computers, skip_schema=skip_schema)
            # Initialize enumerator
            membership_enum = MembershipEnumerator(self.ad, self.pdc, collect, disable_pooling)
            membership_enum.resume = resume
            membership_enum.do_container_collection(timestamp=timestamp, fileNamePrefix=fileNamePrefix)
        elif do_computer_enum:
            # We need to know which computers to query regardless
            # We also need the domains to have a mapping from NETBIOS -> FQDN for local admins
            self.pdc.prefetch_info('objectprops' in collect, 'acl' in collect, cache_computers=cache_computers, skip_schema=skip_schema)
        elif 'trusts' in collect:
            # Prefetch domains
            started = ldap_search_count()
            self.pdc.get_domains('acl' in collect)
            logging.info('Domain lookup: %d LDAP searches', ldap_search_count() - started)
        if 'trusts' in collect or 'acl' in collect or 'objectprops' in collect:
            trusts_enum = DomainEnumerator(self.ad, self.pdc)
            trusts_enum.resume = resume
            trusts_enum.dump_domain(collect,timestamp=timestamp,fileNamePrefix=fileNamePrefix)
        if do_computer_enum:
            # If we don't have a GC server, don't use it for deconflictation
            have_gc = len(self.ad.gcs()) > 0
            computer_enum = ComputerEnumerator(self.ad, self.pdc, collect, do_gc_lookup=have_gc, computerfile=computerfile, exclude_dcs=exclude_dcs)
            computer_enum.resume = resume
            computer_enum.enumerate_computers(self.ad.computers, num_workers=num_workers, timestamp=timestamp, fileNamePrefix=fileNamePrefix)
        end_time = time.time()
        minutes, seconds = divmod(int(end_time-start_time),60)
        logging.info('Done in %02dM %02dS' % (minutes, seconds))

def resolve_collection_methods(methods):
    """
    Convert methods (string) to list of validated methods to resolve
    """
    valid_methods = ['group', 'localadmin', 'session', 'trusts', 'default', 'all', 'loggedon',
                     'objectprops', 'experimental', 'acl', 'dcom', 'rdp', 'psremote', 'dconly',
                     'container']
    default_methods = ['group', 'localadmin', 'session', 'trusts']
    # Similar to SharpHound, All is not really all, it excludes loggedon
    all_methods = ['group', 'localadmin', 'session', 'trusts', 'objectprops', 'acl', 'dcom', 'rdp', 'psremote', 'container']
    # DC only, does not collect to computers
    dconly_methods = ['group', 'trusts', 'objectprops', 'acl', 'container']
    if ',' in methods:
        method_list = [method.lower() for method in methods.split(',')]
        validated_methods = []
        for method in method_list:
            if method not in valid_methods:
                logging.error('Invalid collection method specified: %s', method)
                return False

            if method == 'default':
                validated_methods += default_methods
            elif method == 'all':
                validated_methods += all_methods
            elif method == 'dconly':
                validated_methods += dconly_methods
            else:
                validated_methods.append(method)
        return set(validated_methods)
    else:
        validated_methods = []
        # It is only one
        method = methods.lower()
        if method in valid_methods:
            if method == 'default':
                validated_methods += default_methods
            elif method == 'all':
                validated_methods += all_methods
            elif method == 'dconly':
                validated_methods += dconly_methods
            else:
                validated_methods.append(method)
            return set(validated_methods)
        else:
            logging.error('Invalid collection method specified: %s', method)
            return False

def main():
#    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s: %(message)s')
#    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    parser = argparse.ArgumentParser(add_help=True, description='Python based ingestor for BloodHound Community Edition\nFor help or reporting issues, visit https://github.com/dirkjanm/BloodHound.py', formatter_class=BloodHoundHelpFormatter)

    parser.add_argument('-c',
                        '--collectionmethod',
                        action='store',
                        default='Default',
                        help='Which information to collect. Supported: Group, LocalAdmin, Session, '
                             'Trusts, Default (all previous), DCOnly (no computer connections), DCOM, RDP,'
                             'PSRemote, LoggedOn, Container, ObjectProps, ACL, All (all except LoggedOn). '
                             'You can specify more than one by separating them with a comma. (default: Default)')
    parser.add_argument('-d',
                        '--domain',
                        action='store',
                        default='',
                        help='Domain to query.')
    parser.add_argument('-v',
                        action='store_true',
                        help='Enable verbose output, including obfuscation traces when --obf-* chains are set.')
    parser.add_argument('--log-file',
                        metavar='PATH',
                        action='store',
                        help='Write a timestamped debug log to PATH (the file is overwritten). '
                             'Records BloodHound debug output and, when obfuscation is enabled, '
                             'each original and rewritten filter, BaseDN, and attribute list. '
                             'The console stays at info level unless -v is also set.')
    helptext = 'Specify one or more authentication options. \n' \
               'By default Kerberos authentication is used and NTLM is used as fallback. \n' \
               'Kerberos tickets are automatically requested if a password or hashes are specified.'
    auopts = parser.add_argument_group('authentication options', description=helptext)
    auopts.add_argument('-u',
                        '--username',
                        action='store',
                        help='Username. Format: username[@domain]; If the domain is unspecified, the current domain is used.')
    auopts.add_argument('-p',
                        '--password',
                        action='store',
                        help='Password')
    auopts.add_argument('-k',
                        '--kerberos',
                        action='store_true',
                        help='Use kerberos ccache file')
    auopts.add_argument('--hashes',
                        action='store',
                        help='LM:NLTM hashes')
    auopts.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    auopts.add_argument('-aesKey',
                        action="store",
                        metavar="hex key",
                        help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    auopts.add_argument('--auth-method',
                        choices=('auto','ntlm','kerberos'),
                        default='auto',
                        action='store',
                        help='Authentication methods. Force Kerberos or NTLM only or use auto for Kerberos with NTLM fallback')
    coopts = parser.add_argument_group('collection options')
    coopts.add_argument('-ns',
                        '--nameserver',
                        action='store',
                        help='Alternative name server to use for queries')
    coopts.add_argument('--dns-tcp',
                        action='store_true',
                        help='Use TCP instead of UDP for DNS queries')
    coopts.add_argument('--dns-timeout',
                        action='store',
                        type=int,
                        default=3,
                        help='DNS query timeout in seconds (default: 3)')
    coopts.add_argument('-dc',
                        '--domain-controller',
                        metavar='HOST',
                        action='store',
                        help='Override which DC to query (hostname). With --target this is the Kerberos '
                             'SPN hostname; omit it to read the DC name from RootDSE.')
    coopts.add_argument('-gc',
                        '--global-catalog',
                        metavar='HOST',
                        action='store',
                        help='Override which GC to query (hostname)')
    coopts.add_argument('-w',
                        '--workers',
                        action='store',
                        type=int,
                        default=10,
                        help='Number of workers for computer enumeration (default: 10)')
    coopts.add_argument('--exclude-dcs',
                        action='store_true',
                        help='Skip DCs during computer enumeration')
    coopts.add_argument('--disable-pooling',
                        action='store_true',
                        help='Don\'t use subprocesses for ACL parsing (only for debugging purposes)')
    coopts.add_argument('--disable-autogc',
                        action='store_true',
                        help='Don\'t automatically select a Global Catalog (use only if it gives errors)')
    coopts.add_argument('--zip',
                        action='store_true',
                        help='Compress the JSON output files into a zip archive')
    coopts.add_argument('--computerfile',
                        action='store',
                        help='File containing computer FQDNs to use as allowlist for any computer based methods')
    coopts.add_argument('--cachefile',
                        action='store',
                        help='Cache file (experimental)')
    coopts.add_argument('--ldap-channel-binding',
                        action='store_true',
                        help='Deprecated; ignored (CBT is automatic on LDAPS)')
    coopts.add_argument('--use-ldaps',
                        action='store_true',
                        help='Use LDAP over TLS on port 636 by default')
    coopts.add_argument('--ldaps-legacy-tls',
                        action='store_true',
                        help='Use TLS 1.2 and legacy ciphers for all LDAPS connections')
    coopts.add_argument('--ldap-interval',
                        metavar='DURATION',
                        action='store',
                        help='Wait at least this long before a new LDAP search and before each '
                             'member;range= follow-up, measured from when the previous search finished. '
                             'A continuation page uses --ldap-page-interval instead. Plain number is seconds; '
                             'suffixes s/m/h (e.g. 300, 300s, 5m, 1h). Off by default.\n'
                             '\n'
                             'Note: a directory of about 20000 objects is about 100 pages and about 20 new '
                             'DCOnly searches. 30s + 20%% jitter keeps those searches 30-36s apart, about 11 minutes. '
                             'Pages are not delayed unless --ldap-page-interval is set.')
    coopts.add_argument('--ldap-jitter',
                        metavar='PERCENT',
                        action='store',
                        type=float,
                        default=0,
                        help='Extra delay on top of --ldap-interval, rolled fresh for each new search. '
                             '0-100, default 0. The extra delay is 0 to (interval * PERCENT/100). '
                             'Requires --ldap-interval. Does not apply to continuation pages.')
    coopts.add_argument('--ldap-page-interval',
                        metavar='DURATION',
                        action='store',
                        help='Wait at least this long before a continuation page, the search that sends '
                             'the previous paging cookie. Same duration syntax as --ldap-interval. '
                             'Off by default, so later pages follow as soon as the previous page returns.\n'
                             '\n'
                             'Note: about 20000 objects is about 100 continuation pages. 5s + 40%% jitter '
                             'keeps those pages 5.0-7.0s apart, about 10 minutes.')
    coopts.add_argument('--ldap-page-jitter',
                        metavar='PERCENT',
                        action='store',
                        type=float,
                        default=0,
                        help='Extra delay on top of --ldap-page-interval, rolled fresh for each continuation '
                             'page. 0-100, default 0. Requires --ldap-page-interval.')
    coopts.add_argument('--throttle',
                        metavar='DURATION',
                        action='store',
                        help='Wait this long between host RPC calls (Session, LocalAdmin, LoggedOn, RDP, '
                             'DCOM, PSRemote, Experimental). A plain number is milliseconds. Suffixes ms/s/m/h '
                             'are accepted (500, 500ms, 2s, 1m, 1h). Jitter can make a single wait shorter or longer. '
                             'Off by default.')
    coopts.add_argument('--throttle-jitter',
                        metavar='PERCENT',
                        action='store',
                        type=float,
                        default=0,
                        help='Spread --throttle both below and above the throttle, 0-100. '
                             'The wait is never negative. Requires --throttle.')
    coopts.add_argument('--partition-ldap',
                        action='store_true',
                        help='Split schema, users, groups, computers, GPOs, OUs and containers into 256 '
                             'objectGUID slices. --ldap-interval applies when a slice starts and '
                             '--ldap-page-interval applies between pages inside a slice. Finished slices '
                             'are skipped on --resume.')
    coopts.add_argument('-op',
                        '--outputprefix',
                        metavar='PREFIX_NAME',
                        action='store',
                        help='String to prepend to output file names')
    coopts.add_argument('--resume',
                        action='store_true',
                        help='Continue a stopped collection from the last finished phase. '
                             'With --outputprefix NAME the checkpoint is NAME_resume.json and the JSON files are NAME_<timestamp>_users.json and so on. '
                             'Without --outputprefix, bloodhound_resume.json is used, or the only NAME_resume.json in the working directory. '
                             'Reuses that run\'s timestamp and prefix, and skips phases whose JSON is already complete. '
                             'The phase that was still in progress is collected again. '
                             'The domain and collection methods must match the saved run. '
                             'Every collection method resumes by finished phase. Host methods (LocalAdmin, Session, LoggedOn, DCOM, RDP, PSRemote, Experimental) resume as one host pass, not one computer at a time.')

    obfopts = parser.add_argument_group(
        'obfuscation and targeting options',
        description='Obfuscate LDAP searches in-process with ldapx-py. '
                    '--obf-* chains work with standard DNS discovery, -dc, or --target. '
                    '--socks routes LDAP/LDAPS/GC and Kerberos TCP/88 through a SOCKS5 proxy.')
    obfopts.add_argument('--obf-filter',
                        dest='obf_filter',
                        action='store',
                        help='Search filter middleware chain, e.g. OGDR')
    obfopts.add_argument('--obf-attrlist',
                        dest='obf_attrlist',
                        action='store',
                        help='Attribute list middleware chain, e.g. RD')
    obfopts.add_argument('--obf-basedn',
                        dest='obf_basedn',
                        action='store',
                        help='BaseDN middleware chain, e.g. OX')
    obfopts.add_argument('--obf-attrentries',
                        dest='obf_attrentries',
                        action='store',
                        help='Attribute entries middleware chain')
    obfopts.add_argument('--obf-option',
                        dest='obf_option',
                        metavar='KEY=VALUE',
                        action='append',
                        help='ldapx middleware option. Can be specified multiple times.')
    obfopts.add_argument('--target',
                        dest='target',
                        metavar='HOST[:PORT]',
                        action='store',
                        help='Connect to this DC without DNS discovery. Port defaults to 636 with --use-ldaps, 389 otherwise. An IP works when local DNS cannot resolve the DC.')
    obfopts.add_argument('--socks',
                        dest='socks',
                        metavar='URL',
                        action='store',
                        help='SOCKS5 proxy for LDAP/LDAPS/GC and Kerberos TCP/88, e.g. socks5://127.0.0.1:1080 or socks5://user:pass@host:1080')
    # Hidden backward-compatible aliases
    obfopts.add_argument('--ldapx-filter', dest='obf_filter', help=argparse.SUPPRESS)
    obfopts.add_argument('--ldapx-attrlist', dest='obf_attrlist', help=argparse.SUPPRESS)
    obfopts.add_argument('--ldapx-basedn', dest='obf_basedn', help=argparse.SUPPRESS)
    obfopts.add_argument('--ldapx-attrentries', dest='obf_attrentries', help=argparse.SUPPRESS)
    obfopts.add_argument('--ldapx-option', dest='obf_option', metavar='KEY=VALUE', action='append', help=argparse.SUPPRESS)
    obfopts.add_argument('--ldapx-target', dest='target', metavar='HOST:PORT', help=argparse.SUPPRESS)
    obfopts.add_argument('--ldapx-socks', dest='socks', metavar='URL', help=argparse.SUPPRESS)
    obfopts.add_argument('--ldapx-ldaps', dest='ldapx_ldaps', action='store_true', help=argparse.SUPPRESS)

    args = parser.parse_args()

    if args.ldapx_ldaps:
        parser.error('--ldapx-ldaps has been removed; use --use-ldaps instead')

    # Debug records have to be produced for the log file. The console handler
    # stays at INFO unless -v is set, so a log file does not flood the terminal.
    if args.v or args.log_file:
        logger.setLevel(logging.DEBUG)
    stream.setLevel(logging.DEBUG if args.v else logging.INFO)
    if args.log_file:
        try:
            file_handler = logging.FileHandler(args.log_file, mode='w', encoding='utf-8')
        except OSError as exc:
            parser.error('Could not open --log-file %s: %s' % (args.log_file, exc))
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s',
                                                    datefmt='%Y-%m-%d %H:%M:%S'))
        logger.addHandler(file_handler)

    logging.info('BloodHound.py for BloodHound Community Edition')
    if args.log_file:
        logging.info('Writing detailed log to %s', os.path.abspath(args.log_file))
    if args.ldap_channel_binding:
        logging.warning('--ldap-channel-binding is deprecated and ignored; use --use-ldaps for LDAPS')

    # Validate LDAP query pacing before any LDAP socket is opened.
    try:
        ldap_interval_seconds = parse_ldap_interval(args.ldap_interval)
        ldap_page_interval_seconds = parse_ldap_interval(args.ldap_page_interval, '--ldap-page-interval')
        throttle_ms = parse_throttle(args.throttle)
    except ValueError as e:
        parser.error(str(e))
    if args.ldap_jitter < 0 or args.ldap_jitter > 100:
        parser.error('--ldap-jitter must be between 0 and 100')
    if args.ldap_jitter and ldap_interval_seconds is None:
        parser.error('--ldap-jitter requires --ldap-interval')
    if args.ldap_page_jitter < 0 or args.ldap_page_jitter > 100:
        parser.error('--ldap-page-jitter must be between 0 and 100')
    if args.ldap_page_jitter and ldap_page_interval_seconds is None:
        parser.error('--ldap-page-jitter requires --ldap-page-interval')
    if args.throttle_jitter < 0 or args.throttle_jitter > 100:
        parser.error('--throttle-jitter must be between 0 and 100')
    if args.throttle_jitter and throttle_ms is None:
        parser.error('--throttle-jitter requires --throttle')

    has_obf = bool(args.obf_filter or args.obf_basedn or args.obf_attrlist or args.obf_attrentries)
    obfuscator = None
    if has_obf:
        warn_dangerous_attrlist(args.obf_attrlist)
        try:
            options = parse_ldapx_options(args.obf_option)
            obfuscator = LdapxObfuscator(
                filter_chain=args.obf_filter,
                basedn_chain=args.obf_basedn,
                attrlist_chain=args.obf_attrlist,
                attrentries_chain=args.obf_attrentries,
                options=options)
            install_ldapx_obfuscation(obfuscator)
        except ImportError:
            parser.error('ldapx is required for --obf-* flags. Install it with: pip install "ldapx>=0.5.0"')
        logging.info('In-process LDAP obfuscation enabled (filter=%s basedn=%s attrlist=%s)',
                     args.obf_filter or '-', args.obf_basedn or '-', args.obf_attrlist or '-')

    if ldap_interval_seconds is not None or ldap_page_interval_seconds is not None:
        pacer = install_ldap_pacing(ldap_interval_seconds or 0, args.ldap_jitter,
                                    ldap_page_interval_seconds or 0, args.ldap_page_jitter)
        logging.info(pacer.describe())
    if throttle_ms is not None:
        host_pacer = install_host_pacing(throttle_ms, args.throttle_jitter)
        logging.info(host_pacer.describe())

    if (args.username is not None and args.password is None and args.hashes is None
            and args.aesKey is None and not args.no_pass):
        args.password = getpass.getpass()

    try:
        if args.socks:
            try:
                enable_ldap_socks(args.socks)
                enable_kerberos_socks(args.socks)
            except CollectionException as e:
                logging.error('%s', e)
                sys.exit(1)

        target_dc_fqdn = None
        target_kdc = None
        discovered_domain = None
        dc_target = None
        gc_target = None
        if args.target:
            try:
                default_port = 636 if args.use_ldaps else 389
                target_host, target_port = parse_host_port(args.target, default_port)
                gc_port = 3269 if args.use_ldaps else 3268
                dc_target = (target_host, target_port)
                gc_target = (target_host, gc_port)
                target_kdc = target_host
                if args.domain_controller and not is_ip_or_localhost(args.domain_controller):
                    target_dc_fqdn = args.domain_controller
                if target_dc_fqdn is None or not args.domain:
                    logging.info('Reading RootDSE from %s:%d to discover the DC hostname', target_host, target_port)
                    try:
                        dns_host, default_nc = discover_dc_info(target_host, target_port, args.use_ldaps)
                    except Exception as e:
                        raise CollectionException('Could not read RootDSE from %s:%d: %s' % (target_host, target_port, e))
                    if target_dc_fqdn is None:
                        target_dc_fqdn = dns_host
                    if not args.domain and default_nc:
                        discovered_domain = ADUtils.ldap2domain(default_nc)
                        logging.info('Discovered domain from RootDSE: %s', discovered_domain)
                if target_dc_fqdn is None:
                    raise CollectionException('Could not determine the DC FQDN via RootDSE. Specify it with -dc (e.g. -dc dc01.domain.local)')
                if not args.domain and not discovered_domain:
                    raise CollectionException('Could not determine the domain from RootDSE. Specify it with -d')
                logging.debug('Using %s as DC FQDN for Kerberos SPNs', target_dc_fqdn)
            except CollectionException as e:
                logging.error('%s', e)
                sys.exit(1)
            if discovered_domain and not args.domain:
                args.domain = discovered_domain

        if args.username is not None and args.password is not None:
            logging.debug('Authentication: username/password')
            auth = ADAuthentication(username=args.username, password=args.password, domain=args.domain, auth_method=args.auth_method, ldaps_legacy_tls=args.ldaps_legacy_tls)
        elif args.username is None and (args.password is not None or args.hashes is not None):
            logging.error('Authentication: password or hashes provided without username')
            sys.exit(1)
        elif args.hashes is not None and args.username is not None:
            logging.debug('Authentication: NT hash')
            hash_parts = args.hashes.split(":")
            if len(hash_parts) == 1:
                lm, nt = '', hash_parts[0]
            elif len(hash_parts) == 2:
                lm, nt = hash_parts
            else:
                parser.error('--hashes must be NTHASH or LMHASH:NTHASH')
            auth = ADAuthentication(lm_hash=lm, nt_hash=nt, username=args.username, domain=args.domain, auth_method=args.auth_method, ldaps_legacy_tls=args.ldaps_legacy_tls)
        elif args.aesKey is not None and args.username is not None:
            logging.debug('Authentication: Kerberos AES')
            auth = ADAuthentication(username=args.username, domain=args.domain, aeskey=args.aesKey, auth_method=args.auth_method, ldaps_legacy_tls=args.ldaps_legacy_tls)
        else:
            if not args.kerberos:
                parser.print_help()
                sys.exit(1)
            else:
                if not args.username:
                    logging.error('Specifying the username explicitly is required for Kerberos ccache authentication')
                    sys.exit(1)
                logging.debug('Authentication: Kerberos ccache')
                args.auth_method = 'kerberos'
                auth = ADAuthentication(username=args.username, password=args.password, domain=args.domain, auth_method=args.auth_method, ldaps_legacy_tls=args.ldaps_legacy_tls)

        ad = AD(auth=auth, domain=args.domain, nameserver=args.nameserver, dns_tcp=args.dns_tcp, dns_timeout=args.dns_timeout, use_ldaps=args.use_ldaps)
        ad.obfuscator = obfuscator
        ad.socks_enabled = bool(args.socks)
        # Resolve collection methods
        collect = resolve_collection_methods(args.collectionmethod)
        if not collect:
            return
        logging.debug('Resolved collection methods: %s', ', '.join(list(collect)))

        if dc_target is not None:
            ad.override_dc(target_dc_fqdn)
            ad.override_gc(target_dc_fqdn)
            ad.dc_target = dc_target
            ad.gc_target = gc_target
            auth.dc_target = dc_target
            auth.gc_target = gc_target
            auth.set_kdc(target_kdc)
        else:
            logging.debug('Using DNS to retrieve domain information')
            ad.dns_resolve(domain=args.domain, options=args)

            # Override the detected DC / GC if specified
            if args.domain_controller:
                if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', args.domain_controller):
                    logging.error('The specified domain controller %s looks like an IP address, but requires a hostname (FQDN).\n'\
                                  'Use the -ns flag to specify a DNS server IP if the hostname does not resolve on your default nameserver.',
                                  args.domain_controller)
                    sys.exit(1)
                ad.override_dc(args.domain_controller)
                logging.debug('Using supplied domain controller as KDC')
                auth.set_kdc(args.domain_controller)

            if args.global_catalog:
                if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', args.global_catalog):
                    logging.error('The specified global catalog server %s looks like an IP address, but requires a hostname (FQDN).\n'\
                                  'Use the -ns flag to specify a DNS server IP if the hostname does not resolve on your default nameserver.',
                                  args.global_catalog)
                    sys.exit(1)
                ad.override_gc(args.global_catalog)

        if args.auth_method in ('auto', 'kerberos'):
            if args.kerberos is True:
                loaded_tgt = auth.load_ccache()
                loaded_tgs = False
                spn_host = target_dc_fqdn or (args.domain_controller if args.domain_controller and not is_ip_or_localhost(args.domain_controller) else None)
                if spn_host:
                    loaded_tgs = auth.load_ldap_service_ticket(spn_host)
                if not loaded_tgt and not loaded_tgs:
                    logging.debug('Could not load ticket from ccache, trying to request a TGT instead')
                    auth.get_tgt()
            else:
                auth.get_tgt()

        bloodhound = BloodHound(ad)
        bloodhound.connect()
        try:
            resume = CollectionResume.open(args.outputprefix, bloodhound.ad.domain, collect, args.resume)
        except CollectionException as exc:
            logging.error('%s', exc)
            sys.exit(1)
        timestamp = resume.timestamp
        bloodhound.run(collect=collect,
                       num_workers=args.workers,
                       disable_pooling=args.disable_pooling,
                       timestamp=timestamp,
                       computerfile=args.computerfile,
                       cachefile=args.cachefile,
                       exclude_dcs=args.exclude_dcs,
                       fileNamePrefix=args.outputprefix,
                       resume=resume,
                       partition_ldap=args.partition_ldap)
        #If args --zip is true, the compress output
        if args.zip:
            logging.info("Compressing output into " + timestamp + "bloodhound.zip")
            # Get a list of files in the current dir
            list_of_files = os.listdir(os.getcwd())
            # Create handle to zip file with timestamp prefix
            if(args.outputprefix!=None):
                with ZipFile(args.outputprefix + "_" + timestamp + "bloodhound.zip",'w') as zip:
                    # For each of those files we fetched
                    for each_file in list_of_files:
                        # Finished BloodHound JSON only. Leave the resume checkpoint on disk.
                        if each_file == os.path.basename(resume.path):
                            continue
                        if each_file.startswith(args.outputprefix) and each_file.endswith("json"):
                            # Write it to the zip
                            zip.write(each_file)
                            # Remove it from disk
                            os.remove(each_file)
            else:
                with ZipFile(timestamp + "bloodhound.zip",'w') as zip:
                    # For each of those files we fetched
                    for each_file in list_of_files:
                        # Finished BloodHound JSON only. Leave the resume checkpoint on disk.
                        if each_file == os.path.basename(resume.path):
                            continue
                        if each_file.startswith(timestamp) and each_file.endswith("json"):
                            # Write it to the zip
                            zip.write(each_file)
                            # Remove it from disk
                            os.remove(each_file)
    except Exception:
        logging.exception('BloodHound failed')
        sys.exit(1)
    finally:
        if args.socks:
            disable_kerberos_socks()
            disable_ldap_socks()



if __name__ == '__main__':
    main()
