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

import os, sys, logging, argparse, getpass, time, re, tempfile, textwrap
import socket, subprocess, threading
from zipfile import ZipFile

# pyasn1 >= 0.5 on Python >= 3.14 treats OctetString as UTF-8,
# which crashes on raw GUID bytes (\x80-\xff) used in LDAP substring
# filters for GUID slicing.  Fall back to latin-1 so the full \x00-\xff
# range round-trips without loss.
try:
    import pyasn1.type.univ as _univ
    _orig_octet_str = _univ.OctetString.__str__
    def _octet_str_latin1_fallback(self):
        try:
            return self._value.decode(self.encoding)
        except (UnicodeDecodeError, AttributeError):
            return self._value.decode('latin-1')
    _univ.OctetString.__str__ = _octet_str_latin1_fallback
except Exception:
    pass

from bloodhound.ad.domain import AD, ADDC
from bloodhound.ad.authentication import ADAuthentication, enable_kerberos_socks, disable_kerberos_socks
from bloodhound.ad.utils import ADUtils, CollectionException, parse_ldap_interval, parse_throttle, parse_run_time, parse_run_jitter, install_ldap_pacing, install_ldap_search_counter, install_host_pacing, install_time_window, ldap_search_count
from bloodhound.ldapxbin import LDAPX_VERSION, resolve_ldapx_binary
from bloodhound.enumeration.computers import ComputerEnumerator
from bloodhound.enumeration.memberships import MembershipEnumerator
from bloodhound.enumeration.domains import DomainEnumerator
from bloodhound.enumeration.resume import CollectionResume

LDAPX_DEFAULT_LISTEN = '127.0.0.1:1389'
LDAPX_DEFAULT_GC_LISTEN = '127.0.0.1:13268'


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


class LdapxLauncher(object):
    """
    Starts and stops ldapx (https://github.com/Macmod/ldapx) child processes
    so BloodHound can send its LDAP traffic through a local, transforming
    proxy listener. One process is started for the LDAP target port and one
    for the Global Catalog port, since a single ldapx instance only forwards
    to one target.
    """
    def __init__(self, binary='ldapx', verbose=False, requests_only=False):
        try:
            self.binary = resolve_ldapx_binary(binary)
        except Exception as exc:
            raise CollectionException(
                'Could not find ldapx. Install failed to download it (%s). '
                'Pass --ldapx-binary with the path to an ldapx executable.' % exc)
        if self.binary != binary:
            logging.info('Using ldapx binary: %s', self.binary)
        self.verbose = verbose
        # --log-file wants the request rewrite trail, not response bodies.
        self.requests_only = requests_only
        self.processes = []
        self.listeners = []
        self.decrypt_args = []

    def _build_argv(self, listen, target, use_ldaps, socks_url, chains, options, decrypt_args):
        argv = [self.binary, '-N', '-l', listen, '-t', target]
        if use_ldaps:
            # Upstream (ldapx -> DC) TLS only; the local listener stays plaintext
            argv.append('-s')
        if socks_url:
            argv.extend(['-x', socks_url])
        for flag, chain in (('-f', chains.get('filter')),
                            ('-a', chains.get('attrlist')),
                            ('-b', chains.get('basedn')),
                            ('-e', chains.get('attrentries'))):
            if chain:
                argv.extend([flag, chain])
        for opt in options or []:
            argv.extend(['-o', opt])
        argv.extend(decrypt_args)
        if self.verbose and not self.requests_only:
            # Full packet dumps in both directions. Response dumps include
            # every search result and get very large.
            argv.extend(['-F', '2', '-R', '2'])
        else:
            # Request summaries (original filter, middleware, rewritten filter).
            # -R 0 drops LDAP response bodies.
            argv.extend(['-F', '1', '-R', '0'])
        return argv

    def _redact_argv(self, argv):
        redacted = []
        hide_next = False
        secret_flags = {'--decrypt-hash', '--decrypt-password', '--decrypt-ccache'}
        for arg in argv:
            if hide_next:
                redacted.append('***')
                hide_next = False
                continue
            if '://' in arg and '@' in arg.split('://', 1)[-1]:
                scheme, rest = arg.split('://', 1)
                arg = scheme + '://***@' + rest.rsplit('@', 1)[1]
            redacted.append(arg)
            if arg in secret_flags:
                hide_next = True
        return redacted

    def _drain(self, proc, tag):
        for stream_name, stream in (('stdout', proc.stdout), ('stderr', proc.stderr)):
            def pump(stream=stream, stream_name=stream_name):
                try:
                    for line in iter(stream.readline, b''):
                        line = line.decode('utf-8', 'replace').rstrip()
                        if line:
                            logging.debug('[ldapx:%s:%s] %s', tag, stream_name, line)
                except Exception:
                    pass
            t = threading.Thread(target=pump)
            t.daemon = True
            t.start()

    def _wait_for_listener(self, proc, listen, timeout=15.0):
        host, port = parse_host_port(listen)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if proc.poll() is not None:
                raise CollectionException('ldapx exited immediately with code %s - run with -v to see its output' % proc.returncode)
            try:
                s = socket.create_connection((host, port), timeout=0.5)
                s.close()
                return
            except OSError:
                time.sleep(0.2)
        raise CollectionException('ldapx did not start listening on %s within %d seconds' % (listen, timeout))

    def _spawn(self, listen, target, use_ldaps, socks_url, chains, options, decrypt_args, tag):
        argv = self._build_argv(listen, target, use_ldaps, socks_url, chains, options, decrypt_args)
        logging.debug('Starting ldapx listener: %s', ' '.join(self._redact_argv(argv)))
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            raise CollectionException('Could not start ldapx binary %r: %s' % (self.binary, e))
        # Track the process before waiting so a failed listen is still stopped.
        self.processes.append(proc)
        self._drain(proc, tag)
        self._wait_for_listener(proc, listen)
        logging.debug('ldapx listener ready on %s (target %s)', listen, target)
        return proc

    def start(self, listen, target, use_ldaps, socks_url, chains, options, decrypt_args, tag='ldap'):
        spec = {
            'listen': listen,
            'target': target,
            'use_ldaps': use_ldaps,
            'socks_url': socks_url,
            'chains': chains,
            'options': options,
            'decrypt_args': decrypt_args,
            'tag': tag,
        }
        proc = self._spawn(listen, target, use_ldaps, socks_url, chains, options, decrypt_args, tag)
        self.listeners.append(spec)
        return proc

    def restart(self, decrypt_args):
        """
        Stop both listeners and start them again with new decrypt arguments.
        Used after the LDAP service ticket exists, so ldapx can inject channel bindings.
        """
        specs = [dict(spec) for spec in self.listeners]
        for spec in specs:
            spec['decrypt_args'] = decrypt_args
        self.stop()
        self.listeners = []
        self.decrypt_args = list(decrypt_args)
        # Give the listen ports a moment to leave TIME_WAIT before rebinding.
        time.sleep(0.3)
        for spec in specs:
            self.start(**spec)

    def stop(self):
        for proc in self.processes:
            try:
                proc.terminate()
            except OSError:
                pass
        for proc in self.processes:
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except OSError:
                    pass
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except Exception:
                    pass
        self.processes = []


def _first_attr(value):
    if value is None or value == '':
        return None
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def build_ldapx_decrypt_args(args, ccache_path=None):
    """
    Credentials ldapx needs to re-sign a bind when the DC enforces LDAPS
    channel binding. Explicit --ldapx-decrypt-* flags are always forwarded.
    With --ldapx-ldaps, the password or NT hash from the command line is
    added as well so an NTLM bind can be rewritten, and a generated ccache
    carries the LDAP service ticket for Kerberos.
    """
    decrypt = []
    if ccache_path:
        decrypt.extend(['--decrypt-ccache', ccache_path])
    elif args.ldapx_decrypt_ccache:
        decrypt.extend(['--decrypt-ccache', args.ldapx_decrypt_ccache])
    if args.ldapx_decrypt_hash:
        decrypt.extend(['--decrypt-hash', args.ldapx_decrypt_hash])
    elif args.ldapx_ldaps and args.password:
        # The bind uses -p when it is set, including when --hashes is also present.
        decrypt.extend(['--decrypt-password', args.password])
    elif args.ldapx_ldaps and args.hashes:
        nt_hash = args.hashes.split(':', 1)[-1]
        if nt_hash:
            decrypt.extend(['--decrypt-hash', nt_hash])
    return decrypt


def enable_ldapx_channel_binding(auth, launcher, args, dc_fqdn):
    """
    When the upstream connection is LDAPS, give ldapx the material it needs
    to inject channel bindings. Returns the temp ccache path, if one was written.
    """
    if not args.ldapx_ldaps:
        return None
    # A service ticket loaded from the user's ccache is the file ldapx must
    # decrypt with. A ticket we just requested is written to a temp file,
    # which the caller deletes.
    ccache_path = None
    ephemeral = False
    if auth.ldap_ccache_path:
        ccache_path = auth.ldap_ccache_path
        logging.debug('Using ccache %s for ldapx channel binding', ccache_path)
    elif auth.tgt is not None or auth.ldap_service_ticket is not None:
        try:
            auth.prepare_ldap_service_ticket(dc_fqdn)
        except Exception as e:
            logging.warning('Could not obtain an LDAP service ticket for channel binding: %s', e)
        else:
            if auth.ldap_service_ticket is None:
                pass
            else:
                fd, ccache_path = tempfile.mkstemp(prefix='bh-ldap-', suffix='.ccache')
                os.close(fd)
                ephemeral = True
                try:
                    os.chmod(ccache_path, 0o600)
                except OSError:
                    pass
                try:
                    auth.save_ldap_ccache(ccache_path)
                except Exception:
                    try:
                        os.remove(ccache_path)
                    except OSError:
                        pass
                    raise
                logging.debug('Wrote LDAP service ticket for ldapx channel binding')
    decrypt_args = build_ldapx_decrypt_args(args, ccache_path)
    if decrypt_args != launcher.decrypt_args:
        logging.info('Restarting ldapx with LDAPS channel-binding credentials')
        try:
            launcher.restart(decrypt_args)
        except Exception:
            if ephemeral and ccache_path:
                try:
                    os.remove(ccache_path)
                except OSError:
                    pass
            raise
    elif ephemeral and ccache_path:
        # Ticket file was written but ldapx was not restarted to load it.
        # Drop the cached ticket too, so the bind does not present a ticket
        # ldapx has never seen.
        auth.ldap_service_ticket = None
        try:
            os.remove(ccache_path)
        except OSError:
            pass
        ccache_path = None
        ephemeral = False
    return ccache_path if ephemeral else None


def discover_dc_info(listen_host, listen_port):
    """
    Read dnsHostName and defaultNamingContext from rootDSE through the ldapx
    listener using an anonymous bind. Used in ldapx mode when no usable DC
    FQDN was supplied with -dc (which is required for the Kerberos SPN).
    """
    import ldap3
    server = ldap3.Server(listen_host, port=listen_port, get_info=ldap3.NONE, connect_timeout=10)
    conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS, auto_bind=True, receive_timeout=20)
    dns_host = None
    default_nc = None
    try:
        if conn.search('', '(objectClass=*)', search_scope=ldap3.BASE,
                       attributes=['dnsHostName', 'defaultNamingContext']) and conn.response:
            attrs = conn.response[0].get('attributes', {})
            dns_host = _first_attr(attrs.get('dnsHostName'))
            default_nc = _first_attr(attrs.get('defaultNamingContext'))
    finally:
        try:
            conn.unbind()
        except Exception:
            pass
    return dns_host, default_nc


def start_ldapx_mode(args):
    """
    Start the ldapx child processes and determine the real DC FQDN to use for
    Kerberos SPNs. Returns (launcher, dc_fqdn, kdc_host, discovered_domain).
    """
    target_host, target_port = parse_host_port(args.ldapx_target, 636 if args.ldapx_ldaps else 389)
    listen_host, listen_port = parse_host_port(args.ldapx_listen)
    gc_target_port = 3269 if args.ldapx_ldaps else 3268

    chains = {
        'filter': args.ldapx_filter,
        'attrlist': args.ldapx_attrlist,
        'basedn': args.ldapx_basedn,
        'attrentries': args.ldapx_attrentries,
    }
    decrypt_args = build_ldapx_decrypt_args(args)

    launcher = LdapxLauncher(binary=args.ldapx_binary, verbose=args.v, requests_only=bool(args.log_file))
    launcher.decrypt_args = list(decrypt_args)
    try:
        launcher.start(args.ldapx_listen, '%s:%d' % (target_host, target_port),
                       args.ldapx_ldaps, args.ldapx_socks, chains, args.ldapx_option,
                       decrypt_args, tag='ldap')
        launcher.start(args.ldapx_gc_listen, '%s:%d' % (target_host, gc_target_port),
                       args.ldapx_ldaps, args.ldapx_socks, chains, args.ldapx_option,
                       decrypt_args, tag='gc')

        dc_fqdn = None
        if args.domain_controller and not is_ip_or_localhost(args.domain_controller):
            # In ldapx mode -dc is only used as the Kerberos SPN hostname,
            # never as a connection target or KDC address
            dc_fqdn = args.domain_controller

        discovered_domain = None
        if dc_fqdn is None or not args.domain:
            logging.info('Reading rootDSE through the ldapx listener to discover the DC hostname')
            try:
                dns_host, default_nc = discover_dc_info(listen_host, listen_port)
            except Exception as e:
                raise CollectionException('Could not read rootDSE through the ldapx listener: %s' % e)
            if dc_fqdn is None:
                dc_fqdn = dns_host
            if not args.domain and default_nc:
                discovered_domain = ADUtils.ldap2domain(default_nc)
                logging.info('Discovered domain from rootDSE: %s', discovered_domain)

        if dc_fqdn is None:
            raise CollectionException('Could not determine the DC FQDN via rootDSE. Specify it with -dc (e.g. -dc dc01.domain.local)')
        if not args.domain and not discovered_domain:
            raise CollectionException('Could not determine the domain from rootDSE. Specify it with -d')
        logging.debug('Using %s as DC FQDN for Kerberos SPNs', dc_fqdn)
        return launcher, dc_fqdn, target_host, discovered_domain
    except Exception:
        launcher.stop()
        raise

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


    def run(self, collect, num_workers=10, disable_pooling=False, timestamp="", computerfile="", cachefile=None, exclude_dcs=False, fileNamePrefix="", resume=None, partition_ldap=False, search_base=None, partition_auto=False, partition_buffer=1800):
        start_time = time.time()
        install_ldap_search_counter()
        if search_base:
            self.ad.search_baseDN = search_base
            logging.info('Scoped enumeration to search base: %s', search_base)
        self.resume = resume
        self.pdc.partition_ldap = partition_ldap
        self.pdc.partition_auto = partition_auto
        self.pdc.partition_buffer = partition_buffer
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
                             'You can specify more than one by separating them with a comma. (default: Default). '
                             'With --ldapx-target use DCOnly (or Group/ACL/Trusts/ObjectProps/Container): '
                             'LocalAdmin, Session, LoggedOn, DCOM, RDP, PSRemote and Experimental connect to '
                             'hosts directly and do not go through ldapx.')
    parser.add_argument('-d',
                        '--domain',
                        action='store',
                        default='',
                        help='Domain to query.')
    parser.add_argument('-v',
                        action='store_true',
                        help='Enable verbose output. With ldapx this also dumps request and '
                             'response packets to the console, including search results. '
                             'Use --log-file instead when you want a readable trace without '
                             'those results.')
    parser.add_argument('--log-file',
                        metavar='PATH',
                        action='store',
                        help='Write a timestamped debug log to PATH (the file is overwritten). '
                             'Records BloodHound debug output and the ldapx request path: '
                             'each search, the middleware chain, the original filter, and the '
                             'rewritten filter. LDAP response bodies are not written. The '
                             'console stays at info level unless -v is also set.')
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
                        help='Alternative name server to use for queries. Don\'t use while using with built in ldapx.')
    coopts.add_argument('--dns-tcp',
                        action='store_true',
                        help='Use TCP instead of UDP for DNS queries. Don\'t use while using with built in ldapx.')
    coopts.add_argument('--dns-timeout',
                        action='store',
                        type=int,
                        default=3,
                        help='DNS query timeout in seconds (default: 3). Don\'t use while using with built in ldapx.')
    coopts.add_argument('-dc',
                        '--domain-controller',
                        metavar='HOST',
                        action='store',
                        help='Override which DC to query (hostname). With --ldapx-target this is only the Kerberos '
                             'SPN hostname, not the host connected to; omit it to read the DC name from rootDSE.')
    coopts.add_argument('-gc',
                        '--global-catalog',
                        metavar='HOST',
                        action='store',
                        help='Override which GC to query (hostname). Don\'t use while using with built in ldapx.')
    coopts.add_argument('-w',
                        '--workers',
                        action='store',
                        type=int,
                        default=10,
                        help='Number of workers for computer enumeration (default: 10). Only affects direct '
                             'host enumeration; don\'t use while using with built in ldapx.')
    coopts.add_argument('--exclude-dcs',
                        action='store_true',
                        help='Skip DCs during computer enumeration. Only affects direct host enumeration; '
                             'don\'t use while using with built in ldapx.')
    coopts.add_argument('--disable-pooling',
                        action='store_true',
                        help='Don\'t use subprocesses for ACL parsing (only for debugging purposes)')
    coopts.add_argument('--disable-autogc',
                        action='store_true',
                        help='Don\'t automatically select a Global Catalog (use only if it gives errors). '
                             'Don\'t use while using with built in ldapx.')
    coopts.add_argument('--zip',
                        action='store_true',
                        help='Compress the JSON output files into a zip archive')
    coopts.add_argument('--computerfile',
                        action='store',
                        help='File containing computer FQDNs to use as allowlist for any computer based methods. '
                             'Only affects direct host enumeration; don\'t use while using with built in ldapx.')
    coopts.add_argument('--cachefile',
                        action='store',
                        help='Cache file (experimental)')
    coopts.add_argument('--ldap-channel-binding',
                        action='store_true',
                        help='Use LDAP Channel Binding (will force ldaps protocol to be used). Don\'t use while '
                             'using with built in ldapx (channel binding is injected by ldapx with --ldapx-ldaps).')
    coopts.add_argument('--use-ldaps',
                        action='store_true',
                        help='Use LDAP over TLS on port 636 by default. Don\'t use while using with built in ldapx '
                             '(use --ldapx-ldaps for upstream TLS instead).')
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
    coopts.add_argument('--partition-auto',
                        action='store_true',
                        help='Automatically decide per phase whether to use GUID slicing or a '
                             'single query based on estimated enumeration time vs the run window. '
                             'Requires --partition-ldap and --run-start/--run-end.')
    coopts.add_argument('--partition-buffer',
                        metavar='DURATION',
                        action='store',
                        default='30m',
                        help='Safety margin for --partition-auto. If estimated single-query time '
                             'plus this buffer fits in the run window, use single query. '
                             'Default: 30m. Same duration syntax (s/m/h).')
    coopts.add_argument('--search-base',
                        action='store',
                        metavar='DN',
                        help='Custom LDAP search base DN for scoped enumeration '
                             '(e.g. OU=Sales,DC=corp,DC=local). Limits all LDAP queries '
                             'to this subtree. Trust and domain-level queries still use '
                             'the domain root.')
    coopts.add_argument('--run-start',
                        metavar='HHMM',
                        action='store',
                        help='Earliest time of day to run, in 24h HHMM format (e.g. 0900). '
                             'Requires --run-end. Outside this window the tool sleeps until '
                             'the next valid window opens.')
    coopts.add_argument('--run-end',
                        metavar='HHMM',
                        action='store',
                        help='Latest time of day to run, in 24h HHMM format (e.g. 1730). '
                             'Requires --run-start.')
    coopts.add_argument('--run-days',
                        metavar='DAYS',
                        action='store',
                        help='Comma-separated day numbers when the tool may run. '
                             '1=Monday, 2=Tuesday, ..., 7=Sunday. '
                             'Default: all days. Example: 1,2,3,4,5 for weekdays.')
    coopts.add_argument('--run-jitter',
                        metavar='DURATION',
                        action='store',
                        help='Jitter on --run-start and --run-end, randomized independently '
                             'each day. Shifts the effective start and end by +/- this amount. '
                             'Plain number is minutes; suffixes s/m/h accepted (e.g. 15m, 30s, 1h). '
                             'Default: 0.')
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

    lxopts = parser.add_argument_group('ldapx proxy options', description='Route LDAP traffic through a local ldapx (https://github.com/Macmod/ldapx) child process which transforms queries and forwards them to the target, optionally via SOCKS. Kerberos tickets are still requested from the real DC (over TCP through the same SOCKS proxy when --ldapx-socks is used), with the SPN of the real DC.')
    lxopts.add_argument('--ldapx-target',
                        metavar='HOST:PORT',
                        action='store',
                        help='Enable ldapx mode. Real DC address to forward to (the value normally passed to ldapx -t). Port defaults to 636 with --ldapx-ldaps, 389 otherwise.')
    lxopts.add_argument('--ldapx-ldaps',
                        action='store_true',
                        help='Let ldapx connect to the target over LDAPS (maps to ldapx -s). The local listener stays plaintext. Channel bindings are injected on the bind when the DC requires them.')
    lxopts.add_argument('--ldapx-socks',
                        metavar='URL',
                        action='store',
                        help='SOCKS5 proxy for ldapx upstream connections (maps to ldapx -x), e.g. socks5://127.0.0.1:1080. Also used for Kerberos TCP connections to the KDC.')
    lxopts.add_argument('--ldapx-filter',
                        action='store',
                        help='ldapx search filter middleware chain (-f), e.g. OGDR')
    lxopts.add_argument('--ldapx-attrlist',
                        action='store',
                        help='ldapx attribute list middleware chain (-a), e.g. Owp')
    lxopts.add_argument('--ldapx-basedn',
                        action='store',
                        help='ldapx baseDN middleware chain (-b), e.g. OX')
    lxopts.add_argument('--ldapx-attrentries',
                        action='store',
                        help='ldapx attribute entries middleware chain (-e)')
    lxopts.add_argument('--ldapx-option',
                        metavar='KEY=VALUE',
                        action='append',
                        help='ldapx middleware option (-o). Can be specified multiple times.')
    lxopts.add_argument('--ldapx-binary',
                        action='store',
                        default='ldapx',
                        help='Path to the ldapx binary. Default: the copy downloaded into '
                             'the package on install (ldapx %s), or ldapx from PATH.' % LDAPX_VERSION)
    lxopts.add_argument('--ldapx-listen',
                        action='store',
                        default=LDAPX_DEFAULT_LISTEN,
                        help='Local listen address for the ldapx LDAP listener (default: %s)' % LDAPX_DEFAULT_LISTEN)
    lxopts.add_argument('--ldapx-gc-listen',
                        action='store',
                        default=LDAPX_DEFAULT_GC_LISTEN,
                        help='Local listen address for the ldapx Global Catalog listener (default: %s)' % LDAPX_DEFAULT_GC_LISTEN)
    lxopts.add_argument('--ldapx-decrypt-ccache',
                        metavar='PATH',
                        action='store',
                        help='Forwarded to ldapx --decrypt-ccache. Normally unnecessary: with --ldapx-ldaps the LDAP service ticket is generated and passed automatically.')
    lxopts.add_argument('--ldapx-decrypt-hash',
                        metavar='HEX',
                        action='store',
                        help='Forwarded to ldapx --decrypt-hash. With --ldapx-ldaps the NT hash or password from the command line is passed automatically for NTLM channel binding.')

    args = parser.parse_args()

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

    # Validate and enable LDAP query pacing before any LDAP socket is opened
    # (including the rootDSE discovery in ldapx mode). parser.error() exits
    # with a usage message instead of a traceback.
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
    if args.run_start and not args.run_end:
        parser.error('--run-start requires --run-end')
    if args.run_end and not args.run_start:
        parser.error('--run-end requires --run-start')
    if args.run_jitter and not args.run_start:
        parser.error('--run-jitter requires --run-start and --run-end')
    if args.run_days and not args.run_start:
        parser.error('--run-days requires --run-start and --run-end')
    if args.run_start:
        try:
            run_start_h, run_start_m = parse_run_time(args.run_start)
            run_end_h, run_end_m = parse_run_time(args.run_end)
        except ValueError as e:
            parser.error(str(e))
        if args.run_days:
            try:
                run_days = [int(d.strip()) for d in args.run_days.split(',')]
            except ValueError:
                parser.error('--run-days must be comma-separated numbers 1-7')
            for d in run_days:
                if d < 1 or d > 7:
                    parser.error('--run-days values must be 1 (Monday) through 7 (Sunday)')
        else:
            run_days = [1, 2, 3, 4, 5, 6, 7]
        run_jitter_minutes = 0
        if args.run_jitter:
            try:
                run_jitter_minutes = parse_run_jitter(args.run_jitter)
            except ValueError as e:
                parser.error(str(e))
        tw = install_time_window(run_start_h, run_start_m, run_end_h, run_end_m,
                                 run_days, run_jitter_minutes)
        logging.info(tw.describe())
        install_ldap_search_counter()
    if args.partition_auto:
        if not args.partition_ldap:
            parser.error('--partition-auto requires --partition-ldap')
        if not args.run_start:
            parser.error('--partition-auto requires --run-start and --run-end')
    try:
        partition_buffer_seconds = parse_ldap_interval(args.partition_buffer, '--partition-buffer')
    except ValueError as e:
        parser.error(str(e))
    if args.ldapx_target:
        if args.use_ldaps:
            parser.error("--use-ldaps can't be combined with --ldapx-target; use --ldapx-ldaps for upstream TLS")
        if args.ldap_channel_binding:
            parser.error("--ldap-channel-binding can't be combined with --ldapx-target; channel binding is "
                         "injected by ldapx when --ldapx-ldaps is set")
    if ldap_interval_seconds is not None or ldap_page_interval_seconds is not None:
        pacer = install_ldap_pacing(ldap_interval_seconds or 0, args.ldap_jitter,
                                    ldap_page_interval_seconds or 0, args.ldap_page_jitter)
        logging.info(pacer.describe())
    if throttle_ms is not None:
        host_pacer = install_host_pacing(throttle_ms, args.throttle_jitter)
        logging.info(host_pacer.describe())

    # ldapx mode: start the child processes first so a missing domain can be
    # discovered from rootDSE and Kerberos can be pointed at the real DC.
    # Ask for a password first so --ldapx-ldaps can hand it to ldapx for
    # NTLM channel binding before the listeners start.
    ldapx = None
    ldapx_dc_fqdn = None
    ldapx_kdc = None
    ldap_ccache = None
    try:
        if (args.username is not None and args.password is None and args.hashes is None
                and args.aesKey is None and not args.no_pass):
            args.password = getpass.getpass()

        if args.ldapx_target:
            try:
                ldapx, ldapx_dc_fqdn, ldapx_kdc, discovered_domain = start_ldapx_mode(args)
            except CollectionException as e:
                logging.error('%s', e)
                sys.exit(1)
            if discovered_domain and not args.domain:
                args.domain = discovered_domain

        if args.username is not None and args.password is not None:
            logging.debug('Authentication: username/password')
            auth = ADAuthentication(username=args.username, password=args.password, domain=args.domain, auth_method=args.auth_method, ldap_channel_binding=args.ldap_channel_binding)
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
            auth = ADAuthentication(lm_hash=lm, nt_hash=nt, username=args.username, domain=args.domain, auth_method=args.auth_method, ldap_channel_binding=args.ldap_channel_binding)
        elif args.aesKey is not None and args.username is not None:
            logging.debug('Authentication: Kerberos AES')
            auth = ADAuthentication(username=args.username, domain=args.domain, aeskey=args.aesKey, auth_method=args.auth_method, ldap_channel_binding=args.ldap_channel_binding)
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
                auth = ADAuthentication(username=args.username, password=args.password, domain=args.domain, auth_method=args.auth_method, ldap_channel_binding=args.ldap_channel_binding)

        ad = AD(auth=auth, domain=args.domain, nameserver=args.nameserver, dns_tcp=args.dns_tcp, dns_timeout=args.dns_timeout, use_ldaps=(args.use_ldaps and not args.ldapx_target))
        # Resolve collection methods
        collect = resolve_collection_methods(args.collectionmethod)
        if not collect:
            return
        logging.debug('Resolved collection methods: %s', ', '.join(list(collect)))

        if ldapx is not None:
            # ldapx mode: no DNS discovery. The DC/GC are the real DC FQDN (used
            # for Kerberos SPNs and logging), while the actual LDAP sockets go to
            # the local ldapx listeners. The KDC is the ldapx target address.
            ad.override_dc(ldapx_dc_fqdn)
            ad.override_gc(ldapx_dc_fqdn)
            ad.ldap_listener = parse_host_port(args.ldapx_listen)
            ad.gc_listener = parse_host_port(args.ldapx_gc_listen)
            auth.ldap_listener = ad.ldap_listener
            auth.gc_listener = ad.gc_listener
            auth.set_kdc(ldapx_kdc)
            if args.ldapx_socks:
                try:
                    enable_kerberos_socks(args.ldapx_socks)
                except CollectionException as e:
                    logging.error('%s', e)
                    sys.exit(1)
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
                if ldapx_dc_fqdn:
                    loaded_tgs = auth.load_ldap_service_ticket(ldapx_dc_fqdn)
                if not loaded_tgt and not loaded_tgs:
                    logging.debug('Could not load ticket from ccache, trying to request a TGT instead')
                    auth.get_tgt()
            else:
                auth.get_tgt()

        if ldapx is not None:
            try:
                ldap_ccache = enable_ldapx_channel_binding(auth, ldapx, args, ldapx_dc_fqdn)
            except CollectionException as e:
                logging.error('%s', e)
                sys.exit(1)

        bloodhound = BloodHound(ad)
        bloodhound.connect()
        try:
            resume = CollectionResume.open(args.outputprefix, bloodhound.ad.domain, collect, args.resume)
        except CollectionException as exc:
            logging.error('%s', exc)
            sys.exit(1)
        timestamp = resume.timestamp
        from bloodhound.ad.utils import get_time_window
        tw = get_time_window()
        if tw is not None:
            tw.wait_if_outside()
        bloodhound.run(collect=collect,
                       num_workers=args.workers,
                       disable_pooling=args.disable_pooling,
                       timestamp=timestamp,
                       computerfile=args.computerfile,
                       cachefile=args.cachefile,
                       exclude_dcs=args.exclude_dcs,
                       fileNamePrefix=args.outputprefix,
                       resume=resume,
                       partition_ldap=args.partition_ldap,
                       search_base=args.search_base,
                       partition_auto=args.partition_auto,
                       partition_buffer=partition_buffer_seconds)
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
        if ldapx is not None:
            ldapx.stop()
        if args.ldapx_socks:
            disable_kerberos_socks()
        if ldap_ccache:
            try:
                os.remove(ldap_ccache)
            except OSError:
                pass



if __name__ == '__main__':
    main()
