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
import ssl
import os
import socket
import traceback
from struct import pack, unpack
from bloodhound.ad.utils import CollectionException, get_ldap_pacer, enable_tcp_keepalive
from bloodhound.ad.obfuscation import parse_socks5_url
from binascii import unhexlify
from ldap3 import Server, Connection, NTLM, ALL, NONE, SASL, KERBEROS, Tls
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal, Ticket
from pyasn1.codec.der import decoder
from impacket.krb5.asn1 import AS_REP, TGS_REP, KRB_ERROR
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, KerberosError
from ldap3_ad_auth import bind_kerberos, bind_ntlm, ProtectionError


def ldap_to_ldaps_port(port, gc=False):
    """
    Map an LDAP/GC port to the matching LDAPS port when a bind is retried
    over TLS. Custom ports are left unchanged.
    """
    if port == 3268 or (port is None and gc):
        return 3269
    if port in (389, None):
        return 636
    return port


"""
Active Directory authentication helper
"""
class ADAuthentication(object):
    def __init__(self, username='', password='', domain='',
                 lm_hash='', nt_hash='', aeskey='', kdc=None, auth_method='auto',
                 ldap_channel_binding=False, ldaps_legacy_tls=False):
        self.username = username
        # Assume user domain and enum domain are same
        self.domain = domain.lower()
        self.userdomain = domain.lower()
        # If the domain is unspecified, the current domain is used.
        if '@' in self.username:
            self.username, self.userdomain = self.username.lower().rsplit('@', 1)
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.aeskey = aeskey
        # KDC for domain we query
        self.kdc = kdc
        # KDC for domain of the user - fill with domain first, will be resolved later
        self.userdomain_kdc = self.domain
        self.auth_method = auth_method
        # Kept for compatibility; CBT is automatic on LDAPS via ldap3-ad-auth.
        self.ldap_channel_binding = ldap_channel_binding
        self.ldaps_legacy_tls = ldaps_legacy_tls
        # Direct DC/GC (host, port) when --target is used.
        self.dc_target = None
        self.gc_target = None

        # Kerberos
        self.tgt = None
        # ldap/<dc> service ticket reused for the LDAP bind when -k has one.
        self.ldap_service_ticket = None

        # When LDAP pacing is on, the rootDSE and schema are read once on the
        # first bind and reused on later connections, so the main, resolver and
        # GC connections do not each repeat those server-info searches.
        self._cached_dsa_info = None
        self._cached_schema_info = None

    def set_aeskey(self, aeskey):
        self.aeskey = aeskey

    def set_kdc(self, kdc):
        # Set KDC
        self.kdc = kdc
        if self.userdomain == self.domain:
            # Also set it for user domain if this is equal
            self.userdomain_kdc = kdc

    def _legacy_tls(self):
        return Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2, ciphers='ALL:@SECLEVEL=0')

    def _server_host(self, ip):
        if not ip:
            return ip
        if ip.startswith('[') and ip.endswith(']'):
            return ip[1:-1]
        return ip

    def _build_server(self, ip, protocol, gc, port, info_level):
        host = self._server_host(ip)
        use_ssl = protocol == 'ldaps'
        tls = self._legacy_tls() if use_ssl and self.ldaps_legacy_tls else None
        if port is None:
            if gc:
                port = 3269 if use_ssl else 3268
            elif use_ssl:
                port = 636
            else:
                port = 389
        kwargs = {
            'host': host,
            'port': int(port),
            'use_ssl': use_ssl,
            'get_info': info_level,
        }
        if tls is not None:
            kwargs['tls'] = tls
        if use_ssl and self.ldaps_legacy_tls:
            logging.debug('Using legacy LDAPS TLS settings')
        return Server(**kwargs)

    def getLDAPConnection(self, hostname='', ip='', baseDN='', protocol='ldaps', gc=False, port=None):
        if gc and self.gc_target is not None:
            ip = ip or self.gc_target[0]
            if port is None:
                port = self.gc_target[1]
        elif not gc and self.dc_target is not None:
            ip = ip or self.dc_target[0]
            if port is None:
                port = self.dc_target[1]

        # With LDAP pacing on, read the rootDSE/schema only on the first bind
        # and reuse it on later connections (NONE skips the extra searches).
        pacing_on = get_ldap_pacer() is not None
        reuse_server_info = (pacing_on and self._cached_dsa_info is not None
                             and self._cached_schema_info is not None)
        info_level = NONE if reuse_server_info else ALL
        server = self._build_server(ip, protocol, gc, port, info_level)
        if reuse_server_info:
            # Hand the already-read rootDSE and schema to this Server so the
            # bind does not query them again.
            server.attach_dsa_info(self._cached_dsa_info)
            server.attach_schema_info(self._cached_schema_info)
        # ldap3 supports auth with the NT hash. LM hash is actually ignored since only NTLMv2 is used.
        if self.nt_hash != '':
            if self.lm_hash != '':
                ldappass = self.lm_hash + ':' + self.nt_hash
            else:
                # ldap3 requires a 32-character long string for LM hash in order to use the NT hash
                ldappass = 'aad3b435b51404eeaad3b435b51404ee:' + self.nt_hash
        else:
            ldappass = self.password
        ldaplogin = '%s\\%s' % (self.userdomain, self.username)

        bound = False
        conn = None
        bind_error = None
        if (self.tgt is not None or self.ldap_service_ticket is not None) and self.auth_method in ('kerberos', 'auto'):
            conn = Connection(server, user=ldaplogin, auto_referrals=False, password=ldappass, authentication=SASL, sasl_mechanism=KERBEROS, receive_timeout=60, auto_range=True)
            logging.debug('Authenticating to LDAP server with Kerberos')
            try:
                bound = self.ldap_kerberos(conn, hostname)
            except Exception as exc:
                if isinstance(exc, ProtectionError):
                    logging.error('Protected LDAP connection failed: %s', exc)
                    raise CollectionException('Could not verify protected LDAP connection.') from exc
                bind_error = exc
                if self.auth_method == 'auto':
                    logging.debug(traceback.format_exc())
                    logging.warning('Kerberos auth to LDAP failed, trying NTLM')
                    bound = False
                else:
                    logging.debug(traceback.format_exc())
                    logging.critical('Kerberos auth to LDAP failed, no authentication methods left')
                    raise CollectionException('Could not authenticate to LDAP. Check your credentials and LDAP server requirements.') from exc
        if not bound and self.auth_method in ('auto', 'ntlm'):
            conn = Connection(server, user=ldaplogin, auto_referrals=False, password=ldappass, authentication=NTLM, receive_timeout=60, auto_range=True)
            logging.debug('Authenticating to LDAP server with NTLM')
            try:
                bind_ntlm(conn, domain=self.userdomain, username=self.username,
                          password=self.password, lm_hash=self.lm_hash,
                          nt_hash=self.nt_hash)
                bound = True
            except Exception as exc:
                logging.debug(traceback.format_exc())
                if isinstance(exc, ProtectionError):
                    logging.error('Protected LDAP connection failed: %s', exc)
                    raise CollectionException('Could not verify protected LDAP connection.') from exc
                bind_error = exc

        if not bound:
            if conn is None and self.auth_method == 'kerberos':
                raise CollectionException('Kerberos authentication requested without a TGT.')
            result = conn.result if conn is not None else None
            result = result or {'result': None, 'message': 'protected bind failed'}
            if result['result'] == RESULT_STRONGER_AUTH_REQUIRED and protocol == 'ldap':
                logging.warning('LDAP Authentication is refused because LDAP signing is enabled. '
                                'Trying to connect over LDAPS instead...')
                return self.getLDAPConnection(hostname, ip, baseDN, 'ldaps', gc=gc,
                                              port=ldap_to_ldaps_port(port, gc=gc))
            else:
                message = str(bind_error) if bind_error is not None and result['result'] in (None, 0) else result.get('message')
                logging.error('Failure to authenticate with LDAP! Error %s : Code: %s' % (message, result['result']))
                raise CollectionException('Could not authenticate to LDAP. Check your credentials and LDAP server requirements.') from bind_error

        if pacing_on:
            # Cache the server-info from the first bind so later connections can
            # reuse it, and keep the socket alive across long pacing gaps.
            if not reuse_server_info:
                if conn.server.info is not None:
                    self._cached_dsa_info = conn.server.info
                if conn.server.schema is not None:
                    self._cached_schema_info = conn.server.schema
            enable_tcp_keepalive(_raw_socket(conn))
        return conn

    def ldap_kerberos(self, connection, hostname):
        bind_kerberos(connection, hostname=hostname, domain=self.domain,
                      user_domain=self.userdomain, username=self.username,
                      password=self.password, lm_hash=self.lm_hash,
                      nt_hash=self.nt_hash, aes_key=self.aeskey,
                      kdc=self.kdc, tgt=self.tgt, tgs=self.ldap_service_ticket)
        return True

    def get_tgt(self):
        """
        Request a Kerberos TGT given our provided inputs.

        Etype follows the credential on the command line. A password prefers
        AES and only falls back to RC4 when the KDC rejects AES. An NT hash
        can only produce RC4. An AES key uses that AES type alone.
        """
        username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        logging.info('Getting TGT for user')
        if self.aeskey:
            logging.debug('Kerberos TGT will use the supplied AES key')
        elif self.nt_hash:
            logging.debug('Kerberos TGT will use RC4 because an NT hash was provided')
        else:
            logging.debug('Kerberos TGT will prefer AES. RC4 is used only if the KDC rejects AES')

        try:
            tgt, cipher, _, session_key = getKerberosTGT(username, self.password, self.userdomain,
                                                         unhexlify(self.lm_hash), unhexlify(self.nt_hash),
                                                         self.aeskey,
                                                         self.userdomain_kdc)
        except Exception as exc:
            logging.debug(traceback.format_exc())
            skew = 'KRB_AP_ERR_SKEW' in str(exc) or 'Clock skew' in str(exc)
            if self.auth_method == 'auto':
                if skew:
                    logging.warning('Failed to get Kerberos TGT (clock skew too great; sync time with the DC). Falling back to NTLM. Error: %s', str(exc))
                else:
                    logging.warning('Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: %s', str(exc))
                return
            else:
                if skew:
                    logging.error('Failed to get Kerberos TGT: clock skew too great. Sync this host\'s clock with the DC.')
                else:
                    logging.error('Failed to get Kerberos TGT.')
                raise

        if self.userdomain != self.domain:
            # Try to get inter-realm TGT
            username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            servername = Principal('krbtgt/%s' % self.domain, type=constants.PrincipalNameType.NT_SRV_INST.value)
            # Get referral TGT
            tgs, cipher, _, sessionkey = getKerberosTGS(servername, self.userdomain, self.userdomain_kdc,
                                                                    tgt, cipher, session_key)
            # See if this is a ticket for the correct domain
            refneeded = True
            max_referrals = 10
            referrals = 0
            while refneeded:
                decoded_tgs = decoder.decode(tgs, asn1Spec = TGS_REP())[0]
                sname_components = decoded_tgs['ticket']['sname']['name-string']
                if len(sname_components) < 2:
                    raise CollectionException('Kerberos referral ticket has no realm component in its server name')
                next_realm = str(sname_components[1])
                if next_realm.upper() == self.domain.upper():
                    refneeded = False
                else:
                    referrals += 1
                    if referrals > max_referrals:
                        raise CollectionException('Exceeded %d Kerberos referrals while requesting a TGT for %s' % (max_referrals, self.domain))
                    # Get next referral TGT
                    logging.debug('Following referral across trust to get next TGT')
                    servername = Principal('krbtgt/%s' % self.domain, type=constants.PrincipalNameType.NT_SRV_INST.value)
                    tgs, cipher, _, sessionkey = getKerberosTGS(servername, next_realm, next_realm,
                                                                            tgs, cipher, sessionkey)

            # Get foreign domain TGT
            servername = Principal('krbtgt/%s' % self.domain, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, _, sessionkey = getKerberosTGS(servername, self.domain, self.kdc,
                                                                    tgs, cipher, sessionkey)
            # Store this as our TGT
            self.tgt = {
                'KDC_REP': tgs,
                'cipher': cipher,
                'sessionKey': sessionkey
            }
        else:
            TGT = dict()
            TGT['KDC_REP'] = tgt
            TGT['cipher'] = cipher
            TGT['sessionKey'] = session_key
            self.tgt = TGT

    def get_tgs_for_smb(self, hostname):
        """
        Get a TGS for use with SMB Connection. We do this here to make sure the realms are correct,
        since impacket doesn't support cross-realm TGT usage and we don't want it to do its own Kerberos
        """
        username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        servername = Principal('cifs/%s' % hostname, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, _, sessionkey = getKerberosTGS(servername, self.domain, self.kdc,
                                                                self.tgt['KDC_REP'], self.tgt['cipher'], self.tgt['sessionKey'])
        return {
            'KDC_REP': tgs,
            'cipher': cipher,
            'sessionKey': sessionkey
        }

    def _ccache_path(self):
        """
        Path of the Kerberos credential cache, or None when there is no file.
        """
        krb5cc = os.getenv('KRB5CCNAME')
        if krb5cc and krb5cc.upper().startswith('FILE:'):
            krb5cc = krb5cc[5:]
        if krb5cc and os.path.isfile(krb5cc):
            return krb5cc
        return None

    def load_ldap_service_ticket(self, hostname):
        """
        Load an existing ldap/<hostname> service ticket from the ccache.

        When this succeeds, the bind reuses that ticket so no TGT (AS-REQ)
        and no new service ticket (TGS-REQ) are sent.
        """
        krb5cc = self._ccache_path()
        if krb5cc is None:
            return False
        ccache = CCache.loadFile(krb5cc)
        principal = 'ldap/%s@%s' % (hostname, self.domain.upper())
        creds = ccache.getCredential(principal, anySPN=False)
        if creds is None:
            logging.debug('No LDAP service ticket for %s in %s', principal, krb5cc)
            return False
        client = creds['client'].prettyPrint()
        if isinstance(client, bytes):
            client = client.decode('utf-8', 'replace')
        expected = '%s@%s' % (self.username, self.domain.upper())
        if expected.upper() != client.upper():
            logging.warning('LDAP service ticket in ccache is for %s, not %s', client, expected)
            return False
        tgs = creds.toTGS()
        self.ldap_service_ticket = {
            'KDC_REP': tgs['KDC_REP'],
            'cipher': tgs['cipher'],
            'sessionKey': tgs['sessionKey'],
        }
        logging.info('Using LDAP service ticket from cache')
        return True

    def load_ccache(self):
        """
        Extract a TGT from a ccache file.
        """
        # If the kerberos credential cache is known, use that.
        krb5cc = self._ccache_path()

        # Otherwise, guess it.
        if krb5cc is None:
            try:
                krb5cc = '/tmp/krb5cc_%u' % os.getuid()
            except AttributeError:
                # This fails on Windows
                krb5cc = 'nonexistingfile'

        if os.path.isfile(krb5cc):
            logging.debug('Using kerberos credential cache: %s', krb5cc)
        else:
            logging.debug('No Kerberos credential cache file found, manually requesting TGT')
            return False

        # Load TGT for our domain
        ccache = CCache.loadFile(krb5cc)
        principal = 'krbtgt/%s@%s' % (self.domain.upper(), self.domain.upper())
        creds = ccache.getCredential(principal, anySPN=False)
        if creds is not None:
            TGT = creds.toTGT()
            # This we store for later
            self.tgt = TGT
            tgt, cipher, session_key = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
            logging.info('Using TGT from cache')
        else:
            logging.debug("No valid credentials found in cache. ")
            return False

        # Verify if this ticket is actually for the specified user
        ticket = Ticket()
        decoded_tgt = decoder.decode(tgt, asn1Spec = AS_REP())[0]
        ticket.from_asn1(decoded_tgt['ticket'])

        tgt_principal = Principal()
        tgt_principal.from_asn1(decoded_tgt, 'crealm', 'cname')
        expected_principal = '%s@%s' % (self.username.lower(), self.domain.upper())
        if expected_principal.upper() != str(tgt_principal).upper():
            logging.warning('Username in ccache file does not match supplied username! %s != %s', tgt_principal, expected_principal)
            return False
        else:
            logging.info('Found TGT with correct principal in ccache file.')
        return True


def _raw_socket(conn):
    sock = getattr(conn, 'socket', None)
    if sock is None:
        return None
    for attr in ('socket', '_socket', 'sock'):
        inner = getattr(sock, attr, None)
        if inner is not None and inner is not sock:
            return inner
    return sock


"""
Kerberos-over-SOCKS support.

impacket's getKerberosTGT/getKerberosTGS resolve sendReceive from the
impacket.krb5.kerberosv5 module globals at call time, so patching that
attribute reroutes all Kerberos TCP traffic (port 88) through the proxy.
"""
_kerberos_socks_original = None


def _recv_exact(sock, size):
    buf = b''
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise socket.error('Connection closed while reading the Kerberos reply')
        buf += chunk
    return buf


def _socks_send_receive(proxy_host, proxy_port, proxy_user, proxy_pass, socks_module):
    def sendReceive(data, host, kdcHost, port=88):
        if kdcHost is None:
            kdcHost = host

        messageLen = pack('!i', len(data))

        logging.debug('Trying to connect to KDC at %s:%s through SOCKS proxy %s:%d', kdcHost, port, proxy_host, proxy_port)
        s = socks_module.socksocket()
        s.set_proxy(socks_module.SOCKS5, proxy_host, proxy_port, rdns=True,
                    username=proxy_user, password=proxy_pass)
        s.settimeout(30)
        try:
            s.connect((kdcHost, port))
        except (socket.error, socks_module.ProxyError) as e:
            raise socket.error("Connection error (%s:%s)" % (kdcHost, port), e)

        try:
            s.sendall(messageLen + data)
            recvDataLen = unpack('!i', _recv_exact(s, 4))[0]
            if recvDataLen <= 0 or recvDataLen > 10 * 1024 * 1024:
                raise socket.error('Invalid Kerberos reply length from %s:%s' % (kdcHost, port))
            recvData = _recv_exact(s, recvDataLen)
        finally:
            s.close()

        # Match impacket's sendReceive: a PREAUTH_REQUIRED error is returned
        # to the caller, every other KRB_ERROR is raised. getKerberosTGT uses
        # that raise to fall back from AES to RC4.
        try:
            krb_error = KerberosError(packet=decoder.decode(recvData, asn1Spec=KRB_ERROR())[0])
        except Exception:
            return recvData
        if int(krb_error.getErrorCode()) != int(constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value):
            raise krb_error
        return recvData

    return sendReceive


def enable_kerberos_socks(proxy_url):
    """
    Route impacket's Kerberos TCP traffic through a SOCKS5 proxy.
    """
    global _kerberos_socks_original
    proxy_host, proxy_port, proxy_user, proxy_pass = parse_socks5_url(proxy_url)
    try:
        import socks
    except ImportError:
        raise CollectionException('PySocks is required for --socks. Install it with: pip install PySocks')
    from impacket.krb5 import kerberosv5
    if _kerberos_socks_original is None:
        _kerberos_socks_original = kerberosv5.sendReceive
    kerberosv5.sendReceive = _socks_send_receive(proxy_host, proxy_port, proxy_user, proxy_pass, socks)
    logging.debug('Kerberos traffic will be routed through SOCKS proxy %s:%d', proxy_host, proxy_port)


def disable_kerberos_socks():
    """Restore impacket's original sendReceive."""
    global _kerberos_socks_original
    if _kerberos_socks_original is not None:
        from impacket.krb5 import kerberosv5
        kerberosv5.sendReceive = _kerberos_socks_original
        _kerberos_socks_original = None
