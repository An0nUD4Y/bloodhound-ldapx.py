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
from urllib.parse import urlparse
from hashlib import sha256, md5
from bloodhound.ad.utils import CollectionException, get_ldap_pacer, enable_tcp_keepalive
from binascii import unhexlify
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import ldap3
from ldap3 import Server, Connection, NTLM, ALL, NONE, SASL, KERBEROS, Tls
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from ldap3.operation.bind import bind_operation
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal, KerberosTime, Ticket
from pyasn1.codec.der import decoder, encoder
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, KRB_ERROR, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, sendReceive, KerberosError
from impacket.krb5.gssapi import CheckSumField, GSS_C_SEQUENCE_FLAG, GSS_C_REPLAY_FLAG, GSS_C_MUTUAL_FLAG
import datetime
from pyasn1.type.univ import noValue
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

"""
Active Directory authentication helper
"""
class ADAuthentication(object):
    def __init__(self, username='', password='', domain='',
                 lm_hash='', nt_hash='', aeskey='', kdc=None, auth_method='auto', ldap_channel_binding=False):
        self.username = username
        # Assume user domain and enum domain are same
        self.domain = domain.lower()
        self.userdomain = domain.lower()
        # If not, override userdomain
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
        self.ldap_channel_binding = ldap_channel_binding
        # ldapx mode: local (host, port) listeners the LDAP/GC sockets connect
        # to, while `hostname` keeps the real DC FQDN for the Kerberos SPN
        self.ldap_listener = None
        self.gc_listener = None

        # Kerberos
        self.tgt = None
        # ldap/<dc> service ticket reused for the LDAP bind. When LDAPS channel
        # binding is in play this is also the ticket written for ldapx, so the
        # proxy and the AP-REQ are decrypting the same session key.
        self.ldap_service_ticket = None
        # Set when the LDAP service ticket was loaded from the user's ccache.
        # ldapx is given that file directly; it is not a temp file to delete.
        self.ldap_ccache_path = None

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

    def getLDAPConnection(self, hostname='', ip='', baseDN='', protocol='ldaps', gc=False, _cb_retry=False):
        listener = self.gc_listener if gc else self.ldap_listener
        # With LDAP pacing on, read the rootDSE/schema only on the first bind
        # and reuse it on later connections (NONE skips the extra searches).
        pacing_on = get_ldap_pacer() is not None
        reuse_server_info = (pacing_on and self._cached_dsa_info is not None
                             and self._cached_schema_info is not None)
        info_level = NONE if reuse_server_info else ALL
        if listener is not None:
            # ldapx mode: plaintext LDAP to the local ldapx listener, which
            # forwards (and transforms) the traffic to the real DC. The
            # Kerberos SPN still uses the real DC FQDN passed as `hostname`.
            server = Server("ldap://%s:%d" % listener, get_info=info_level)
        elif gc:
            # Global Catalog connection
            if protocol == 'ldaps' or self.ldap_channel_binding is True:
                if self.ldap_channel_binding is True:
                    if not hasattr(ldap3, 'TLS_CHANNEL_BINDING'):
                        raise Exception("To use LDAP channel binding, install the patched ldap3 module: pip3 install git+https://github.com/ly4k/ldap3 or pip3 install ldap3-bleeding-edge")
                    logging.debug("Using LDAPS channel binding")
                    protocol = 'ldaps'
                    version=ssl.PROTOCOL_TLSv1_2
                    tls = Tls(validate=ssl.CERT_NONE, version=version, ciphers='ALL:@SECLEVEL=0')
                    server = Server(
                        "%s://%s:3269" % (protocol,ip),
                        use_ssl=True,
                        get_info=info_level,
                        tls=tls
                    )
                else:
                    # Ldap SSL (no channel binding)
                    server = Server("%s://%s:3269" % (protocol, ip), get_info=info_level)
            else:
                # Plain LDAP
                server = Server("%s://%s:3268" % (protocol, ip), get_info=info_level)
        else: # no GC specified
            if self.ldap_channel_binding is True:
                if not hasattr(ldap3, 'TLS_CHANNEL_BINDING'):
                    raise Exception("To use LDAP channel binding, install the patched ldap3 module: pip3 install git+https://github.com/ly4k/ldap3 or pip3 install ldap3-bleeding-edge")
                logging.debug("Using LDAPS channel binding")
                protocol = 'ldaps'
                version=ssl.PROTOCOL_TLSv1_2
                tls = Tls(validate=ssl.CERT_NONE, version=version, ciphers='ALL:@SECLEVEL=0')
                server = Server(
                    "%s://%s" % (protocol,ip),
                    use_ssl=True,
                    get_info=info_level,
                    tls=tls
                )
            else: # No LDAP Channel Binding
                server = Server("%s://%s" % (protocol, ip), get_info=info_level)
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
        if (self.tgt is not None or self.ldap_service_ticket is not None) and self.auth_method in ('kerberos', 'auto'):
            conn = Connection(server, user=ldaplogin, auto_referrals=False, password=ldappass, authentication=SASL, sasl_mechanism=KERBEROS, receive_timeout=60, auto_range=True)
            logging.debug('Authenticating to LDAP server with Kerberos')
            try:
                bound = self.ldap_kerberos(conn, hostname)
            except Exception as exc:
                if self.auth_method == 'auto':
                    logging.debug(traceback.format_exc())
                    logging.warning('Kerberos auth to LDAP failed, trying NTLM')
                    bound = False
                else:
                    logging.debug(traceback.format_exc())
                    logging.critical('Kerberos auth to LDAP failed, no authentication methods left')
                    raise CollectionException('Could not authenticate to LDAP. Check your credentials and LDAP server requirements.')
        if not bound and self.auth_method in ('auto','ntlm'):
            conn = Connection(server, user=ldaplogin, auto_referrals=False, password=ldappass, authentication=NTLM, receive_timeout=60, auto_range=True)
            logging.debug('Authenticating to LDAP server with NTLM')
            if self.ldap_channel_binding:
                from ldap3 import TLS_CHANNEL_BINDING
                logging.debug("Using LDAPS channel binding")
                protocol = 'ldaps'
                channel_binding = {"channel_binding": TLS_CHANNEL_BINDING}
                conn = Connection(server, user=ldaplogin, password=ldappass, authentication=NTLM, auto_referrals=False, receive_timeout=60, auto_range=True, **channel_binding)
            else:
                conn = Connection(server, user=ldaplogin, auto_referrals=False, password=ldappass, authentication=NTLM, receive_timeout=60, auto_range=True)
            bound = conn.bind()

        if not bound:
            result = conn.result
            if listener is not None:
                logging.error('Failure to authenticate with LDAP through the ldapx listener! Error %s : Code: %s' % (result['message'], result['result']))
                raise CollectionException('Could not authenticate to LDAP through ldapx. With --ldapx-ldaps, channel binding is injected by ldapx. '
                                          'SASL sign/seal is not added: Active Directory rejects sign/seal on a connection that is already LDAPS.')
            if result['result'] == RESULT_STRONGER_AUTH_REQUIRED and protocol == 'ldaps':
                if _cb_retry:
                    logging.error('Failure to authenticate with LDAP using LDAP Channel Binding! Error %s : Code: %s' % (result['message'], result['result']))
                    raise CollectionException('Could not authenticate to LDAP. Check your credentials and LDAP server requirements.')
                logging.warning('LDAP Authentication is refused because LDAP Channel Binding is likely enabled. '
                                'Trying to connect using LDAP Channel Binding')
                self.ldap_channel_binding = True
                return self.getLDAPConnection(hostname, ip, baseDN, 'ldaps', _cb_retry=True)
            if result['result'] == RESULT_STRONGER_AUTH_REQUIRED and protocol == 'ldap':
                logging.warning('LDAP Authentication is refused because LDAP signing is enabled. '
                                'Trying to connect over LDAPS instead...')
                return self.getLDAPConnection(hostname, ip, baseDN, 'ldaps')
            else:
                logging.error('Failure to authenticate with LDAP! Error %s : Code: %s' % (result['message'], result['result']))
                raise CollectionException('Could not authenticate to LDAP. Check your credentials and LDAP server requirements.')

        if pacing_on:
            # Cache the server-info from the first bind so later connections can
            # reuse it, and keep the socket alive across long pacing gaps.
            if not reuse_server_info:
                if conn.server.info is not None:
                    self._cached_dsa_info = conn.server.info
                if conn.server.schema is not None:
                    self._cached_schema_info = conn.server.schema
            enable_tcp_keepalive(conn.socket)
        return conn

    def ldap_kerberos(self, connection, hostname):
        # Hackery to authenticate with ldap3 using impacket Kerberos stack

        # Open ldap3 socket because we need it
        connection.open(read_server_info=False)

        username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if self.ldap_service_ticket is not None:
            logging.debug('Reusing LDAP service ticket for ldap/%s', hostname)
            tgs = self.ldap_service_ticket['tgs']
            cipher = self.ldap_service_ticket['cipher']
            sessionkey = self.ldap_service_ticket['sessionKey']
        else:
            servername = Principal('ldap/%s' % hostname, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, _, sessionkey = getKerberosTGS(servername, self.domain, self.kdc,
                                                                    self.tgt['KDC_REP'], self.tgt['cipher'], self.tgt['sessionKey'])

        # Let's build a NegTokenInit with a Kerberos AP_REQ
        blob = SPNEGO_NegTokenInit()

        # Kerberos
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

        # Let's extract the ticket from the TGS
        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

        # Now let's build the AP_REQ
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = []
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = self.userdomain
        seq_set(authenticator, 'cname', username.components_to_asn1)
        now = datetime.datetime.utcnow()

        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        peercert = None
        bindings = None
        try:
            peercert = connection.socket.getpeercert(binary_form=True)
        except AttributeError:
            # No TLS, skip
            pass
        if peercert:
            # Do TLS channel binding
            # The logic here is heavly inspired by "msldap", "minikerberos" and "asysocks" projects by @skelsec.
            # Adapted from ldap3 contributions by ThePirateWhoSmellsOfSunflowers
            peer_certificate = x509.load_der_x509_certificate(peercert, default_backend())
            peer_certificate_hash_algorithm = peer_certificate.signature_hash_algorithm

            # RFC 5929 section 4.1 hashes list
            rfc5929_hashes_list = (hashes.MD5, hashes.SHA1)

            # section 4.1 hash function selection
            if isinstance(peer_certificate_hash_algorithm, rfc5929_hashes_list):
                digest = hashes.Hash(hashes.SHA256(), default_backend())
            else:
                digest = hashes.Hash(peer_certificate_hash_algorithm, default_backend())
            digest.update(peercert)
            peer_certificate_digest = digest.finalize()

            # https://datatracker.ietf.org/doc/html/rfc2744#section-3.11
            channel_binding_struct = bytes()
            initiator_address = b'\x00'*8
            acceptor_address = b'\x00'*8

            # https://datatracker.ietf.org/doc/html/rfc5929#section-4
            application_data_raw = b'tls-server-end-point:' + peer_certificate_digest
            len_application_data = len(application_data_raw).to_bytes(4, byteorder='little', signed = False)
            application_data = len_application_data
            application_data += application_data_raw
            channel_binding_struct += initiator_address
            channel_binding_struct += acceptor_address
            channel_binding_struct += application_data
            bindings = md5(channel_binding_struct).digest()

        # Add checksum to authenticator
        authenticator['cksum'] = noValue
        authenticator['cksum']['cksumtype'] = 0x8003

        chkField = CheckSumField()
        chkField['Lgth'] = 16
        if bindings:
            chkField['Bnd'] = bindings
        # Flags stay unset. On LDAPS, Active Directory rejects a bind that
        # also requests SASL sign/seal (LDAP error 00002029). TLS already
        # covers LDAP signing; ldapx injects the channel binding into this
        # same authenticator because the local listener has no certificate.
        chkField['Flags'] = 0
        authenticator['cksum']['checksum'] = chkField.getData()

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 11
        # AP-REQ Authenticator (includes application authenticator
        # subkey), encrypted with the application session key
        # (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionkey, 11, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        blob['MechToken'] = encoder.encode(apReq)

        # From here back to ldap3
        request = bind_operation(connection.version, SASL, None, None, connection.sasl_mechanism, blob.getData())
        response = connection.post_send_single_response(connection.send('bindRequest', request, None))[0]
        connection.result = response
        if response['result'] == 0:
            connection.bound = True
            # Only read rootDSE/schema if we do not already have it (pacing
            # reuse attaches cached info to the Server, so skip the extra read).
            if connection.server.schema is None or connection.server.info is None:
                connection.refresh_server_info()
        else:
            logging.warning('Kerberos LDAP bind rejected: %s', response.get('message') or response)
        return response['result'] == 0

    def prepare_ldap_service_ticket(self, hostname):
        """
        Request ldap/<hostname> once. The bind reuses this ticket so ldapx can
        decrypt the same AP-REQ and inject LDAPS channel bindings.
        """
        if self.ldap_service_ticket is not None:
            logging.debug('Reusing LDAP service ticket already loaded for ldap/%s', hostname)
            return True
        if self.tgt is None:
            return False
        logging.debug('Requesting LDAP service ticket for ldap/%s', hostname)
        servername = Principal('ldap/%s' % hostname, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, _, sessionkey = getKerberosTGS(servername, self.domain, self.kdc,
                                                                self.tgt['KDC_REP'], self.tgt['cipher'], self.tgt['sessionKey'])
        self.ldap_service_ticket = {
            'tgs': tgs,
            'cipher': cipher,
            'sessionKey': sessionkey,
        }
        return True

    def save_ldap_ccache(self, path):
        """
        Write the LDAP service ticket in MIT ccache form for ldapx --decrypt-ccache.
        fromTGS decrypts the ticket with the TGT session key and stores the
        service session key, which is what ldapx needs to re-sign the bind.
        """
        ccache = CCache()
        ccache.fromTGS(self.ldap_service_ticket['tgs'], self.tgt['sessionKey'], self.ldap_service_ticket['sessionKey'])
        ccache.saveFile(path)

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
            if self.auth_method == 'auto':
                logging.warning('Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: %s', str(exc))
                return
            else:
                # No other auth methods, so raise exception
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

        When this succeeds, the bind and ldapx both use that ticket, so no
        TGT (AS-REQ) and no new service ticket (TGS-REQ) are sent.
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
            'tgs': tgs['KDC_REP'],
            'cipher': tgs['cipher'],
            'sessionKey': tgs['sessionKey'],
        }
        self.ldap_ccache_path = krb5cc
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


"""
Kerberos-over-SOCKS support for ldapx mode.

impacket's getKerberosTGT/getKerberosTGS resolve sendReceive from the
impacket.krb5.kerberosv5 module globals at call time, so patching that
attribute reroutes all Kerberos TCP traffic (port 88) through the proxy.
"""
_kerberos_socks_original = None


def _parse_socks5_url(proxy_url):
    """
    Accept socks5://[user:pass@]host:port, socks5h:// (remote DNS), or host:port.
    """
    raw = proxy_url if '://' in proxy_url else 'socks5://' + proxy_url
    parsed = urlparse(raw)
    if parsed.scheme not in ('socks5', 'socks5h'):
        raise CollectionException('Kerberos through ldapx only supports a SOCKS5 proxy, got %s' % proxy_url)
    if not parsed.hostname:
        raise CollectionException('Invalid SOCKS URL: %s' % proxy_url)
    return parsed.hostname, parsed.port or 1080, parsed.username, parsed.password


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
    Used in ldapx mode, where the KDC is only reachable via the proxy.
    """
    global _kerberos_socks_original
    proxy_host, proxy_port, proxy_user, proxy_pass = _parse_socks5_url(proxy_url)
    try:
        import socks
    except ImportError:
        raise CollectionException('PySocks is required for --ldapx-socks. Install it with: pip install PySocks')
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
