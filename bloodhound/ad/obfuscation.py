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
"""
In-process LDAP query obfuscation via ldapx-py, plus a SOCKS5 dialer for ldap3.

Filters are parsed by ldapx, transformed on the AST, and compiled directly to
ldap3 ASN.1 so OID spacing, garbage attributes, and single-byte objectGUID
escapes survive ldap3's string parser.
"""
import logging
import socket
import threading
from datetime import datetime
from urllib.parse import urlparse

from bloodhound.ad.utils import CollectionException

_LIST_OPTIONS = {'FiltApproxExcludeAttrs'}
_DANGEROUS_ATTRLIST = {
    'W': 'replace the attribute list with *',
    'w': 'add * to the attribute list',
    'p': 'add + (operational attributes)',
    'e': 'replace the attribute list with empty',
    'O': 'rewrite names to spaced OIDs; BloodHound looks up attributes by LDAP name',
    'o': 'rewrite names to spaced OIDs; BloodHound looks up attributes by LDAP name',
}
_SKIPPED_ATTRLIST = 'Oo'

_OBFUSCATOR = None
_OBF_INSTALLED = False
_SOCKS_INSTALLED = False
_SOCKS_STATE = None
_bypass = threading.local()

_orig_search_operation = None
_orig_connection_search = None
_orig_safe_dn = None
_orig_cidict_contains = None
_orig_open_socket = None
_orig_address_info = None
_orig_dns_socket_factory = None


def parse_ldapx_options(option_list):
    """
    Parse repeatable --obf-option KEY=VALUE strings into ldapx.Options.
    """
    import ldapx

    if not option_list:
        return ldapx.Options()
    overrides = {}
    for item in option_list:
        if not item or '=' not in item:
            logging.warning('Ignoring invalid --obf-option %r (expected KEY=VALUE)', item)
            continue
        key, value = item.split('=', 1)
        key = key.strip()
        value = value.strip()
        if key in _LIST_OPTIONS:
            overrides[key] = [v.strip() for v in value.split(',') if v.strip()]
        elif value.lower() in ('true', 'false'):
            overrides[key] = value.lower() == 'true'
        else:
            try:
                overrides[key] = int(value)
            except ValueError:
                try:
                    overrides[key] = float(value)
                except ValueError:
                    overrides[key] = value
    return ldapx.Options(**overrides)


def parse_socks5_url(proxy_url):
    """
    Accept socks5://[user:pass@]host:port, socks5h:// (remote DNS), or host:port.
    """
    raw = proxy_url if '://' in proxy_url else 'socks5://' + proxy_url
    parsed = urlparse(raw)
    if parsed.scheme not in ('socks5', 'socks5h'):
        raise CollectionException('Only SOCKS5 is supported, got %s' % proxy_url)
    if not parsed.hostname:
        raise CollectionException('Invalid SOCKS URL: %s' % proxy_url)
    return parsed.hostname, parsed.port or 1080, parsed.username, parsed.password


def warn_dangerous_attrlist(chain):
    """
    Log a warning when AttrList codes change what the server returns.
    """
    if not chain:
        return
    active = [code for code in chain if code in _DANGEROUS_ATTRLIST]
    if not active:
        return
    details = ', '.join('%s (%s)' % (code, _DANGEROUS_ATTRLIST[code]) for code in active)
    logging.warning(
        'AttrList code(s) %s change what the server returns and can break BloodHound parsing: %s',
        ''.join(active), details)


def _preescape_filter(filter_str):
    """
    Turn raw non-ASCII / NUL characters into RFC 4515 hex escapes so ldapx
    can parse them, without rewriting escapes that are already present.
    """
    if not filter_str:
        return filter_str
    out = []
    i = 0
    length = len(filter_str)
    while i < length:
        ch = filter_str[i]
        if ch == '\\' and i + 2 < length:
            hexpart = filter_str[i + 1:i + 3]
            try:
                int(hexpart, 16)
            except ValueError:
                pass
            else:
                out.append(filter_str[i:i + 3])
                i += 3
                continue
        code = ord(ch)
        if code == 0 or code > 127:
            out.append('\\%02x' % (code & 0xff))
        else:
            out.append(ch)
        i += 1
    return ''.join(out)


def _assertion_bytes(value):
    """
    Encode an ldapx AST assertion value as LDAP assertion bytes.

    ldapx stores decoded \\xx escapes as Latin-1 code points (U+0080-U+00FF).
    Encoding those as Latin-1 preserves the original single byte. Remaining
    ASCII \\xx sequences are expanded by ldap3's prepare_filter_for_sending.
    """
    from ldap3.protocol.convert import prepare_filter_for_sending

    if value is None:
        return b''
    if isinstance(value, bytes):
        raw = value
    else:
        try:
            raw = value.encode('latin-1')
        except UnicodeEncodeError:
            raw = value.encode('utf-8')
    # ldapx already decoded RFC 4515 \\xx escapes to Latin-1 code points.
    # If the value has those decoded bytes, do not run ldap3's expander:
    # a literal backslash followed by two hex digits would be treated as
    # another escape. ASCII remaining \\xx (hex-value middleware) still
    # needs expansion.
    if any(b == 0 or b > 127 for b in raw):
        return bytes(raw)
    return prepare_filter_for_sending(raw)


def _attr_desc(name):
    from ldap3.protocol.rfc4511 import AttributeDescription
    if name is None:
        name = ''
    return AttributeDescription(name)


def ast_to_ldap3_filter(ast_node):
    """
    Convert an ldapx filter AST node to an ldap3 rfc4511.Filter.
    """
    from ldapx.parser.filter import (
        FilterAnd, FilterOr, FilterNot,
        FilterEqualityMatch, FilterSubstring, FilterPresent,
        FilterGreaterOrEqual, FilterLessOrEqual,
        FilterApproxMatch, FilterExtensibleMatch,
    )
    from ldap3.protocol.rfc4511 import (
        Filter, And, Or, Not, EqualityMatch, AssertionValue,
        ApproxMatch, GreaterOrEqual, LessOrEqual, ExtensibleMatch,
        Present, SubstringFilter, Substrings, Substring,
        Initial, Any, Final, MatchingRule, Type, MatchValue, DnAttributes,
    )

    compiled = Filter()
    if isinstance(ast_node, FilterAnd):
        boolean_filter = And()
        for pos, element in enumerate(ast_node.filters):
            boolean_filter[pos] = ast_to_ldap3_filter(element)
        compiled['and'] = boolean_filter
    elif isinstance(ast_node, FilterOr):
        boolean_filter = Or()
        for pos, element in enumerate(ast_node.filters):
            boolean_filter[pos] = ast_to_ldap3_filter(element)
        compiled['or'] = boolean_filter
    elif isinstance(ast_node, FilterNot):
        boolean_filter = Not()
        boolean_filter['innerNotFilter'] = ast_to_ldap3_filter(ast_node.filter)
        compiled.setComponentByName('notFilter', boolean_filter, verifyConstraints=False)
    elif isinstance(ast_node, FilterPresent):
        compiled['present'] = Present(_attr_desc(ast_node.attribute_desc))
    elif isinstance(ast_node, FilterEqualityMatch):
        matching_filter = EqualityMatch()
        matching_filter['attributeDesc'] = _attr_desc(ast_node.attribute_desc)
        matching_filter['assertionValue'] = AssertionValue(_assertion_bytes(ast_node.assertion_value))
        compiled.setComponentByName('equalityMatch', matching_filter)
    elif isinstance(ast_node, FilterGreaterOrEqual):
        matching_filter = GreaterOrEqual()
        matching_filter['attributeDesc'] = _attr_desc(ast_node.attribute_desc)
        matching_filter['assertionValue'] = AssertionValue(_assertion_bytes(ast_node.assertion_value))
        compiled['greaterOrEqual'] = matching_filter
    elif isinstance(ast_node, FilterLessOrEqual):
        matching_filter = LessOrEqual()
        matching_filter['attributeDesc'] = _attr_desc(ast_node.attribute_desc)
        matching_filter['assertionValue'] = AssertionValue(_assertion_bytes(ast_node.assertion_value))
        compiled['lessOrEqual'] = matching_filter
    elif isinstance(ast_node, FilterApproxMatch):
        matching_filter = ApproxMatch()
        matching_filter['attributeDesc'] = _attr_desc(ast_node.attribute_desc)
        matching_filter['assertionValue'] = AssertionValue(_assertion_bytes(ast_node.assertion_value))
        compiled['approxMatch'] = matching_filter
    elif isinstance(ast_node, FilterSubstring):
        matching_filter = SubstringFilter()
        matching_filter['type'] = _attr_desc(ast_node.attribute_desc)
        substrings = Substrings()
        pos = 0
        for sub in ast_node.substrings or []:
            if sub.initial:
                substrings[pos] = Substring().setComponentByName(
                    'initial', Initial(_assertion_bytes(sub.initial)))
                pos += 1
            elif sub.any:
                substrings[pos] = Substring().setComponentByName(
                    'any', Any(_assertion_bytes(sub.any)))
                pos += 1
            elif sub.final:
                substrings[pos] = Substring().setComponentByName(
                    'final', Final(_assertion_bytes(sub.final)))
                pos += 1
        matching_filter['substrings'] = substrings
        compiled['substringFilter'] = matching_filter
    elif isinstance(ast_node, FilterExtensibleMatch):
        matching_filter = ExtensibleMatch()
        if ast_node.matching_rule:
            matching_filter['matchingRule'] = MatchingRule(ast_node.matching_rule)
        if ast_node.attribute_desc:
            matching_filter['type'] = Type(ast_node.attribute_desc)
        matching_filter['matchValue'] = MatchValue(_assertion_bytes(ast_node.match_value))
        matching_filter['dnAttributes'] = DnAttributes(bool(ast_node.dn_attributes))
        compiled['extensibleMatch'] = matching_filter
    else:
        raise ValueError('Unsupported filter AST type: %s' % type(ast_node))
    return compiled


def _loggable_filter(filter_str):
    if not filter_str:
        return filter_str
    out = []
    for ch in filter_str:
        code = ord(ch)
        if code < 32 or code > 126:
            out.append('\\%02x' % (code & 0xff))
        else:
            out.append(ch)
    return ''.join(out)


class LdapxObfuscator(object):
    """
    Holds ldapx middleware chains and per-DN GUID/SID metadata.
    """

    def __init__(self, filter_chain=None, basedn_chain=None, attrlist_chain=None,
                 attrentries_chain=None, options=None):
        import ldapx

        self.filter_chain = filter_chain or ''
        self.basedn_chain = basedn_chain or ''
        raw_attrlist = attrlist_chain or ''
        skipped = ''.join(c for c in raw_attrlist if c in _SKIPPED_ATTRLIST)
        if skipped:
            logging.warning(
                'AttrList code(s) %s ignored: BloodHound reads attributes by LDAP name, so OID rewriting breaks collection',
                skipped)
        self.attrlist_chain = ''.join(c for c in raw_attrlist if c not in _SKIPPED_ATTRLIST)
        self.attrentries_chain = attrentries_chain or ''
        self.options = options if options is not None else ldapx.Options()
        self._dn_metadata = {}
        self._config_nc = None
        self._schema_nc = None
        self._transform_cache = {}
        self._user_set_guid = bool(self.options.get('BaseDNGuid'))
        self._user_set_sid = bool(self.options.get('BaseDNSid'))
        self._user_set_config = bool(self.options.get('FiltObjectCategoryConfigNC'))

    def register_dn_metadata(self, dn, guid_hex=None, sid_str=None):
        if not dn:
            return
        key = dn
        current = self._dn_metadata.get(key, {})
        if guid_hex:
            current['guid'] = guid_hex
        if sid_str:
            current['sid'] = sid_str
        self._dn_metadata[key] = current

    def set_config_nc(self, config_nc):
        self._config_nc = config_nc
        if config_nc and not self._user_set_config:
            self.options.set('FiltObjectCategoryConfigNC', config_nc)

    def set_schema_nc(self, schema_nc):
        self._schema_nc = schema_nc

    def _clone_options(self):
        import ldapx
        opts = ldapx.Options()
        opts._values = dict(self.options._values)
        return opts

    def _lookup_metadata(self, dn):
        if not dn:
            return None
        needle = dn.strip().lower()
        for registered, meta in self._dn_metadata.items():
            if registered.strip().lower() == needle:
                return meta
        return None

    def _options_for(self, search_base):
        # U/I GUID/SID substitution applies only when search_base is exactly
        # a registered naming context. Descendant DNs must keep their own
        # base; ldapx would otherwise rewrite them to the domain object.
        opts = self._clone_options()
        meta = self._lookup_metadata(search_base)
        if meta is not None:
            if not self._user_set_guid:
                opts.set('BaseDNGuid', meta.get('guid') or '')
            if not self._user_set_sid:
                opts.set('BaseDNSid', meta.get('sid') or '')
        else:
            if not self._user_set_guid:
                opts.set('BaseDNGuid', '')
            if not self._user_set_sid:
                opts.set('BaseDNSid', '')
        if self._config_nc and not self._user_set_config:
            opts.set('FiltObjectCategoryConfigNC', self._config_nc)
        return opts

    def obfuscate_filter_ast(self, search_filter):
        """
        Return (obfuscated_string, compiled_asn1_or_None).
        """
        import ldapx
        from ldapx.parser import query_to_filter, filter_to_query

        if not search_filter or not self.filter_chain:
            return search_filter, None
        prepared = _preescape_filter(search_filter)
        try:
            ast = query_to_filter(prepared)
        except Exception as exc:
            logging.warning('Failed to parse LDAP filter for obfuscation: %s', exc)
            return search_filter, None

        middlewares = ldapx._build_filter_middlewares(self._options_for(''))
        for code in self.filter_chain:
            factory = middlewares.get(code)
            if factory:
                ast = factory()(ast)
            else:
                logging.warning('Unknown filter obfuscation code: %s', code)

        try:
            compiled = ast_to_ldap3_filter(ast)
        except Exception as exc:
            logging.warning('Failed to compile obfuscated filter to ASN.1: %s', exc)
            compiled = None
        try:
            as_string = filter_to_query(ast)
        except Exception:
            as_string = search_filter
        logging.debug('Obfuscated filter (%s): %s -> %s',
                      self.filter_chain,
                      _loggable_filter(search_filter),
                      _loggable_filter(as_string))
        return as_string, compiled

    def obfuscate_basedn(self, search_base):
        import ldapx

        if not search_base or not self.basedn_chain:
            return search_base
        original = search_base
        result = ldapx.obfuscate_basedn(search_base, self.basedn_chain,
                                        options=self._options_for(search_base))
        if result != original:
            logging.debug('Obfuscated BaseDN (%s): %s -> %s',
                          self.basedn_chain, original, result)
        return result

    def obfuscate_attrlist(self, attributes):
        import ldapx
        from ldap3 import ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, NO_ATTRIBUTES, SEQUENCE_TYPES

        if not self.attrlist_chain or attributes is None:
            return attributes
        if attributes == ALL_ATTRIBUTES:
            attr_list = [ALL_ATTRIBUTES]
        elif isinstance(attributes, str):
            attr_list = [attributes]
        elif isinstance(attributes, SEQUENCE_TYPES):
            attr_list = list(attributes)
        else:
            return attributes
        if not attr_list:
            return attributes
        if len(attr_list) == 1 and attr_list[0] in (NO_ATTRIBUTES, '1.1'):
            return attributes
        original = list(attr_list)
        result = ldapx.obfuscate_attrlist(attr_list, self.attrlist_chain, options=self.options)
        logging.debug('Obfuscated AttrList (%s): %s -> %s',
                      self.attrlist_chain, original, result)
        return result

    def obfuscate_attrentries(self, entries):
        import ldapx

        if not self.attrentries_chain or not entries:
            return entries
        original = dict(entries)
        result = ldapx.obfuscate_attrentries(entries, self.attrentries_chain, options=self.options)
        logging.debug('Obfuscated AttrEntries (%s): %s -> %s',
                      self.attrentries_chain, list(original.keys()), list(result.keys()))
        return result

    def transform(self, search_base, search_filter, search_scope, attributes, skip_attrlist=False):
        # Reuse the first rewrite for later pages of the same search. OGDR/RD
        # are non-deterministic; AD paging cookies require an identical filter
        # and attribute list on every page.
        attr_key = None
        if attributes is not None and not skip_attrlist:
            try:
                attr_key = tuple(attributes) if not isinstance(attributes, str) else (attributes,)
            except TypeError:
                attr_key = (str(attributes),)
        cache_key = (search_base, search_filter, search_scope, attr_key, skip_attrlist)
        cached = self._transform_cache.get(cache_key)
        if cached is not None:
            return cached
        compiled = None
        if self.filter_chain and search_filter:
            search_filter, compiled = self.obfuscate_filter_ast(search_filter)
        if self.basedn_chain and search_base:
            search_base = self.obfuscate_basedn(search_base)
        if self.attrlist_chain and not skip_attrlist:
            attributes = self.obfuscate_attrlist(attributes)
        result = (search_base, search_filter, attributes, compiled)
        self._transform_cache[cache_key] = result
        return result


def get_obfuscator():
    return _OBFUSCATOR


def _is_rootdse(search_base, search_scope):
    from ldap3 import BASE
    if search_base not in ('', None):
        return False
    return search_scope in (BASE, 0, 'BASE', 'baseObject')


def _is_schema_or_dsa_read(search_base, search_scope, search_filter, attributes):
    """
    ldap3's schema dump is a BASE search for (objectClass=subschema) at the
    subschemaSubentry DN. AttrList W/w/p/e and filter garbage would break it.
    """
    from ldap3 import BASE
    if search_scope not in (BASE, 0, 'BASE', 'baseObject'):
        return False
    filt = (search_filter or '').replace(' ', '').lower()
    if filt in ('(objectclass=subschema)', 'objectclass=subschema'):
        return True
    names = attributes
    if isinstance(names, str):
        names = [names]
    try:
        lowered = {str(n).lower() for n in (names or []) if n}
    except TypeError:
        return False
    return bool(lowered & {'subschemasubentry', 'objectclasses', 'attributetypes', 'ldapsyntaxes'})


def _is_schema_nc_search(search_base):
    """
    BloodHound's object-type map is a SUBTREE of the schema NC. Filter/attrlist
    obfuscation there breaks paging cookies and schemaIDGUID lookups.
    """
    if not search_base:
        return False
    needle = search_base.replace(' ', '').lower()
    if needle.startswith('cn=schema,cn=configuration,') or ',cn=schema,cn=configuration,' in needle:
        return True
    schema = getattr(_OBFUSCATOR, '_schema_nc', None) if _OBFUSCATOR is not None else None
    if not schema:
        return False
    key = schema.replace(' ', '').lower()
    return needle == key or needle.endswith(',' + key)


def _should_skip_obfuscation(search_base, search_scope, search_filter=None, attributes=None):
    if _is_rootdse(search_base, search_scope):
        return True
    if _is_schema_nc_search(search_base):
        return True
    return _is_schema_or_dsa_read(search_base, search_scope, search_filter, attributes)


def _is_range_request(attributes):
    if not attributes:
        return False
    if isinstance(attributes, str):
        attributes = [attributes]
    try:
        for name in attributes:
            if name and ';range=' in str(name).lower():
                return True
    except TypeError:
        return False
    return False


def _set_bypass(active):
    _bypass.active = bool(active)


def _bypass_active():
    return bool(getattr(_bypass, 'active', False))


def install_ldapx_obfuscation(obfuscator):
    """
    Hook ldap3 request construction so every search is obfuscated.

    Request-side safe_dn() and schema.attribute_types checks are bypassed
    while the SearchRequest is built. Connection.check_names stays True for
    response formatting. Must be called before install_ldap_pacing so the
    pacer wraps this Connection.search wrapper.
    """
    global _OBFUSCATOR, _OBF_INSTALLED
    global _orig_search_operation, _orig_connection_search, _orig_safe_dn, _orig_cidict_contains

    _OBFUSCATOR = obfuscator
    if _OBF_INSTALLED:
        return
    _OBF_INSTALLED = True

    import ldap3
    import ldap3.core.connection as conn_mod
    import ldap3.operation.search as search_mod
    import ldap3.utils.dn as dn_mod
    from ldap3.utils.ciDict import CaseInsensitiveDict

    _orig_search_operation = search_mod.search_operation
    _orig_connection_search = ldap3.Connection.search
    _orig_safe_dn = conn_mod.safe_dn
    _orig_cidict_contains = CaseInsensitiveDict.__contains__

    def _safe_dn(dn, *args, **kwargs):
        if _bypass_active():
            try:
                return _orig_safe_dn(dn, *args, **kwargs)
            except Exception:
                return dn
        return _orig_safe_dn(dn, *args, **kwargs)

    def _contains(self, item):
        if _bypass_active():
            return True
        return _orig_cidict_contains(self, item)

    def _search_operation(search_base,
                          search_filter,
                          search_scope,
                          dereference_aliases,
                          attributes,
                          size_limit,
                          time_limit,
                          types_only,
                          auto_escape,
                          auto_encode,
                          schema=None,
                          validator=None,
                          check_names=False):
        current = _OBFUSCATOR
        compiled = None
        dummy_filter = search_filter
        if current is not None and not _should_skip_obfuscation(
                search_base, search_scope, search_filter, attributes):
            skip_attrlist = _is_range_request(attributes)
            search_base, search_filter, attributes, compiled = current.transform(
                search_base, search_filter, search_scope, attributes,
                skip_attrlist=skip_attrlist)
            dummy_filter = '(objectClass=*)' if compiled is not None else search_filter
            schema = None
            check_names = False
        try:
            request = _orig_search_operation(
                search_base,
                dummy_filter,
                search_scope,
                dereference_aliases,
                attributes,
                size_limit,
                time_limit,
                types_only,
                auto_escape,
                auto_encode,
                schema=schema,
                validator=validator,
                check_names=check_names)
        finally:
            _set_bypass(False)
        if compiled is not None:
            request['filter'] = compiled
        return request

    def _connection_search(self, *args, **kwargs):
        if _OBFUSCATOR is None:
            return _orig_connection_search(self, *args, **kwargs)
        _set_bypass(True)
        try:
            return _orig_connection_search(self, *args, **kwargs)
        finally:
            _set_bypass(False)

    conn_mod.safe_dn = _safe_dn
    dn_mod.safe_dn = _safe_dn
    CaseInsensitiveDict.__contains__ = _contains
    search_mod.search_operation = _search_operation
    conn_mod.search_operation = _search_operation
    ldap3.Connection.search = _connection_search
    logging.debug('Installed in-process ldapx-py obfuscation')


def enable_ldap_socks(proxy_url):
    """
    Dial ldap3 sockets through a SOCKS5 proxy. DNS SRV lookups stay local;
    LDAP/LDAPS/GC TCP connections use the proxy with remote DNS (rdns=True).

    The SOCKS socket is swapped in only for ldap3's _open_socket so
    dnspython and impacket keep using the stdlib socket.
    """
    global _SOCKS_INSTALLED, _SOCKS_STATE
    global _orig_open_socket, _orig_address_info, _orig_dns_socket_factory

    proxy_host, proxy_port, proxy_user, proxy_pass = parse_socks5_url(proxy_url)
    try:
        import socks
    except ImportError:
        raise CollectionException('PySocks is required for --socks. Install it with: pip install PySocks')

    import ldap3.strategy.base as base_mod
    from ldap3.core.server import Server
    import dns.query as dns_query

    _SOCKS_STATE = (proxy_host, proxy_port, proxy_user, proxy_pass, socks)
    if _SOCKS_INSTALLED:
        logging.debug('LDAP traffic will be routed through SOCKS proxy %s:%d', proxy_host, proxy_port)
        return

    stdlib_socket_cls = socket.socket
    _orig_open_socket = base_mod.BaseStrategy._open_socket
    _orig_address_info = Server.address_info.fget
    _orig_dns_socket_factory = getattr(dns_query, 'socket_factory', None)

    def _socks_socket(*args, **kwargs):
        sock = socks.socksocket(*args, **kwargs)
        sock.set_proxy(socks.SOCKS5, proxy_host, proxy_port, rdns=True,
                       username=proxy_user, password=proxy_pass)
        return sock

    def _open_socket(self, *args, **kwargs):
        saved = base_mod.socket.socket
        base_mod.socket.socket = _socks_socket
        try:
            return _orig_open_socket(self, *args, **kwargs)
        finally:
            base_mod.socket.socket = saved

    def _address_info(self):
        info = _orig_address_info(self)
        if info:
            return info
        host = self.host
        port = self.port
        synthetic = [[socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                      '', (host, port), None, None]]
        self._address_info = synthetic
        self._address_info_resolved_time = datetime.now()
        logging.debug('Using SOCKS remote DNS for LDAP host %s:%s', host, port)
        return self._address_info

    def _local_dns_socket(af, kind, proto=0):
        return stdlib_socket_cls(af, kind, proto)

    base_mod.BaseStrategy._open_socket = _open_socket
    Server.address_info = property(_address_info)
    dns_query.socket_factory = _local_dns_socket
    _SOCKS_INSTALLED = True
    logging.debug('LDAP traffic will be routed through SOCKS proxy %s:%d', proxy_host, proxy_port)


def disable_ldap_socks():
    """Restore ldap3's original connect path and DNS socket factory."""
    global _SOCKS_INSTALLED, _SOCKS_STATE
    global _orig_open_socket, _orig_address_info, _orig_dns_socket_factory
    if not _SOCKS_INSTALLED:
        _SOCKS_STATE = None
        return
    import ldap3.strategy.base as base_mod
    from ldap3.core.server import Server
    import dns.query as dns_query

    if _orig_open_socket is not None:
        base_mod.BaseStrategy._open_socket = _orig_open_socket
    if _orig_address_info is not None:
        Server.address_info = property(_orig_address_info)
    if _orig_dns_socket_factory is not None:
        dns_query.socket_factory = _orig_dns_socket_factory
    _SOCKS_INSTALLED = False
    _SOCKS_STATE = None
    _orig_open_socket = None
    _orig_address_info = None
    _orig_dns_socket_factory = None
