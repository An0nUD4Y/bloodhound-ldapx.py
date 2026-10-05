"""
Locate the ldapx binary BloodHound shells out to.

ldapx (https://github.com/Macmod/ldapx) is a separate Go program. This module
does not vendor its source. ``pip install`` and the first ``--ldapx-target``
run download the pinned official release for the current OS into
``bloodhound/bin``. ``--ldapx-binary`` and an ``ldapx`` already on ``PATH``
still win.
"""

import hashlib
import io
import os
import platform
import shutil
import tarfile
import urllib.request
import zipfile

LDAPX_VERSION = '1.3.5'
_RELEASE_URL = 'https://github.com/Macmod/ldapx/releases/download/v' + LDAPX_VERSION + '/'

# sha256 of the release archive, from the v1.3.5 GitHub release.
_ASSETS = {
    ('windows', 'amd64'): (
        'ldapx-v%s-windows-amd64.zip' % LDAPX_VERSION,
        '273eb88d4c6976ecfd50f3497482c042b6abc7703153d363c49ebf5a3fcf0c30',
    ),
    ('linux', 'amd64'): (
        'ldapx-v%s-linux-amd64.tar.gz' % LDAPX_VERSION,
        '82340bef730377dd1744ef9c116e81ce280407c163a79d6eea4beddefe29c226',
    ),
    ('linux', 'arm64'): (
        'ldapx-v%s-linux-arm64.tar.gz' % LDAPX_VERSION,
        '5d71099359727ee00819de1e8ba1a06a193effa705f525241676faa6b7967c64',
    ),
    ('darwin', 'amd64'): (
        'ldapx-v%s-darwin-amd64.tar.gz' % LDAPX_VERSION,
        'fef0549a75bd3cc0dee0abc443c8400ac0561153f996ee5c9f78b8c378b267a1',
    ),
    ('darwin', 'arm64'): (
        'ldapx-v%s-darwin-arm64.tar.gz' % LDAPX_VERSION,
        'b253fa1a65a191c2a3f7f427844c068b16789684fbc2e5790768c310adca5873',
    ),
}

_BINARY_NAMES = ('ldapx', 'ldapx.exe')


def platform_key():
    """
    ('windows'|'linux'|'darwin', 'amd64'|'arm64') for the running interpreter.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ('x86_64', 'amd64'):
        machine = 'amd64'
    elif machine in ('aarch64', 'arm64'):
        machine = 'arm64'
    if system not in ('windows', 'linux', 'darwin') or machine not in ('amd64', 'arm64'):
        raise RuntimeError('No ldapx release is published for %s/%s. Pass --ldapx-binary.' % (system, machine))
    if (system, machine) not in _ASSETS:
        raise RuntimeError('No ldapx release is published for %s/%s. Pass --ldapx-binary.' % (system, machine))
    return system, machine


def bundled_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bin')


def bundled_binary_path():
    name = 'ldapx.exe' if os.name == 'nt' else 'ldapx'
    return os.path.join(bundled_dir(), name)


def _version_path(directory):
    return os.path.join(directory, 'VERSION')


def _is_current(directory, binary_path):
    if not os.path.isfile(binary_path):
        return False
    version_file = _version_path(directory)
    try:
        with open(version_file, 'r', encoding='utf-8') as handle:
            return handle.read().strip() == LDAPX_VERSION
    except OSError:
        return False


def _download(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'bloodhound-ce'})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def _extract_binary(asset_name, payload, dest):
    wanted = set(_BINARY_NAMES)
    source = io.BytesIO(payload)
    if asset_name.endswith('.zip'):
        with zipfile.ZipFile(source) as archive:
            names = [name for name in archive.namelist()
                     if os.path.basename(name).lower() in wanted and not name.endswith('/')]
            if not names:
                raise RuntimeError('ldapx binary not found inside %s' % asset_name)
            with archive.open(names[0]) as src, open(dest, 'wb') as out:
                shutil.copyfileobj(src, out)
        return
    with tarfile.open(fileobj=source, mode='r:gz') as archive:
        members = [member for member in archive.getmembers()
                   if member.isfile() and os.path.basename(member.name).lower() in wanted]
        if not members:
            raise RuntimeError('ldapx binary not found inside %s' % asset_name)
        extracted = archive.extractfile(members[0])
        if extracted is None:
            raise RuntimeError('Could not read ldapx from %s' % asset_name)
        with extracted, open(dest, 'wb') as out:
            shutil.copyfileobj(extracted, out)


def install_bundled_ldapx(force=False):
    """
    Download the pinned ldapx release into ``bloodhound/bin`` and return its path.
    A binary already at that path for this version is left in place.
    """
    system, machine = platform_key()
    asset_name, digest = _ASSETS[(system, machine)]
    directory = bundled_dir()
    dest = bundled_binary_path()
    if not force and _is_current(directory, dest):
        return dest

    payload = _download(_RELEASE_URL + asset_name)
    actual = hashlib.sha256(payload).hexdigest()
    if actual != digest:
        raise RuntimeError('Checksum mismatch for %s (got %s)' % (asset_name, actual))

    os.makedirs(directory, exist_ok=True)
    temporary = dest + '.partial'
    try:
        _extract_binary(asset_name, payload, temporary)
        if os.name != 'nt':
            os.chmod(temporary, 0o755)
        os.replace(temporary, dest)
        with open(_version_path(directory), 'w', encoding='utf-8') as handle:
            handle.write(LDAPX_VERSION + '\n')
    finally:
        if os.path.exists(temporary):
            try:
                os.remove(temporary)
            except OSError:
                pass
    return dest


def resolve_ldapx_binary(requested='ldapx'):
    """
    Path to the ldapx executable.

    An explicit ``--ldapx-binary`` path is used as given. The default name
    ``ldapx`` means: the copy in ``bloodhound/bin``, then ``PATH``, then a
    download of the pinned release.
    """
    if requested not in (None, '', 'ldapx', 'ldapx.exe'):
        return requested
    bundled = bundled_binary_path()
    if _is_current(bundled_dir(), bundled):
        return bundled
    found = shutil.which('ldapx') or shutil.which('ldapx.exe')
    if found:
        return found
    return install_bundled_ldapx()
