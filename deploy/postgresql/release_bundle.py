"""Bounded release inspection and GitHub workflow provenance verification.

No archive member is executed. Checksums establish content consistency; the
separate GitHub CLI verification establishes the expected signing identity.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import subprocess
import tarfile
import time

from migration_protocol import pairs, require
from release_version import VERSION, valid as valid_version

REPOSITORY = 'crdffrance/NoiseFence'
WORKFLOW = REPOSITORY + '/.github/workflows/release.yml'
MACHINES = {'linux-amd64': 62, 'linux-arm64': 183}
MAX_ARCHIVE = 512 * 1024**2
MAX_EXPANDED = 2 * 1024**3
MAX_MEMBERS = 30000
MAX_METADATA = 1024**2
CHUNK = 65536


def identity(version, platform, commit):
    require(valid_version(version),
            'Invalid release version')
    require(platform in MACHINES and isinstance(commit, str) and re.fullmatch('[a-f0-9]{40}', commit),
            'Invalid release platform or commit')
    return f'noisefence-{version}-{platform}'


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


class BoundedTarStream:
    """Forward-only gzip reader; reject oversized PAX/metadata read requests."""
    def __init__(self, source):
        self.source = gzip.GzipFile(fileobj=source)
        self.position = 0
        self.replay = b''
        self.deadline = time.monotonic() + 120

    def tell(self):
        return self.position

    def read(self, size):
        require(0 <= size <= MAX_METADATA and self.position + size <= MAX_EXPANDED + 64*1024**2,
                'Tar metadata or expanded stream exceeds bounds')
        require(time.monotonic() < self.deadline, 'Archive inspection deadline exceeded')
        raw = self.replay[:size]
        self.replay = self.replay[len(raw):]
        if len(raw) < size: raw += self.source.read(size-len(raw))
        self.position += len(raw)
        return raw

    def seek(self, offset, whence=0):
        require(whence == 0 and offset >= self.position, 'Unexpected archive seek')
        while self.position < offset:
            require(self.read(min(CHUNK, offset-self.position)), 'Truncated archive padding')
        return self.position



class SafeTarInfo(tarfile.TarInfo):
    def _proc_member(self, tar):
        # Intercept before Python expands GNU names or sparse maps. Newer
        # Python security releases bypass the public frombuf method internally.
        require(self.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE,
                              tarfile.XHDTYPE, tarfile.XGLTYPE),
                'Unsupported tar member type')
        return super()._proc_member(tar)

    def _proc_pax(self, tar):
        # Validate a deliberately small PAX subset before Python's generic
        # parser can interpret sparse maps or arbitrarily large extensions.
        require(0 < self.size <= 16384, 'PAX header exceeds bounds')
        reader = tar.fileobj
        raw = reader.read(self._block(self.size))
        records = raw[:self.size]; offset = 0; keys = set()
        while offset < len(records):
            end = records.find(b' ', offset, offset+12)
            require(end > offset and records[offset:end].isdigit(), 'Invalid PAX record length')
            length = int(records[offset:end])
            require(end-offset+3 <= length <= 1024 and offset+length <= len(records), 'Invalid PAX record bounds')
            record = records[end+1:offset+length]
            require(record.endswith(b'\n') and b'=' in record, 'Invalid PAX record')
            key, value = record[:-1].split(b'=', 1)
            require(key in (b'path', b'mtime', b'atime', b'ctime') and key not in keys
                    and len(value) <= 512, 'Unsupported PAX field')
            if key != b'path':
                require(re.fullmatch(rb'-?[0-9]{1,16}(?:\.[0-9]{1,9})?', value), 'Invalid PAX timestamp')
            keys.add(key); offset += length
        require(not reader.replay, 'Unexpected buffered PAX input')
        reader.replay = raw; reader.position -= len(raw)
        return super()._proc_pax(tar)


def member_path(member, top):
    name = member.name
    require(isinstance(name, str) and 0 < len(name.encode()) <= 512
            and not any(ord(c) < 32 or ord(c) == 127 for c in name) and '\\' not in name,
            'Unsafe archive name')
    path = PurePosixPath(name)
    require(str(path) == name and not path.is_absolute() and '..' not in path.parts
            and path.parts[0] == top and (len(path.parts) > 1 or member.isdir()),
            'Archive path is not canonical or escapes its release')
    require((member.isfile() or member.isdir()) and not member.issparse()
            and not member.mode & 0o7000, 'Special archive members are forbidden')
    require(member.isdir() or 0 <= member.size <= MAX_EXPANDED, 'Oversized archive member')
    return str(PurePosixPath(*path.parts[1:])) if len(path.parts) > 1 else ''


def inspect_archive(archive, version, platform, commit, destination=None):
    """Inspect every member/hash; optionally write into a new private directory."""
    archive = Path(archive)
    top = identity(version, platform, commit)
    require(archive.is_file() and 0 < archive.stat().st_size <= MAX_ARCHIVE, 'Oversized or absent archive')
    if destination is not None:
        destination = Path(destination)
        destination.mkdir(mode=0o700)  # Must be new; never adopt an existing tree.
    seen = set(); files = {}; metadata = {}; total = 0; directories = {''}
    with archive.open('rb') as source:
        stream = BoundedTarStream(source)
        with tarfile.open(fileobj=stream, mode='r:', tarinfo=SafeTarInfo) as tar:
            for member in tar:
                relative = member_path(member, top)
                require(relative not in seen and len(seen) < MAX_MEMBERS, 'Duplicate or excessive archive members')
                seen.add(relative)
                ancestors = PurePosixPath(relative).parents if relative else []
                require(not any(str(p) in files for p in ancestors), 'Archive file used as a directory')
                if member.isdir():
                    require(member.size == 0, 'Directory contains an unexpected payload')
                    directories.add(relative)
                    if destination is not None and relative:
                        (destination/relative).mkdir(mode=0o755, parents=True, exist_ok=True)
                    continue
                require(relative not in directories, 'Archive directory replaced by a file')
                directories.update(str(parent) for parent in ancestors if str(parent) != '.')
                total += member.size
                require(total <= MAX_EXPANDED, 'Expanded release exceeds bounds')
                if relative in ('noisefence','build.json','SHA256SUMS','web/index.html'):
                    require(member.size > 0, 'Required release file is empty')
                if relative == 'noisefence':
                    require(member.mode & 0o111, 'Release binary is not executable')
                capture = relative in ('build.json', 'SHA256SUMS')
                require(not capture or member.size <= MAX_METADATA, 'Release metadata exceeds bounds')
                output = None
                if destination is not None:
                    path = destination/relative
                    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    output = path.open('xb')
                result = hashlib.sha256(); body = bytearray(); prefix = bytearray(); remaining = member.size
                try:
                    with tar.extractfile(member) as data:
                        while remaining:
                            block = data.read(min(CHUNK, remaining))
                            require(block, 'Truncated archive member')
                            result.update(block); remaining -= len(block)
                            if output is not None: output.write(block)
                            if capture: body.extend(block)
                            if relative == 'noisefence' and len(prefix) < 20: prefix.extend(block[:20-len(prefix)])
                    if output is not None:
                        os.fchmod(output.fileno(), 0o755 if member.mode & 0o111 else 0o644)
                        output.flush(); os.fsync(output.fileno())
                finally:
                    if output is not None: output.close()
                files[relative] = result.hexdigest()
                if capture: metadata[relative] = bytes(body)
                if relative == 'noisefence':
                    require(prefix[:6] == b'\x7fELF\x02\x01' and len(prefix) == 20
                            and int.from_bytes(prefix[18:20], 'little') == MACHINES[platform],
                            'Expected a little-endian 64-bit binary for this architecture')
            # Force gzip CRC/truncation validation and reject data after tar EOF.
            while block := stream.read(CHUNK):
                require(not any(block), 'Unexpected data after the tar end marker')
    require({'noisefence', 'build.json', 'SHA256SUMS', 'web/index.html'} <= set(files),
            'Incomplete release archive')
    build = json.loads(metadata['build.json'], object_pairs_hook=pairs)
    require(isinstance(build, dict) and build.get('project') == 'NoiseFence'
            and (build.get('version'), build.get('platform'), build.get('commit')) == (version, platform, commit)
            and build.get('storage_schema') == 7, 'Release metadata differs from the requested candidate')
    declared = {}
    for line in metadata['SHA256SUMS'].decode().splitlines():
        sha, separator, path = line.partition('  ')
        require(separator and re.fullmatch('[a-f0-9]{64}', sha) and path not in declared, 'Invalid release checksum manifest')
        declared[path] = sha
    require(declared == {path: sha for path, sha in files.items() if path != 'SHA256SUMS'},
            'Release checksums do not cover the exact archive contents')
    rehearsal_only = build.get('rehearsal_only', False)
    require(isinstance(rehearsal_only, bool), 'Invalid rehearsal-only marker')
    return {'version': version, 'platform': platform, 'commit': commit, 'files': files, 'bytes': total,
            'rehearsal_only': rehearsal_only}


def bounded_command(command, *, timeout=90, maximum=4*1024**2, env=None):
    """Bound both verifier output and elapsed time; never invoke a shell."""
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env) as process:
        try:
            output = {process.stdout: bytearray(), process.stderr: bytearray()}
            size = 0; deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                for pipe in output: selector.register(pipe, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, 'Provenance verification timed out')
                    for key, _ in selector.select(min(remaining, 1)):
                        block = os.read(key.fd, CHUNK)
                        if not block: selector.unregister(key.fileobj); continue
                        size += len(block)
                        require(size <= maximum, 'Provenance verifier output exceeds bounds')
                        output[key.fileobj].extend(block)
                code = process.wait(timeout=max(.01, deadline-time.monotonic()))
            require(code == 0, 'GitHub provenance verification failed; preserve the archive and inspect separately')
            return bytes(output[process.stdout])
        finally:
            if process.poll() is None: process.kill()
            process.wait()


def verify_provenance(archive, version, commit, *, executable='gh', env=None):
    require(valid_version(version)
            and isinstance(commit, str) and re.fullmatch('[a-f0-9]{40}', commit), 'Invalid provenance identity')
    raw = bounded_command([executable, 'attestation', 'verify', str(Path(archive).resolve()),
        '--repo', REPOSITORY, '--hostname', 'github.com',
        '--signer-digest', commit, '--source-digest', commit,
        '--source-ref', 'refs/tags/v'+version,
        '--cert-identity', 'https://github.com/'+WORKFLOW+'@refs/tags/v'+version,
        '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com',
        '--digest-alg', 'sha256', '--deny-self-hosted-runners', '--predicate-type', 'https://slsa.dev/provenance/v1',
        '--limit', '10', '--format', 'json'], env=env)
    verified = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(verified, list) and 0 < len(verified) <= 10
            and all(isinstance(item, dict) and isinstance(item.get('verificationResult'), dict)
                    for item in verified), 'Missing successful provenance verification results')
    return {'repository': REPOSITORY, 'workflow': WORKFLOW, 'ref': 'refs/tags/v'+version,
            'commit': commit, 'verification_sha256': hashlib.sha256(raw).hexdigest()}
