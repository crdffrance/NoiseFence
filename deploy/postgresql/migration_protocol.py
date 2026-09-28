"""Bounded private migration transport. No shell evaluation or content logging."""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import time
import uuid

SOURCE = 'noisefence-source-session-1'
COMMIT = 'noisefence-import-commit-1'
AGENT = 'noisefence-migration-agent-1'
MAX_FRAME = 5 * 1024 * 1024
MAX_FILE = 3 * 1024**3
MAX_TOTAL = 8 * 1024**3


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def identity(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def checked_selection(value):
    require(isinstance(value, dict) and set(value) == {'protocol', 'database', 'node', 'role', 'baseline', 'mfa_key_sha256'},
            'Invalid source selection fields')
    require(value['protocol'] == 'noisefence-management-selection-1' and value['role'] in ('coordinator', 'worker'),
            'Invalid source selection protocol')
    database, node, baseline = value['database'], value['node'], value['baseline']
    require(isinstance(database, dict) and set(database) == {'instance', 'source_digest'}
            and identity(database['instance']) and sha(database['source_digest']), 'Invalid selected database')
    require(isinstance(node, dict) and set(node) == {'node', 'epoch'} and identity(node['epoch'])
            and isinstance(node['node'], str) and re.fullmatch('[a-z0-9_-]{1,40}', node['node']), 'Invalid selected node')
    require(isinstance(baseline, dict) and set(baseline) == {'sequence', 'revision', 'digest'}
            and all(type(baseline[k]) is int and 0 <= baseline[k] <= 2**63-1 for k in ('sequence', 'revision'))
            and sha(baseline['digest']), 'Invalid selected baseline')
    require(sha(value['mfa_key_sha256']) if value['role'] == 'coordinator' else value['mfa_key_sha256'] is None,
            'Invalid selected MFA binding')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


class Channel:
    """Length-prefixed JSON plus explicitly sized file bodies, under one deadline."""
    def __init__(self, reader, writer, deadline):
        self.reader, self.writer, self.deadline = reader, writer, deadline
        os.set_blocking(reader, False)
        os.set_blocking(writer, False)

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Migration transport deadline exceeded')
        return remaining

    def read(self, size):
        require(type(size) is int and 0 <= size <= MAX_FRAME, 'Read exceeds frame bounds')
        data = bytearray()
        while len(data) < size:
            ready, _, _ = select.select([self.reader], [], [], self.remaining())
            if not ready:
                raise TimeoutError('Migration read deadline exceeded')
            try:
                block = os.read(self.reader, min(size - len(data), 65536))
            except (BlockingIOError, InterruptedError):
                continue
            if not block:
                raise EOFError('Migration peer disconnected')
            data.extend(block)
        return bytes(data)

    def write(self, data):
        view = memoryview(data)
        while view:
            _, ready, _ = select.select([], [self.writer], [], self.remaining())
            if not ready:
                raise TimeoutError('Migration write deadline exceeded')
            try:
                written = os.write(self.writer, view[:65536])
            except (BlockingIOError, InterruptedError):
                continue
            if not written:
                raise EOFError('Migration write interrupted')
            view = view[written:]

    def receive(self):
        size = struct.unpack('!I', self.read(4))[0]
        require(0 < size <= MAX_FRAME, 'Migration JSON frame exceeds bounds')
        try:
            value = json.loads(self.read(size), object_pairs_hook=pairs,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeError) as error:
            raise ValueError('Invalid migration JSON frame') from error
        require(isinstance(value, dict), 'Expected migration object')
        return value

    def send(self, value):
        raw = canonical(value)
        require(0 < len(raw) <= MAX_FRAME, 'Migration JSON response exceeds bounds')
        self.write(struct.pack('!I', len(raw)))
        self.write(raw)

    def send_file(self, path, expected):
        with private_read(path, MAX_FILE) as source:
            require(os.fstat(source.fileno()).st_size == expected['bytes'], 'Export file size changed')
            digest = hashlib.sha256()
            remaining = expected['bytes']
            while remaining:
                block = source.read(min(65536, remaining))
                require(bool(block), 'Export file was truncated')
                self.write(block)
                digest.update(block)
                remaining -= len(block)
            require(not source.read(1) and digest.hexdigest() == expected['sha256'], 'Export file digest changed')

    def receive_file(self, path, expected):
        require(type(expected.get('bytes')) is int and 0 <= expected['bytes'] <= MAX_FILE
                and sha(expected.get('sha256')), 'Invalid export file declaration')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as output:
                digest = hashlib.sha256()
                remaining = expected['bytes']
                while remaining:
                    block = self.read(min(65536, remaining))
                    output.write(block)
                    digest.update(block)
                    remaining -= len(block)
                require(digest.hexdigest() == expected['sha256'], 'Transferred file checksum mismatch')
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            Path(path).unlink(missing_ok=True)
            raise


def private_read(path, maximum):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'Expected physical absolute file path')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    info = os.fstat(fd)
    if not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum
            and info.st_mode & 0o022 == 0):
        os.close(fd)
        raise ValueError('Unsafe or oversized migration file')
    return os.fdopen(fd, 'rb')


def atomic(path, raw, *, uid=None, gid=None, mode=0o600):
    path = Path(path)
    temp = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as output:
            if uid is not None:
                os.fchown(output.fileno(), uid, gid)
            os.fchmod(output.fileno(), mode)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temp.unlink(missing_ok=True)


class SourceSession:
    def __init__(self, path, node, deadline):
        self.socket = socket.socket(socket.AF_UNIX)
        try:
            self.socket.settimeout(min(5, max(0.001, deadline - time.monotonic())))
            self.socket.connect(str(path))
            self.channel = Channel(self.socket.fileno(), self.socket.fileno(), deadline)
            self.ready = self.channel.receive()
            self.sequence = 0
            ready = self.ready
            require(ready.get('protocol') == SOURCE and ready.get('state') == 'frozen'
                    and identity(ready.get('session')), 'Invalid source session greeting')
            receipt = ready.get('receipt', {})
            journal = receipt.get('journal', {})
            node_identity = journal.get('identity', {})
            require(node_identity.get('node') == node and identity(node_identity.get('epoch'))
                    and type(journal.get('sequence')) is int and journal['sequence'] >= 0
                    and sha(receipt.get('sha256')) and type(receipt.get('bytes')) is int
                    and 0 < receipt['bytes'] <= MAX_FILE, 'Invalid source export receipt')
        except BaseException:
            self.socket.close()
            raise

    def command(self, command):
        self.sequence += 1
        require(self.sequence <= 64, 'Source session command limit exceeded')
        self.channel.send({'protocol': SOURCE, 'session': self.ready['session'],
                           'sequence': self.sequence, 'command': command})
        response = self.channel.receive()
        require(response.get('protocol') == SOURCE and response.get('session') == self.ready['session']
                and response.get('sequence') == self.sequence, 'Source reply identity mismatch')
        expected = {'check': 'held', 'select': 'selected', 'abort': 'aborted', 'release': 'released'}[command['action']]
        require(response.get('state') == expected, 'Unexpected source reply state')
        if command['action'] == 'select':
            require(response.get('selection') == command['selection'], 'Source selection receipt mismatch')
        return response

    def close(self):
        self.socket.close()
