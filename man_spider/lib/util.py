import os
import re
import magic
import string
import random
import logging
import ipaddress
from pathlib import Path
from dataclasses import dataclass

log = logging.getLogger('manspider.util')


@dataclass
class Target:
    """Represents a target host with optional port."""
    host: str
    port: int = 445

    def __str__(self):
        if self.port == 445:
            return self.host
        return f"{self.host}:{self.port}"

    def __hash__(self):
        return hash((self.host, self.port))

    def __eq__(self, other):
        if isinstance(other, Target):
            return self.host == other.host and self.port == other.port
        return False


def parse_host_port(s):
    """
    Parse a host:port string. Returns (host, port) tuple.
    Port defaults to 445 if not specified.
    Handles IPv6 addresses in brackets: [::1]:445
    """
    # IPv6 with port: [::1]:445
    ipv6_match = re.match(r'^\[([^\]]+)\]:(\d+)$', s)
    if ipv6_match:
        return ipv6_match.group(1), int(ipv6_match.group(2))

    # IPv6 without port: [::1] or ::1
    if s.startswith('[') and s.endswith(']'):
        return s[1:-1], 445
    if ':' in s and s.count(':') > 1:
        # Plain IPv6 address (multiple colons, no port)
        return s, 445

    # IPv4/hostname with port: 192.168.1.1:445 or host.com:445
    if ':' in s:
        host, port_str = s.rsplit(':', 1)
        try:
            return host, int(port_str)
        except ValueError:
            # Not a valid port, treat whole thing as host
            return s, 445

    # No port specified
    return s, 445


def str_to_list(s):

    l = set()
    # try to open as file
    try:
        with open(s) as f:
            lines = set([l.strip() for l in f.readlines()])
            for line in lines:
                if line:
                    l.add(line)
    except OSError:
        l.add(s)

    return list(l)


def make_targets(s):
    '''
    Accepts filename, CIDR, IP, hostname, file, or folder
    Supports host:port syntax (e.g., 192.168.1.1:4455)
    Returns list of targets as Target objects or Path() objects
    '''

    targets = set()

    p = Path(s)
    if s.lower() == 'loot':
        targets.add(Path.home() / '.manspider' / 'loot')

    elif p.is_dir():
        targets.add(p)

    else:
        for i in str_to_list(s):
            # Parse host:port if present
            host, port = parse_host_port(i)
            try:
                # Try to expand as CIDR network
                for ip in ipaddress.ip_network(host, strict=False):
                    targets.add(Target(str(ip), port))
            except ValueError:
                # Not a CIDR, treat as hostname
                targets.add(Target(host, port))

    return list(targets)


def human_to_int(h):
    '''
    converts human-readable number to integer
    e.g. 1K --> 1000
    '''

    if type(h) == int:
        return h

    units = {'': 1, 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}

    try:
        h = h.upper().strip()
        i = float(''.join(c for c in h if c in string.digits + '.'))
        unit = ''.join([c for c in h if c in units.keys()])
    except (ValueError, KeyError):
        raise ValueError(f'Invalid filesize "{h}"')

    return int(i * units[unit])


def bytes_to_human(_bytes):
    '''
    converts bytes to human-readable filesize
    e.g. 1024 --> 1KB
    '''

    sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB']
    units = {}
    count = 0
    for size in sizes:
        units[size] = pow(1024, count)
        count +=1

    for size in sizes:
        if abs(_bytes) < 1024.0:
            if size == sizes[0]:
                _bytes = str(int(_bytes))
            else:
                _bytes = '{:.2f}'.format(_bytes)
            return '{}{}'.format(_bytes, size)
        _bytes /= 1024

    raise ValueError


def better_decode(b):

    # detect encoding with libmagic
    m = magic.Magic(mime_encoding=True)
    encoding = m.from_buffer(b)

    try:
        return b.decode(encoding)
    except Exception:
        return str(b)[2:-1]


def random_string(length):

    return ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for i in range(length))


def list_files(path):

    path = Path(path)

    if path.is_file() and not path.is_symlink():
        yield path

    elif path.is_dir():
        for dir_name, dirnames, filenames in os.walk(path):
            for file in filenames:
                file = Path(dir_name) / file
                if file.is_file() and not file.is_symlink():
                    yield file


def rmdir(directory):
    '''
    Recursively remove directory
    '''
    directory = Path(directory)
    for item in directory.iterdir():
        if item.is_dir():
            rmdir(item)
        else:
            item.unlink()
    directory.rmdir()