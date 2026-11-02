#!/usr/bin/env python3
"""A minimal FUSE server for the VM test: one read-only file, `hello`.

It speaks the raw kernel protocol on an already mounted /dev/fuse
connection, the way a tenantd FUSE server gets one: fd 3 (or
$TENANTD_FUSE_FD), from `tenantd container attach-fuse`.

Usage: fuse-hello.py [TEXT]   (default "hello from fuse")
"""
import errno
import os
import struct
import sys

FD = int(os.environ.get("TENANTD_FUSE_FD", "3"))
CONTENT = ((sys.argv[1] if len(sys.argv) > 1 else "hello from fuse") + "\n").encode()

LOOKUP, FORGET, GETATTR, OPEN, READ, STATFS, RELEASE = 1, 2, 3, 14, 15, 17, 18
FLUSH, INIT, OPENDIR, READDIR, RELEASEDIR = 25, 26, 27, 28, 29
INTERRUPT, BATCH_FORGET = 36, 42
ROOT, HELLO = 1, 2


def attr(ino):
    if ino == ROOT:
        mode, size, nlink = 0o040755, 0, 2
    else:
        mode, size, nlink = 0o100444, len(CONTENT), 1
    # fuse_attr: ino size blocks atime mtime ctime, 3 nsecs, mode nlink uid
    # gid rdev blksize flags
    return struct.pack("<6Q3I7I", ino, size, 1, 0, 0, 0, 0, 0, 0,
                       mode, nlink, 0, 0, 0, 4096, 0)


def handle(op, node, body):
    """Reply payload, an errno, or None for no reply."""
    if op == INIT:
        _major, _minor, readahead, _flags = struct.unpack_from("<4I", body)
        # major minor max_readahead flags max_background congestion_threshold
        # max_write time_gran, then padding to the 64-byte fuse_init_out.
        out = struct.pack("<4I2H2I", 7, 31, readahead, 0, 16, 12, 128 << 10, 1)
        return out.ljust(64, b"\0")
    if op == GETATTR:
        if node not in (ROOT, HELLO):
            return errno.ENOENT
        return struct.pack("<QII", 0, 0, 0) + attr(node)
    if op == LOOKUP:
        name = body.split(b"\0", 1)[0]
        if node == ROOT and name == b"hello":
            return struct.pack("<4Q2I", HELLO, 0, 0, 0, 0, 0) + attr(HELLO)
        return errno.ENOENT
    if op in (OPEN, OPENDIR):
        return struct.pack("<QII", 0, 0, 0)
    if op == READ:
        _fh, off, size = struct.unpack_from("<QQI", body)
        return CONTENT[off:off + size]
    if op == READDIR:
        _fh, off = struct.unpack_from("<QQ", body)
        if off > 0:
            return b""
        # fuse_dirent: ino off namelen type, name padded to 8 bytes
        return struct.pack("<QQII", HELLO, 1, 5, 8) + b"hello\0\0\0"
    if op == STATFS:
        return struct.pack("<5Q4I6I", 0, 0, 0, 1, 0, 4096, 255, 4096, 0, *[0] * 6)
    if op in (RELEASE, RELEASEDIR, FLUSH):
        return b""
    if op in (FORGET, BATCH_FORGET, INTERRUPT):
        return None
    return errno.ENOSYS


def main():
    print(f"fuse-hello: serving fd {FD}", file=sys.stderr, flush=True)
    while True:
        try:
            req = os.read(FD, (1 << 20) + 4096)
        except InterruptedError:
            continue
        except OSError as e:
            if e.errno == errno.ENOENT:  # request interrupted before we read it
                continue
            print(f"fuse-hello: connection ended ({e})", file=sys.stderr)
            return 0
        _len, op, unique, node = struct.unpack_from("<IIQQ", req)
        reply = handle(op, node, req[40:])
        if reply is None:
            continue
        if isinstance(reply, int):
            out = struct.pack("<IiQ", 16, -reply, unique)
        else:
            out = struct.pack("<IiQ", 16 + len(reply), 0, unique) + reply
        try:
            os.write(FD, out)
        except OSError as e:
            if e.errno != errno.ENOENT:  # the request was interrupted
                raise


if __name__ == "__main__":
    sys.exit(main())
