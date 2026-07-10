# How vbkvomit works (and what we figured out about VBK files)

Notes on reverse-engineering the Veeam `.vbk` format enough to yank NTDS/SAM out of a
backup without Veeam, wine, NBD, ntfs-3g, or a ramdisk. Just python reading bytes.

## The idea

A Veeam full backup of a DC is basically the whole system disk in a box. Inside that box
is an NTFS volume, and inside *that* is `ntds.dit`, the `SAM`/`SECURITY`/`SYSTEM` hives —
everything `secretsdump` needs. So if you can read the VBK, walk the NTFS inside it, and
pull those files back out, you get domain hashes straight from a backup file. No touching
the live DC.

The whole tool is: **VBK → find the NTFS volume → walk its MFT → reassemble the files we
want → hand them to secretsdump.**

## The part that bit us: blocks aren't in order

Veeam stores the disk as a pile of ~1 MB blocks (they start with `0f 00 00 f8`, then a
12-byte header, then an LZ4-ish compressed payload). To read the NTFS inside, you need to
know which block holds which 1 MB chunk of the volume (the LBA).

The old code *guessed* this by interpolating between a few known points. That's wrong,
and here's why: **Veeam doesn't store blocks in volume order.** It stores them in
*piecewise-linear* runs — a stretch of blocks that are in order, then a jump, then another
stretch in order, etc. (dedup + however it streams the backup). Interpolating across one
of those jumps lands you on a *completely unrelated block* from somewhere else on disk.

That's exactly what was breaking things:
- `SAM` was fine for the first 4 KB then turned to garbage — its later fragments lived in
  a different run.
- `ntds.dit` looked valid (right header) but every row read threw `getNextRow()` errors —
  the back half of the DB was foreign blocks.

## The fix: stop guessing, verify

Two changes:

1. **Snap to the nearest known anchor, don't interpolate.** Inside one run,
   `block_index = lba + constant`. So we grab the closest anchor and apply *its* offset,
   never a slope drawn across two anchors (which can straddle a jump).

2. **Locate each file fragment by checking the bytes actually belong to it.** A file's
   fragments can live in different runs, so for each NTFS run we spiral outward from the
   guess until the content checks out, and only then accept the block. If nothing nearby
   matches, we sweep the whole file rather than silently accept junk.

The content checks are the nice trick:
- **ntds.dit (ESE database):** every 8 KB page has an XOR checksum in its first bytes.
  For a page at file offset `N*8192`, `checksum_lo XOR (xor of the page's dwords) == N-1`.
  So we can tell if a page is sitting where it belongs. (Skip the DB header pages and
  empty pages, or you'll reject good blocks and waste time.)
- **hives (regf):** `regf` at offset 0, and every `hbin` records its own distance from the
  start of the hive — so a bin at the wrong spot is obvious.

After this, ntds.dit comes out clean: 0 bad pages, full domain dump, no errors.

## The speed part: Veeam already has a block map, so don't scan the whole file

First version found blocks by scanning all 10 GB for the `0f 00 00 f8` marker. That's ~100 s
of just reading over SMB before anything useful happens. Dumb, because **Veeam already
wrote down where every block is** — we just had to find its directory.

What we found digging through the file:
- The first ~1.6 MB is a header. In it are **descriptor banks** — 60-byte records, one per
  block, holding the block's **file offset** (at +5) and **compressed size** (at +13).
- Blocks are **packed back-to-back**: `offset[i] + size[i] == offset[i+1]`. Confirmed for
  16,059 of 16,060 blocks.
- The header only covers the first ~476 blocks. The rest of the descriptors sit in
  **metadata regions near the end** of the file (~9.8 GB in, on our 10 GB sample).
- Those regions are pointed to by a **superblock** at offset `0x1000` (backup copy at
  `0x81000`): a little pointer table starting at `0xa0`, entries of
  `[pointer u64][size u32][crc u32]`. The superblock also stashes the total block count at
  `+0x30` (we read `0x3EBD` = 16061, which matched).

So the fast path is: read the superblock → follow the pointers → read the descriptor banks →
now you have every block's location. **~5 MB of reads instead of 10 GB.** On our sample the
block list dropped from ~100 s of scanning to **1.9 s**. Same list, 50x less I/O.

If the format ever doesn't parse cleanly (weird version, encrypted, whatever), it falls
back to the old full scan — slower, but it still works.

## The other big speedup: use the C lz4

Decompressing blocks was done with a hand-rolled pure-python LZ4 decoder — ~120 ms a
block. The system `lz4.block` (the C one) does the same block in ~3 ms — **~40x** — and
gives byte-identical output. Catch: the C decoder needs the *exact* compressed length, and
Veeam pads each block's slot, so you can't just hand it the slot. Fix: walk the LZ4 tokens
tracking only output length (no copying) to find where the real compressed data ends, then
let the C decoder rip. Net ~5x on every decompress, which is most of the runtime — a fresh
first run dropped from ~129 s to ~47 s. Falls back to pure-python if `lz4` isn't installed.

## The rabbit hole we didn't finish: skipping the block search

The slow part of a cold run is finding ntds/hive blocks — the backup scrambles block order
(piecewise runs), so we search ~a couple thousand blocks to locate the one we want. We
tried to skip that by decoding Veeam's internal map, and got close but not there:

- Every block descriptor carries a 16-byte content hash. Veeam is doing **dedup /
  content-addressed storage** — blocks are keyed by hash, not position.
- There's a hash **index** in the metadata: 32-byte records `[u32][0x40000000][0xffffffff]
  [16-byte hash]`, **sorted by hash** (it's a B-tree for hash→block lookup).
- To go LBA→block you'd need the other half — an LBA→hash "recipe" — and we couldn't find
  where that lives. Without it the hash B-tree alone doesn't get you there.

So the "just read Veeam's LBA map and skip the search" idea is real in principle but needs
more reversing than it's worth right now. The C-lz4 win got the same runtime down anyway.

## Things that DIDN'T work (so we don't retry them)

- **Prefetching the search window sequentially.** Sounded great — the search reads a
  contiguous region scattered instead of sequential. But the search is **CPU-bound on
  decompression**, not I/O-bound, so warming the cache just added a wasted 26 s read. The
  fix was faster decompression (C lz4), not faster reads.

## The dumb-but-real gotcha: two impackets

On the test box `/usr/bin/impacket-secretsdump` ran the apt copy of the script but python
imported a *different*, older impacket from `~/.local` → `ImportError: KeyListSecrets`,
crash right at "Running secretsdump". Fixed by actually testing each candidate for a clean
import and picking one that works instead of the first one on PATH.

## What still costs time

- **The block search.** Locating ntds/hive blocks means decompressing ~a couple thousand
  candidate blocks to check their contents. Even with C lz4 that's the bulk of a cold first
  run (~35 s of the ~47 s). Killing it needs the LBA→hash recipe above. Re-runs are cached
  (~15 s), so this only bites the first pass on a given backup.
- **One NTFS volume.** We parse the first NTFS volume in the backup. If a DC keeps
  `NTDS\` on a separate drive, ntds.dit isn't on the volume we're reading and we won't find
  it. SAM/SECURITY still come out fine.
- **Size.** Correctness doesn't care how big the VBK is. Time does — the metadata read is
  tiny either way, but the MFT walk and fragment lookups scale with the volume and with how
  big ntds.dit is.

## Layout cheat-sheet

```
0x0000        header / property blob ("md5" key, etc.)
0x1000        superblock  -> pointer table @0xa0: [ptr u64][size u32][crc u32]
0x81000       superblock backup copy
~0x109000     descriptor banks for the first ~476 blocks
0x189000      first data block (0f 00 00 f8 | crc | decompressed_size | LZ4 payload)
...           data blocks, packed contiguously, piecewise-linear vs. volume LBA
~end          metadata regions: descriptor banks for the rest of the blocks

descriptor (60 bytes): +5 file_offset (u64), +13 compressed_size (u32)
ESE page check: checksum_lo XOR xor(dwords from +8) == (file_offset/8192) - 1
```
