# Veeam Agent v9 VBK format: what's different

Notes on the specific ways v9-era Veeam Agent for Windows backups (changed-block-tracking /
CBT mode) differ from the newer VBKs documented in `vbk-format-internals.md`. These were
worked out empirically against real CBT backups of Windows domain controllers.

## What "v9" means here

Veeam Agent for Windows version 2.x / 3.x, shipping with Backup & Replication 9.x–10.x.
The `.vbk` container format is the same outer shell (superblock at 0x1000, block
descriptors, LZ4 payload — see the internals doc), but the **contents** of the disk image
stored inside differ in several critical ways because CBT mode only records changed blocks.

## Key difference 1: the VBR block is sparse

In a full backup the Volume Boot Record (LBA 0 of the NTFS volume, first 512 bytes) is
always present. In a CBT backup Veeam skips "pre-cluster volume metadata" — everything
before the first data cluster — so the VBR block is not stored and reads back as zeros.

**Consequence:** the NTFS library (dissect, ntfstool, etc.) can't open the volume because
it can't find the BPB. You get a silent fail or an exception at `NTFS.__init__`.

**Fix:** when the VBR is zero/missing, probe for `$MFT` directly at known Windows
cluster positions:
- LCN 786432 × cluster_size (Win10/11 NVMe placement for large disks — 3 GB in)
- LCN 262144, 393216 (alternate large-disk positions)
- LCN 4, 2, 6 (classic small-disk positions)

Try cluster sizes 4096, 8192, 2048. Validate by checking the candidate location starts
with `FILE` and has a sane update-sequence count (2 or 3 for a 1 KB record). Ignore the
VBR entirely once $MFT is located; everything after that (cluster size, bytes-per-sector)
comes from the MFT record header.

## Key difference 2: INDX blocks are sparse

Directory index allocation blocks (`$I30:$INDEX_ALLOCATION`) are also not always stored in
CBT backups. This means standard directory traversal ("follow the path
`\Windows\NTDS\ntds.dit`") hits a sparse block mid-walk and produces garbage or errors.
dissect raises a `BrokenIndexError`; other NTFS implementations just return wrong results.

**Consequence:** path-based file lookup is unreliable.

**Fix:** bypass directory trees entirely and scan $MFT directly.

1. Read $MFT record 0 to get the complete MFT run list (parse `$DATA` attribute → NTFS
   run list). $MFT itself is almost never sparse.
2. Iterate every record in every MFT extent, applying update-sequence fix-ups.
3. Match by filename from the `$FILE_NAME` attribute (prefer Win32 namespace over
   POSIX/8.3). No directory traversal needed.
4. For each match, read `$DATA` runs and reassemble the file.
5. Validate before accepting: `regf` magic for registry hives; non-zero first 64 bytes for
   ntds.dit. Sparse/zero content means the CBT backup didn't store those blocks — return
   empty and report cleanly rather than writing garbage.

## Key difference 3: GPT partitioning (not MBR)

v9 DC backups are typically GPT-partitioned (Windows Server 2012+ default). Older full
backup parsers assume MBR and look for a partition table at LBA 0 offset 446.

**Fix:** detect GPT by reading LBA 1 (byte offset 512) and checking for the `EFI PART`
signature. If present, parse the GPT partition entry array:
- GPT header at byte 512, 92 bytes
- `pe_lba` (u64 at +72) → first partition entry LBA
- `n_ent` (u32 at +80), `ent_sz` (u32 at +84)
- Each entry: type GUID (16 bytes), partition start LBA (u64 at +32)
- Filter for type GUID `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7` (basic data / NTFS)

Fall back to a raw VBR scan (try offsets 0, 512, 1048576 …) if neither MBR nor GPT works.

## Key difference 4: CBT backups are usually incrementals

A CBT backup stores only changed blocks — typically 2–10% of total disk blocks. If you
try to read a file whose blocks weren't in the changed set, you get zeros.

**Detection:** after building the block descriptor list, compute
`stored_blocks / total_blocks`. If it's under ~5%, the VBK is almost certainly an
incremental and the target files (ntds.dit, SAM, SYSTEM, SECURITY) will be absent.
Bail early with a clear message rather than spending 30+ seconds finding zeros.

The only reliable source for ntds.dit in an incremental CBT backup is the corresponding
full backup (or a synthetic full if one was synthesised).

## Key difference 5: _RobustNTFS wrapper needed

Even when the VBR is readable and the NTFS library opens cleanly, system files like
`$Secure` and `$UsnJrnl` use allocation-index blocks that may also be sparse. dissect
raises `BrokenIndexError` during `NTFS.__init__()` while processing those.

**Fix:** subclass `NTFS`, catch `BrokenIndexError` in `__init__`, and continue. The MFT
is fully loaded before those files are hit, so `get_entry()` / path lookups still work
for the files we care about.

```python
class _RobustNTFS(NTFS):
    def __init__(self, *a, **kw):
        try:
            super().__init__(*a, **kw)
        except _BrokenIndexError:
            pass
```

## Decision tree for extraction

```
open VBK
├── read VBR at partition start
│   ├── valid NTFS BPB → try _RobustNTFS path lookup
│   │   ├── succeeds → extract files
│   │   └── BrokenIndexError / not found → fall through to MFT scan
│   └── zero / sparse → skip to MFT scan
└── MFT scan (_mft_scan_v9)
    ├── VBR valid → mft_start = partition_offset + mft_lcn × cluster_size
    └── VBR sparse → probe LCN 786432/262144/393216/4/2/6 at cs 4096/8192/2048
        ├── found FILE record → use that mft_start
        └── not found → give up (probably incremental with no useful blocks)
```

## Runtime notes

- The MFT scan path is slower than path lookup (iterates all MFT records) but fast enough
  in practice: a 10 GB full DC backup scans ~65 k records in a few seconds once blocks are
  located.
- Block location (finding ntds.dit in the piecewise-linear block order) still dominates
  runtime — see the internals doc. The v9 path doesn't change that.
- Caching (`*.mft_blocks`, `*.anchors.ntds`, etc.) works the same way for v9 backups;
  re-runs skip the slow scan entirely.
