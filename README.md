# vbkvomit

Pull domain hashes straight out of a Veeam `.vbk` backup.

It reads the VBK directly, finds the NTFS volume inside, walks the MFT, reassembles
`ntds.dit` + `SAM`/`SECURITY`/`SYSTEM`, and runs impacket `secretsdump`.

## Use it

```bash
# mounts the remote share itself (needs sudo for mount.cifs), dumps, unmounts
sudo python3 vbkvomit.py -t 192.168.15.40 -u veeam-admin -p 'B@ckupP@ssw0rd' -d ecorp.local

# already-mounted / local file
python3 vbkvomit.py --local-path /mnt/backups/dc.vbk
```

NTDS is pulled automatically when the backup is a DC. Non-DC backups just give you SAM.
Use `--no-ntds` to skip it.

Loot + scan caches land in `vbkvomit_loot/` and `vbkvomit_cache/` next to the script.
Re-running against the same backup is instant (it's all cached).

## Extraction modes (`-m`)

```bash
python3 vbkvomit.py --local-path /mnt/backups/dc.vbk                                    # fast (default)
python3 vbkvomit.py --local-path /mnt/backups/dc.vbk -m mft                             # MFT scan fallback
python3 vbkvomit.py --local-path /mnt/backups/dc.vbk -m full-extract --extract-dir /tmp # dump full VHD
```

After `full-extract`, vbkvomit prints the exact `vhdvomit.py --local-path` command to run
against the output VHD.

| Mode | What it does | Needs |
|------|-------------|-------|
| `fast` (default) | Uses `dissect` to resolve dedup blocks by digest and read target files directly. ~5–15x faster than `mft`. | `pip install dissect` |
| `mft` | Hand-rolled scan: walks the raw VBK blocks, finds NTFS MFT, reassembles hives. No extra deps, proven path. | — |
| `full-extract` ⚠️ | **EXPERIMENTAL.** Dumps every disk in the VBK as a VHD/VHDX file. Detects format from stream magic (`vhdxfile` → VHDX passthrough, otherwise Fixed VHD with spec-compliant footer). Uses a 4-worker parallel fetch pipeline. | `pip install dissect` |

### `full-extract` notes

- **Write to local disk.** If the VBK is on a NAS share and `--extract-dir` also points there,
  reads and writes fight over the same network link (~125 MB/s on 1Gbps). Use
  `--extract-dir /tmp/` or a local drive for the write path — you'll typically see 2–3×
  the throughput.
- Output format is auto-detected per disk: VHDX streams pass through as-is; raw sector
  streams get a Fixed VHD footer appended (matches Veeam `extract.exe` output).
- Marked experimental because VBK layout varies across Veeam versions and backup types
  (agent vs Hyper-V VM vs VMware). The fast/mft credential extraction paths are the
  validated ones.

## How it works

See [research.md](research.md) — short version: Veeam stores the disk as ~1 MB blocks that
*aren't* in volume order, so we snap to the nearest known anchor and verify every fragment
by its actual content (ESE page checksums for ntds, `regf`/`hbin` for hives) instead of
guessing. And instead of scanning the whole file for blocks, we read Veeam's own block
directory (~5 MB) to know where everything is.

## Encryption detection

vbkvomit checks whether a VBK is encrypted before attempting extraction. Encrypted VBKs
exit immediately with a clear message rather than producing garbage output or cryptic errors.

**Detection order:**

1. `.vbm` sidecar file — Veeam writes a plaintext XML sidecar to the same directory as the
   VBK. It contains an `EncryptionState` attribute:
   - `0` → plaintext
   - `1` → encryption key configured on the job but not applied to this backup run (readable)
   - `2` → AES-256 encrypted (extraction blocked)

2. Dissect block-level check — if no `.vbm` is present, reads `keyset_id` from FIB block
   descriptors in the VBK. Non-null keyset = encrypted.

3. Dissect parse failure — encrypted VBKs have encrypted block-store metadata. If dissect
   crashes traversing the VBK structure and no `.vbm` was found, the VBK is treated as
   encrypted.

Encrypted VBKs use AES-256. The key is not recoverable without the backup password — there
is no offline bypass.

## Needs

- `impacket` (secretsdump)
- `cifs-utils` (for `-t` SMB mode)
- `lz4` (fast block decode — ~5x; falls back to pure python without it)
- `numpy` (fast ESE checksums; falls back without it)
- `dissect` (for `fast` and `full-extract` modes; `pip install dissect`)
