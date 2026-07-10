# vbkvomit

Pull domain hashes straight out of a Veeam `.vbk` backup. No Veeam, no wine, no NBD, no
ntfs-3g. Point it at a backup, get `secretsdump` output.

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

### `--fast` (experimental, ~5–15x faster)

```bash
python3 vbkvomit.py --local-path /mnt/backups/dc.vbk --fast   # needs: pip install dissect
```

Instead of the hand-rolled scan+reassembly, `--fast` uses Fox-IT's [`dissect`](https://github.com/fox-it/dissect)
library to resolve the VBK's content-addressed (deduplicated) blocks by their digest, mount
the embedded NTFS volume, and read the files directly — no block search. Cold run drops from
~40 s to ~8 s on our sample (full DC dump, identical output). It's opt-in while the default
reassembler stays the proven path; if `dissect` isn't installed it prints install guidance
and you just drop `--fast`.

## How it works

See [research.md](research.md) — short version: Veeam stores the disk as ~1 MB blocks that
*aren't* in volume order, so we snap to the nearest known anchor and verify every fragment
by its actual content (ESE page checksums for ntds, `regf`/`hbin` for hives) instead of
guessing. And instead of scanning the whole file for blocks, we read Veeam's own block
directory (~5 MB) to know where everything is.

## Needs

- `impacket` (secretsdump)
- `cifs-utils` (for `-t` SMB mode)
- `lz4` (fast block decode — ~5x; falls back to pure python without it)
- `numpy` (fast ESE checksums; falls back without it)
- `dissect` (only for `--fast`; `pip install dissect`)
