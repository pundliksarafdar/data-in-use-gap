#!/usr/bin/env python3
"""scan.py — show that a privileged host observer can read a *normal* process's
memory.

This walks a target process's readable regions via ``/proc/<pid>/maps`` and
reads them through ``/proc/<pid>/mem``, searching for a small set of *planted
demo canary* strings and printing where they were found.

It is part of a confidential-computing teaching demo. The contrast the demo
makes: against an Intel TDX trust domain, these same reads return ciphertext,
so the canary never appears in the clear.

By design this searches ONLY for the specific needle strings below (or ones you
pass explicitly). It is intentionally a fixed-string finder for planted demo
values — not a generic secret/credential/key scraper, and it should not be
extended into one.
"""
import argparse
import sys

# Planted demo canaries — fixed teaching values, not real secrets.
DEFAULT_NEEDLES = [
    b"DB_PASSWORD=Pr0d_c0nn_7f3a9c21",
    b"TDX_DEMO_CANARY_v1",
]

CHUNK = 4 * 1024 * 1024  # 4 MiB read window


def parse_maps(pid):
    """Return readable regions as (start, end, perms, path)."""
    regions = []
    with open(f"/proc/{pid}/maps", "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            addr, perms = parts[0], parts[1]
            if "r" not in perms:
                continue
            start_s, end_s = addr.split("-")
            path = parts[5] if len(parts) >= 6 else ""
            regions.append((int(start_s, 16), int(end_s, 16), perms, path))
    return regions


def scan_region(mem, start, end, needles):
    """Yield (absolute_address, needle) for every needle found in [start, end)."""
    hits = []
    max_needle = max(len(n) for n in needles)
    keep = max_needle - 1  # bytes retained to catch a needle split across reads

    try:
        mem.seek(start)
    except OSError:
        return hits  # region not actually readable (e.g. [vvar]); skip quietly

    carry = b""
    carry_base = start
    pos = start
    while pos < end:
        try:
            data = mem.read(min(CHUNK, end - pos))
        except OSError:
            break
        if not data:
            break

        buf = carry + data
        for needle in needles:
            idx = buf.find(needle)
            while idx != -1:
                hits.append((carry_base + idx, needle))
                idx = buf.find(needle, idx + 1)

        pos += len(data)
        if keep > 0 and len(buf) > keep:
            carry = buf[-keep:]
            carry_base = carry_base + len(buf) - keep
        else:
            carry = buf  # (carry_base unchanged)
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pid", type=int, help="target process id (on the host)")
    ap.add_argument("--needle", action="append", default=[],
                    help="extra planted demo string to search for (repeatable)")
    args = ap.parse_args()

    needles = list(DEFAULT_NEEDLES) + [n.encode() for n in args.needle]

    try:
        regions = parse_maps(args.pid)
    except FileNotFoundError:
        sys.exit(f"[scan] no such pid: {args.pid}")
    except PermissionError:
        sys.exit(f"[scan] permission denied reading /proc/{args.pid}/maps "
                 f"(run as root / with CAP_SYS_PTRACE)")

    print(f"[scan] pid={args.pid}  readable_regions={len(regions)}  "
          f"needles={len(needles)}")

    total = 0
    try:
        with open(f"/proc/{args.pid}/mem", "rb", buffering=0) as mem:
            for start, end, perms, path in regions:
                for addr, needle in scan_region(mem, start, end, needles):
                    total += 1
                    print(f"[hit] 0x{addr:012x}  {perms}  "
                          f"{needle.decode(errors='replace')!r}  "
                          f"region={path or '[anon]'}")
    except PermissionError:
        sys.exit(f"[scan] permission denied reading /proc/{args.pid}/mem "
                 f"(run as root / with CAP_SYS_PTRACE)")

    if total:
        print(f"[scan] FOUND {total} canary occurrence(s) in cleartext.")
        print("[scan] note: against a TDX trust domain these reads would "
              "return ciphertext, not the canary.")
    else:
        print("[scan] no canary found (process exited, or memory not readable).")


if __name__ == "__main__":
    main()
