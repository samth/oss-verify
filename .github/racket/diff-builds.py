#!/usr/bin/env python3
"""Show where two builds of a fuzz target differ: python3 diff-builds.py <a> <b>.

Each differing run of bytes is mapped to its section and to the symbol that contains it, and the runs are counted
per symbol. A run inside one of the embedded blobs (fuzz_petite_boot ... fuzz_modules) is shown with its offset in
the blob and some bytes of context."""
import collections, string, sys
from elftools.elf.elffile import ELFFile

def load(path):
    data = open(path, "rb").read()
    elf = ELFFile(open(path, "rb"))
    secs = [(s["sh_offset"], s["sh_offset"] + s["sh_size"], s.name, s["sh_addr"])
            for s in elf.iter_sections() if s["sh_type"] != "SHT_NOBITS" and s["sh_size"]]
    syms = []
    for s in elf.iter_sections():
        if s["sh_type"] in ("SHT_SYMTAB",):
            for y in s.iter_symbols():
                if y.name and y["st_value"]:
                    syms.append((y["st_value"], y["st_size"], y.name))
    syms.sort()
    return data, secs, syms

def where(off, secs, syms):
    for lo, hi, name, addr in secs:
        if lo <= off < hi:
            va = addr + off - lo
            best = None
            for v, size, n in syms:
                if v > va:
                    break
                best = (v, size, n)
            if best and addr:
                return name, best[2], va - best[0]
            return name, None, off - lo
    return "(no section)", None, off

def show(b):
    return "".join(chr(c) if chr(c) in string.printable[:-5] else "." for c in b)

a, secs, syms = load(sys.argv[1])
b = open(sys.argv[2], "rb").read()
assert len(a) == len(b), (len(a), len(b))
runs = []
i, n = 0, len(a)
while i < n:
    if a[i] != b[i]:
        j = i
        while j < n and (a[j] != b[j] or (j + 8 < n and a[j:j + 8] != b[j:j + 8])):
            j += 1
        runs.append((i, j))
        i = j
    else:
        i += 1
print(f"{len(runs)} differing runs, {sum(j - i for i, j in runs)} bytes")
count = collections.Counter()
for i, j in runs:
    sec, sym, rel = where(i, secs, syms)
    count[(sec, sym)] += 1
for (sec, sym), k in count.most_common(40):
    print(f"  {k:6d} runs in {sec} {sym or ''}")
shown = collections.Counter()
for i, j in runs:
    sec, sym, rel = where(i, secs, syms)
    if shown[sym] >= 6:
        continue
    shown[sym] += 1
    lo, hi = max(0, i - 24), min(n, j + 24)
    print(f"\n{sec} {sym} +{rel:#x} ({j - i} bytes)")
    print("  a:", a[lo:hi].hex(" "), "|", show(a[lo:hi]))
    print("  b:", b[lo:hi].hex(" "), "|", show(b[lo:hi]))
