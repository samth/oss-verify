#!/usr/bin/env python3
"""Count the differing bytes of two builds of a fuzz target by embedded file (petite, scheme, racket boot, modules)."""
import collections, subprocess, sys
from elftools.elf.elffile import ELFFile

def layout(path):
    elf = ELFFile(open(path, "rb"))
    secs = [(s["sh_addr"], s["sh_offset"], s["sh_size"], s.name) for s in elf.iter_sections() if s["sh_addr"]]
    syms = {}
    for line in subprocess.run(["nm", path], capture_output=True, text=True).stdout.splitlines():
        p = line.split()
        if len(p) == 3 and p[2].startswith("fuzz_"):
            syms[p[2]] = int(p[0], 16)
    def off(va):
        for addr, o, size, name in secs:
            if addr <= va < addr + size:
                return o + va - addr
    return {k: off(v) for k, v in syms.items()}

a, b = sys.argv[1], sys.argv[2]
L = layout(a)
print("layout:", {k: hex(v) for k, v in sorted(L.items(), key=lambda kv: kv[1] or 0)})
names = ["fuzz_petite_boot", "fuzz_scheme_boot", "fuzz_racket_boot", "fuzz_modules"]
ranges = [(n, L[n], L[n + "_end"]) for n in names if n in L]
da, db = open(a, "rb").read(), open(b, "rb").read()
count, first = collections.Counter(), {}
for i in range(len(da)):
    if da[i] != db[i]:
        n = next((n for n, lo, hi in ranges if lo <= i < hi), "other")
        count[n] += 1
        if n not in first:
            lo = next((lo for m, lo, hi in ranges if m == n), 0)
            first[n] = i - lo
for n, k in count.items():
    print(f"{n}: {k} differing bytes, first at +{first[n]:#x}")
