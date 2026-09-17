#!/usr/bin/env python3
"""Generates include/conduitscope/oui_table.gen.hpp from nmap's nmap-mac-prefixes
file, itself an aggregation of the IEEE Registration Authority's three public MAC
address block registries (MA-L / classic 24-bit OUI, MA-M / 28-bit, MA-S / 36-bit).
See that header's own file comment for the full sourcing note this script writes
into its output -- keep the two in sync if this script changes.

To refresh the embedded table against the current IEEE registries, re-fetch the
source file and re-run this script:

    curl -sS -o /tmp/nmap-mac-prefixes.txt \\
        https://raw.githubusercontent.com/nmap/nmap/master/nmap-mac-prefixes
    python3 tools/generate_oui_table.py /tmp/nmap-mac-prefixes.txt \\
        include/conduitscope/oui_table.gen.hpp

(IEEE's own standards-oui.ieee.org isn't reachable from every network this project
is built on, which is why this goes through nmap's redistribution rather than
IEEE directly -- see this file's own header comment for why that's still a sound,
attributable source: it's public registry data, not nmap's creative content.) The
raw fetched file itself is deliberately NOT committed to this repo (it's ~1.3MB of
intermediate data superseded entirely by the generated header); only the command
above and the generated output are kept.
"""
import sys

def esc(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')

def load(path):
    by_bits = {24: [], 28: [], 36: []}
    seen = {24: set(), 28: set(), 36: set()}
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or line.startswith('#'):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            hexprefix, vendor = parts
            hexprefix = hexprefix.strip()
            vendor = vendor.strip()
            if not vendor:
                continue
            nbits = {6: 24, 7: 28, 9: 36}.get(len(hexprefix))
            if nbits is None:
                continue
            try:
                val = int(hexprefix, 16)
            except ValueError:
                continue
            if val in seen[nbits]:
                continue  # keep first occurrence only, matches source file order
            seen[nbits].add(val)
            by_bits[nbits].append((val, vendor))
    for nbits in by_bits:
        by_bits[nbits].sort(key=lambda t: t[0])
    return by_bits

def emit(by_bits, out_path, source_note):
    with open(out_path, 'w', encoding='utf-8') as out:
        out.write("// SPDX-License-Identifier: MIT\n")
        out.write("// oui_table.gen.hpp - GENERATED FILE, do not hand-edit -- see\n")
        out.write("// tools/generate_oui_table.py (which regenerates this from a fetched copy of nmap's\n")
        out.write("// nmap-mac-prefixes file) for how this table was produced and exactly how to refresh it.\n")
        out.write("//\n")
        out.write("// Source data: %s\n" % source_note)
        out.write("//\n")
        out.write("// nmap-mac-prefixes itself aggregates the three public IEEE Registration Authority MAC\n")
        out.write("// address block registries -- MA-L (the classic 24-bit OUI), MA-M (28-bit), and MA-S\n")
        out.write("// (36-bit) -- each block owner's registered organization name is public registry DATA,\n")
        out.write("// not creative content; this generator reads only the hex-prefix/name pairs (skipping\n")
        out.write("// nmap's own comments and its own handful of documented non-IEEE additions -- see the\n")
        out.write("// fetched file's own header) and re-emits them as this project's own lookup table, the\n")
        out.write("// same \"facts extracted, re-expressed in this codebase's own structures\" sourcing\n")
        out.write("// convention already used for e.g. stp.hpp/ffhse.hpp (see their own file comments).\n")
        out.write("//\n")
        out.write("// Three tables, one per block size, each sorted ascending by its N-bit prefix (stored\n")
        out.write("// right-justified in a uint64_t) for binary search. oui_vendor_lookup (resolver.cpp)\n")
        out.write("// tries MA-S (36-bit, most specific) first, then MA-M (28-bit), then MA-L (24-bit) --\n")
        out.write("// see its own comment for why that order is correct (MA-M/MA-S are sub-delegations\n")
        out.write("// within specific MA-L blocks IEEE reserves for exactly this purpose, so a MAC can\n")
        out.write("// legitimately match more than one table at once, and the most specific one is always\n")
        out.write("// the right answer).\n")
        out.write("#pragma once\n\n")
        out.write("#include <cstdint>\n\n")
        out.write("namespace conduitscope::detail {\n\n")
        out.write("struct OuiEntry {\n    uint64_t prefix;  // right-justified N-bit value\n    const char* vendor;\n};\n\n")
        for nbits in (24, 28, 36):
            entries = by_bits[nbits]
            out.write(f"// {len(entries)} entries, MA-{'L' if nbits==24 else ('M' if nbits==28 else 'S')} ({nbits}-bit), sorted ascending by prefix.\n")
            out.write(f"inline constexpr OuiEntry kOuiTable{nbits}[] = {{\n")
            for val, vendor in entries:
                out.write('    {0x%0*Xull, "%s"},\n' % ((nbits + 3) // 4, val, esc(vendor)))
            out.write("};\n\n")
        out.write("}  // namespace conduitscope::detail\n")

if __name__ == '__main__':
    src = sys.argv[1] if len(sys.argv) > 1 else 'nmap-mac-prefixes.txt'
    dst = sys.argv[2] if len(sys.argv) > 2 else 'oui_table.gen.hpp'
    by_bits = load(src)
    for nbits in (24, 28, 36):
        print(f"{nbits}-bit: {len(by_bits[nbits])} entries", file=sys.stderr)
    emit(by_bits, dst, "nmap project's nmap-mac-prefixes file (github.com/nmap/nmap), itself sourced from "
                        "the IEEE Registration Authority's public MA-L/MA-M/MA-S registries "
                        "(standards.ieee.org/products-programs/regauth) -- fetched 2026-09-17.")
