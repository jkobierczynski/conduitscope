// SPDX-License-Identifier: Apache-2.0
// symbol_table.hpp - optional, additive human-readable name resolution for S7comm-Plus's own
// native symbolic item addressing (Symbol CRC + LID chain -- see S7CommPlusItemAddress,
// s7commplus.hpp) via an externally-supplied lookup table. Modeled directly on resolver.hpp's own
// Resolver class -- same "annotation, never a replacement" posture, same fail-fast-on-open/
// tolerant-on-malformed-line error handling, same render-time-only data flow -- because the two
// features solve the identical shaped problem: a raw wire value (a MAC, a port, here a CRC+LID
// chain) that only means something to a human once it's matched against an externally-supplied,
// static mapping this tool has no way to derive on its own.
//
// WHY THIS CAN ONLY EVER BE A LOOKUP TABLE, NEVER A COMPUTED RESOLUTION: S7comm-Plus's own Symbol
// CRC is a hash of a TIA Portal symbol name, but the full hash algorithm (the exact variant, init
// value, reflection, XOR-out, and the string-normalization convention TIA applies before hashing)
// is not documented anywhere publicly accessible, including in the reference Wireshark dissector
// this codebase already cross-checks every other S7comm-Plus field against -- that dissector
// parses the CRC out of the wire and displays it, but contains no forward CRC-computation code at
// all. So there is no way to compute "the CRC of symbol name X" and confirm it against what a real
// capture shows; the only buildable direction is the reverse one this file implements: given a
// capture's own CRC values (and the LID chain alongside each one, since one top-level symbol's CRC
// can be addressed at several different struct/array member depths), accept an externally-supplied
// CRC+LID-chain -> name table and look matches up. The table itself has to come from somewhere that
// DOES have the mapping already -- in practice, a human correlating a real capture's own observed
// (CRC, LID chain) pairs against the symbol names visible in the TIA Portal project that produced
// that traffic, and writing the result down here once. This tool cannot generate that table itself.
//
// Scope, deliberately narrow, per Jurgen's own framing of the ask as "S7 symbolic addressing":
// this resolves ONLY the symbolic case (S7CommPlusItemAddress::crc_or_rid != 0, i.e.
// is_object_id_style == false). An object-ID-style address (crc_or_rid == 0, addressed by
// RID/AID-style numeric IDs instead of a symbol name) has no symbol-name concept to resolve at
// all -- SymbolTable::resolve is simply never called for one; see s7commplus.cpp's own call site.
//
// File format: "simple hand-rolled text" (Jurgen's own explicit choice over a CSV-with-header
// alternative), one entry per line: "<crc-hex> <lid-chain> <name>" --
//   - <crc-hex>: S7CommPlusItemAddress::crc_or_rid in hex, matching how it already appears in this
//     decoder's own rendered `tag` field (e.g. "SYM-CRC=1a2b3c4d" -- see decode_item_address,
//     s7commplus.cpp); an optional leading "0x"/"0X" is also accepted. Case-insensitive hex
//     digits.
//   - <lid-chain>: S7CommPlusItemAddress::extra_lids verbatim, in order, written as dot-separated
//     decimal (e.g. "2.5" for a DB10.2.5-shaped address) -- deliberately NOT the area/DB-number
//     pair (see resolve()'s own comment below for why that isn't part of the lookup key), and
//     deliberately NOT S7CommPlusItemAddress::base_area either: despite reading as if it belongs
//     to the LID path, base_area is the wire's own SECOND, separate restatement of the memory
//     area/region (the reference Wireshark dissector's own comment calls it just that, "restating
//     the memory area" -- a magic value like 0xe98 for Merkers or 0x9f6 for DBs, not a struct/
//     array member selector), and that same dissector's own rendering never includes it in the
//     human-readable address string either -- see decode_item_address, s7commplus.cpp. A
//     lid_nesting_depth of 1 (e.g. a bare Merker/flag address, "SYM-CRC=..., LID=M" with no
//     trailing numbers at all) has an EMPTY extra_lids -- write "-" for <lid-chain> in that case,
//     not an empty field (which this file's own tolerant line-parser would otherwise just skip as
//     malformed -- "a line with fewer than 3 fields" looks identical to a truncated one
//     otherwise).
//   - <name>: the rest of the line, trimmed -- everything after the first two whitespace-delimited
//     tokens, so a name itself may contain internal whitespace (e.g. "Line 2 / Motor Speed").
// '#' starts a comment (whole-line or trailing), blank lines are skipped, and any individual line
// that doesn't parse into exactly this shape (bad hex, a non-numeric or empty LID-chain segment, a
// missing name) is silently skipped rather than treated as an error -- the same "a malformed
// config-file line degrades gracefully, only an unopenable file is fatal" posture
// parse_hosts_file/parse_services_file already establish (resolver.cpp). A later line for the same
// (crc, lid-chain) pair overwrites an earlier one, matching parse_services_file's own
// last-line-wins override convention (not parse_hosts_file's first-wins convention -- there is no
// "built-in table to protect from being silently overridden" concern here the way there is for
// Resolver's own services table, so last-wins is simply the least surprising rule for a file the
// operator is actively curating).
//
// Deliberately NOT given a dedicated file-size cap the way baseline.hpp's own
// kDefaultMaxBaselineFileBytes guards a baseline store: Resolver's own --hosts/--services files
// (the chosen precedent for this feature, see above) have no such cap either, and a symbol table
// is the same shape of small, operator-authored reference file -- adding a bespoke cap here would
// be new scope beyond what the explicitly-chosen precedent calls for, not a gap.
#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace conduitscope {

// Thrown only for a hard, environment-level failure setting up a SymbolTable -- currently just "a
// --s7plus-symbols path that passed CLI11's ->check(CLI::ExistingFile) at parse time could not
// actually be opened when the SymbolTable went to read it" (a TOCTOU race, permissions changing
// mid-run, or similar) -- exactly ResolverError's own scope and rationale (see resolver.hpp),
// mirrored here under its own name since the two are unrelated types. Deliberately NOT thrown for
// anything a malformed table-file LINE might contain -- see this file's own header comment.
class SymbolTableError : public std::runtime_error {
public:
    explicit SymbolTableError(const std::string& what) : std::runtime_error(what) {}
};

// Owns the (possibly empty) CRC+LID-chain -> name lookup table, built once from `decode`'s
// --s7plus-symbols flag (and, per Jurgen's own scoping choice, also threaded into the `inventory`
// subcommand's own top-touched-address rendering -- see asset_inventory.cpp). Cheap to query per
// item address: a single hash-map probe, no I/O after construction.
class SymbolTable {
public:
    // path: --s7plus-symbols value; empty means inactive (active() returns false, resolve() always
    // returns nullopt, matching Resolver's own "empty path = harmless no-op" convention for its own
    // optional inputs). Must already exist and be readable (CLI11's ->check(CLI::ExistingFile)
    // enforces existence before this constructor ever runs) -- SymbolTableError is thrown only if
    // it still can't be opened here anyway (see SymbolTableError's own comment above).
    explicit SymbolTable(const std::string& path);

    // crc: S7CommPlusItemAddress::crc_or_rid, symbolic addresses only -- never meaningfully called
    // with an object-ID-style address's crc_or_rid (always 0 there; see this file's own header
    // comment on scope). lid_chain: S7CommPlusItemAddress::extra_lids verbatim, in order -- never
    // base_area (a separate wire-level restatement of the memory area/region, not a struct/array
    // member selector -- see this file's own header comment for why) and never the recognized
    // area/DB-number pair either. Neither is part of the lookup key because neither is part of
    // what the Symbol CRC identifies: the CRC is a hash of the symbol's own name as TIA Portal
    // knows it, and two different symbols (potentially living in different DBs/areas) cannot
    // legitimately share one CRC in practice, so the CRC+LID-chain pair alone already uniquely
    // identifies one TIA symbolic address regardless of which area it lives in -- folding the area
    // into the key would only make every table entry longer to write by hand for no disambiguating
    // benefit. May be empty (lid_nesting_depth == 1, a bare Merker/flag-style address with no
    // struct/array nesting at all) -- written as "-" on disk, see this file's own header comment.
    // Returns nullopt when the table is inactive (no --s7plus-symbols given), or no entry matches
    // this exact (crc, lid_chain) pair -- a miss adds nothing, never an "(unknown)" placeholder,
    // the same convention Resolver's own three lookups already follow.
    std::optional<std::string> resolve(uint32_t crc, const std::vector<uint32_t>& lid_chain) const;

    // Whether this table has at least one loaded entry -- exposed so a caller can skip attempting
    // resolution entirely when the table is empty, without needing to know SymbolTable's internals;
    // resolve() already returns nullopt unconditionally in that case regardless, so using this is
    // purely an optional optimization, never required for correctness.
    bool active() const { return !entries_.empty(); }

private:
    // "<crc>:<lid>:<lid>:..." (decimal, ':'-joined -- an internal key encoding, unrelated to the
    // file's own '.'-joined on-disk spelling) -> resolved name. See parse_symbol_table_file
    // (symbol_table.cpp) for exactly how a line becomes one entry here, and resolve()'s own comment
    // above for exactly what the lid_chain argument must contain.
    std::unordered_map<std::string, std::string> entries_;
};

}  // namespace conduitscope
