#!/usr/bin/env python3
"""
verify_network_calls.py -- audit a source tree for network-capable API calls
and classify each match as INERT (comment/string literal -- can't execute)
or LIVE (in actual code), and, when live, whether it's an expected
receive-only capture call or something that deserves a human look.

Motivation
----------
For a passive network-monitoring tool (e.g. conduitscope), the security
property that matters most is "this tool never puts data on the wire." A
plain `grep` for network-sounding identifiers can't tell you whether a hit
is a real, reachable call or just a comment citing a URL, a decode-time
field named after a wire-protocol constant (e.g. "AF_INET" appearing in a
comment describing a decoded byte), or a string literal. This script does
that classification automatically, across an entire tree, so the audit is
repeatable instead of a one-off manual grep-and-eyeball pass.

How it works
------------
For each source file, the script walks it character by character with a
small per-language tokenizer, tracking whether each character sits inside:
  - a line comment            ("//" in C/C++, "#" in Python)
  - a block comment           ("/* ... */" in C/C++, possibly multi-line)
  - a string/char literal     ("...", '...', or Python's triple-quoted
                                '''...'''/\"\"\"...\"\"\", possibly multi-line)
  - or "live code" (none of the above)

It then searches every line for a curated list of network-capable API
names, grouped into five categories (see CATEGORIES below), and classifies
each match by the context character at the match's start position:

  INERT        -- match sits inside a comment or string literal. Can never
                   execute. Always safe, regardless of category.
  LIVE_SAFE    -- match sits in live code, but its category is
                   RECEIVE_SETUP: the libpcap/socket setup calls a passive
                   capture tool is EXPECTED to make (pcap_create,
                   pcap_next_ex, recv, ...). Shown for transparency, not a
                   finding that needs review.
  LIVE_REVIEW  -- match sits in live code AND its category is TRANSMIT,
                   NAME_RESOLUTION, or HTTP_CLIENT: something that could
                   plausibly put data on the wire or resolve a name over
                   the network. Always worth a human's attention, however
                   it turns out on inspection.
  ALLOWLISTED  -- would otherwise be LIVE_REVIEW, but the matched line (or
                   the line immediately above it) contains the marker
                   "network-audit: allow" -- a deliberate, reviewed
                   exception, kept visible in the report rather than
                   silently dropped.

Usage
-----
    python3 verify_network_calls.py [--root PATH] [--ext .cpp,.hpp,.h,.py]
                                     [--json] [--quiet] [--positives-only]
                                     [--show-live-safe] [--show-inert]

--positives-only prints exactly the LIVE_REVIEW findings as "path:line",
one per line, and nothing else -- the plain report (no --positives-only)
also includes this same file:line list as its own "POSITIVE HITS" block,
right after the detailed LIVE_REVIEW listing.

Exit code 0: no LIVE_REVIEW findings (an ALLOWLISTED finding does not fail
             the run -- that's the point of the marker).
Exit code 1: at least one LIVE_REVIEW finding -- inspect the report.

Limitations (stated plainly, not hidden): the tokenizer is line-oriented
and does not understand C++11 raw string literals (R"(...)"); a match
inside one would be misclassified as code rather than string content. It
also does not evaluate preprocessor conditionals (#if 0 / #ifdef never
compiled in this configuration still counts as "live code" here) -- a
transmit-capable call inside dead #if 0 code would still be reported as
LIVE_REVIEW, which is the conservative direction to be wrong in for a
security audit. Only files under --root with a recognized extension are
scanned; a network call reached only through a dynamically loaded plugin
or an external dependency's own source is out of scope.
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Pattern catalog
# ---------------------------------------------------------------------------
# Each category maps a short, human-readable label to a compiled regex. The
# regexes use (?<!\w)...(?!\w)-style boundaries (rather than bare \b) so a
# match requires the identifier to stand alone -- "attack_send(" never
# matches the "send(" pattern, but "pcap_sendpacket(" still matches its own,
# separately-listed pattern.

def _id(name: str) -> str:
    """A regex matching the bare identifier `name` immediately followed by
    an opening paren, not preceded/followed by another identifier character
    -- so it matches `name(` but not `my_name(` or `name_suffix(`."""
    return r"(?<![A-Za-z0-9_])" + re.escape(name) + r"\s*\("


TRANSMIT: Dict[str, str] = {
    "send()": _id("send"),
    "sendto()": _id("sendto"),
    "sendmsg()": _id("sendmsg"),
    "WSASend()": _id("WSASend"),
    "WSASendTo()": _id("WSASendTo"),
    "pcap_sendpacket()": _id("pcap_sendpacket"),
    "pcap_inject()": _id("pcap_inject"),
    "connect()": _id("connect"),
    "socket.socket() [py]": r"(?<![A-Za-z0-9_])socket\.socket\s*\(",
    "socket() [C, AF_-qualified]": r"(?<![A-Za-z0-9_])socket\s*\(\s*(?:AF_|socket\.AF_)",
    "requests.* [py]": r"(?<![A-Za-z0-9_])requests\.(get|post|put|delete|head|patch|request|Session)\s*\(",
    "urlopen() [py]": _id("urlopen"),
}

RECEIVE_SETUP: Dict[str, str] = {
    "pcap_create()": _id("pcap_create"),
    "pcap_open_live()": _id("pcap_open_live"),
    "pcap_open_dead()": _id("pcap_open_dead"),
    "pcap_activate()": _id("pcap_activate"),
    "pcap_next_ex()": _id("pcap_next_ex"),
    "pcap_next()": _id("pcap_next"),
    "pcap_loop()": _id("pcap_loop"),
    "pcap_dispatch()": _id("pcap_dispatch"),
    "pcap_findalldevs()": _id("pcap_findalldevs"),
    "pcap_setfilter()": _id("pcap_setfilter"),
    "pcap_compile()": _id("pcap_compile"),
    "pcap_set_promisc()": _id("pcap_set_promisc"),
    "pcap_setnonblock()": _id("pcap_setnonblock"),
    "recv()": _id("recv"),
    "recvfrom()": _id("recvfrom"),
    "bind()": _id("bind"),
    "listen()": _id("listen"),
    "accept()": _id("accept"),
}

NAME_RESOLUTION: Dict[str, str] = {
    "getaddrinfo()": _id("getaddrinfo"),
    "gethostbyname()": _id("gethostbyname"),
    "gethostbyaddr()": _id("gethostbyaddr"),
    "getnameinfo()": _id("getnameinfo"),
    "socket.getaddrinfo() [py]": r"(?<![A-Za-z0-9_])socket\.getaddrinfo\s*\(",
    "socket.gethostbyname() [py]": r"(?<![A-Za-z0-9_])socket\.gethostbyname\s*\(",
}

HTTP_CLIENT: Dict[str, str] = {
    "curl_easy_*()": r"(?<![A-Za-z0-9_])curl_easy_\w*\s*\(",
    "CURL type/macro": r"(?<![A-Za-z0-9_])CURL(?![A-Za-z0-9_])",
    "#include <curl/...>": r"#include\s*<curl/",
    "boost::asio": r"boost::asio",
    "cpp-httplib": r"(?<![A-Za-z0-9_])httplib(?![A-Za-z0-9_])",
    "urllib [py]": r"(?<![A-Za-z0-9_])urllib(?![A-Za-z0-9_])",
}

HEADER_INCLUDE: Dict[str, str] = {
    "#include <sys/socket.h>": r"#include\s*<sys/socket\.h>",
    "#include <netinet/in.h>": r"#include\s*<netinet/in\.h>",
    "#include <arpa/inet.h>": r"#include\s*<arpa/inet\.h>",
    "#include <winsock2.h>": r"#include\s*<winsock2\.h>",
    "#include <ws2tcpip.h>": r"#include\s*<ws2tcpip\.h>",
    "import socket [py]": r"^\s*import\s+socket(?:\s|$|\.)",
}

CATEGORIES: Dict[str, Dict[str, str]] = {
    "TRANSMIT": TRANSMIT,
    "RECEIVE_SETUP": RECEIVE_SETUP,
    "NAME_RESOLUTION": NAME_RESOLUTION,
    "HTTP_CLIENT": HTTP_CLIENT,
    "HEADER_INCLUDE": HEADER_INCLUDE,
}

# Categories whose LIVE matches are expected/benign for a passive capture
# tool and don't need a human decision -- everything else that shows up in
# live code is LIVE_REVIEW.
LIVE_SAFE_CATEGORIES = {"RECEIVE_SETUP", "HEADER_INCLUDE"}

ALLOWLIST_MARKER = "network-audit: allow"

DEFAULT_EXTENSIONS = {".cpp", ".hpp", ".h", ".cc", ".cxx", ".hxx", ".py"}
DEFAULT_SKIP_DIR_NAMES = {".git", "__pycache__", "node_modules", ".claude"}
DEFAULT_SKIP_DIR_PREFIXES = ("build",)  # build, build-fuzz, build-mingw, build_nolive, ...


# ---------------------------------------------------------------------------
# Per-language context tokenizers
# ---------------------------------------------------------------------------
# Each returns a list of strings, one per input line, the same length as
# that line, where each character is one of:
#   'K'  -- live code
#   'M'  -- comment (line or block)
#   'Q'  -- inside a string or char literal


def tokenize_cpp(lines: List[str]) -> List[str]:
    masks: List[str] = []
    in_block_comment = False
    for line in lines:
        mask: List[str] = []
        i, n = 0, len(line)
        while i < n:
            if in_block_comment:
                if line[i : i + 2] == "*/":
                    mask.append("M")
                    mask.append("M")
                    i += 2
                    in_block_comment = False
                else:
                    mask.append("M")
                    i += 1
                continue
            two = line[i : i + 2]
            if two == "//":
                mask.extend(["M"] * (n - i))
                i = n
                continue
            if two == "/*":
                mask.append("M")
                mask.append("M")
                i += 2
                in_block_comment = True
                continue
            c = line[i]
            if c in ("'", '"'):
                quote = c
                mask.append("Q")
                i += 1
                while i < n:
                    if line[i] == "\\" and i + 1 < n:
                        mask.append("Q")
                        mask.append("Q")
                        i += 2
                        continue
                    if line[i] == quote:
                        mask.append("Q")
                        i += 1
                        break
                    mask.append("Q")
                    i += 1
                continue
            mask.append("K")
            i += 1
        masks.append("".join(mask))
    return masks


def tokenize_python(lines: List[str]) -> List[str]:
    masks: List[str] = []
    triple_state: Optional[str] = None  # None, "'''", or '"""'
    for line in lines:
        mask: List[str] = []
        i, n = 0, len(line)
        while i < n:
            if triple_state:
                if line[i : i + 3] == triple_state:
                    mask.extend(["Q", "Q", "Q"])
                    i += 3
                    triple_state = None
                else:
                    mask.append("Q")
                    i += 1
                continue
            c = line[i]
            three = line[i : i + 3]
            if c == "#":
                mask.extend(["M"] * (n - i))
                i = n
                continue
            if three in ("'''", '"""'):
                triple_state = three
                mask.extend(["Q", "Q", "Q"])
                i += 3
                continue
            if c in ("'", '"'):
                quote = c
                mask.append("Q")
                i += 1
                while i < n:
                    if line[i] == "\\" and i + 1 < n:
                        mask.append("Q")
                        mask.append("Q")
                        i += 2
                        continue
                    if line[i] == quote:
                        mask.append("Q")
                        i += 1
                        break
                    mask.append("Q")
                    i += 1
                continue
            mask.append("K")
            i += 1
        masks.append("".join(mask))
    return masks


TOKENIZERS = {
    ".cpp": tokenize_cpp,
    ".hpp": tokenize_cpp,
    ".h": tokenize_cpp,
    ".cc": tokenize_cpp,
    ".cxx": tokenize_cpp,
    ".hxx": tokenize_cpp,
    ".py": tokenize_python,
}


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    path: str
    line_no: int  # 1-based
    col: int  # 0-based
    category: str
    pattern_label: str
    context: str  # "code" | "comment" | "string"
    classification: str  # INERT | LIVE_SAFE | LIVE_REVIEW | ALLOWLISTED
    snippet: str


def classify_context(ch: str) -> str:
    return {"K": "code", "M": "comment", "Q": "string"}.get(ch, "code")


def scan_file(path: str) -> List[Finding]:
    ext = os.path.splitext(path)[1]
    tokenizer = TOKENIZERS.get(ext)
    if tokenizer is None:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw_lines = fh.read().splitlines()
    except OSError:
        return []

    masks = tokenizer(raw_lines)
    findings: List[Finding] = []

    for category, patterns in CATEGORIES.items():
        for label, pattern in patterns.items():
            regex = re.compile(pattern)
            for line_no, line in enumerate(raw_lines, start=1):
                for m in regex.finditer(line):
                    start = m.start()
                    mask = masks[line_no - 1]
                    ch = mask[start] if start < len(mask) else "K"
                    context = classify_context(ch)

                    if context in ("comment", "string"):
                        classification = "INERT"
                    elif category in LIVE_SAFE_CATEGORIES:
                        classification = "LIVE_SAFE"
                    else:
                        allow_here = ALLOWLIST_MARKER in line
                        allow_above = line_no > 1 and ALLOWLIST_MARKER in raw_lines[line_no - 2]
                        classification = "ALLOWLISTED" if (allow_here or allow_above) else "LIVE_REVIEW"

                    findings.append(
                        Finding(
                            path=path,
                            line_no=line_no,
                            col=start,
                            category=category,
                            pattern_label=label,
                            context=context,
                            classification=classification,
                            snippet=line.strip(),
                        )
                    )
    return findings


def iter_source_files(root: str, extensions: set) -> List[str]:
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d
            for d in dirnames
            if d not in DEFAULT_SKIP_DIR_NAMES and not d.startswith(DEFAULT_SKIP_DIR_PREFIXES)
        ]
        for fn in filenames:
            if os.path.splitext(fn)[1] in extensions:
                out.append(os.path.join(dirpath, fn))
    out.sort()
    return out


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

CLASS_ORDER = ["LIVE_REVIEW", "ALLOWLISTED", "LIVE_SAFE", "INERT"]


def print_report(findings: List[Finding], show_live_safe: bool, show_inert: bool) -> None:
    by_class: Dict[str, List[Finding]] = {c: [] for c in CLASS_ORDER}
    for f in findings:
        by_class[f.classification].append(f)

    print("=" * 78)
    print("NETWORK CALL AUDIT")
    print("=" * 78)
    print()
    print(f"{len(findings)} total match(es) across all categories.")
    for c in CLASS_ORDER:
        print(f"  {c:<12} {len(by_class[c])}")
    print()

    if by_class["LIVE_REVIEW"]:
        print("-" * 78)
        print("LIVE_REVIEW -- live code, transmit-capable or name-resolution/HTTP-client")
        print("category. Each of these needs a human look.")
        print("-" * 78)
        for f in by_class["LIVE_REVIEW"]:
            print(f"  [{f.category}] {f.path}:{f.line_no}: {f.pattern_label}")
            print(f"      {f.snippet}")
        print()

        print("-" * 78)
        print("POSITIVE HITS -- file:line only, one per line (for scripting/grep):")
        print("-" * 78)
        for f in by_class["LIVE_REVIEW"]:
            print(f"{f.path}:{f.line_no}")
        print()
    else:
        print("No LIVE_REVIEW findings: no transmit-capable, name-resolution, or")
        print("HTTP-client call was found outside a comment/string anywhere scanned.")
        print()

    if by_class["ALLOWLISTED"]:
        print("-" * 78)
        print(f"ALLOWLISTED -- {len(by_class['ALLOWLISTED'])} finding(s) marked")
        print(f'"{ALLOWLIST_MARKER}" on the line itself or the line above it:')
        print("-" * 78)
        for f in by_class["ALLOWLISTED"]:
            print(f"  [{f.category}] {f.path}:{f.line_no}: {f.pattern_label}")
            print(f"      {f.snippet}")
        print()

    if show_live_safe and by_class["LIVE_SAFE"]:
        print("-" * 78)
        print("LIVE_SAFE -- receive-only capture setup / header includes, live code,")
        print("shown for transparency (not a finding):")
        print("-" * 78)
        for f in by_class["LIVE_SAFE"]:
            print(f"  [{f.category}] {f.path}:{f.line_no}: {f.pattern_label}")
            print(f"      {f.snippet}")
        print()

    if show_inert and by_class["INERT"]:
        print("-" * 78)
        print(f"INERT -- {len(by_class['INERT'])} match(es) in comments/strings, shown for transparency:")
        print("-" * 78)
        for f in by_class["INERT"]:
            print(f"  [{f.category}/{f.context}] {f.path}:{f.line_no}: {f.pattern_label}")
            print(f"      {f.snippet}")
        print()

    print("=" * 78)
    if by_class["LIVE_REVIEW"]:
        print(f"RESULT: FAIL -- {len(by_class['LIVE_REVIEW'])} live call(s) need review.")
    else:
        print("RESULT: PASS")
    print("=" * 78)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="Root directory to scan (default: current directory)")
    parser.add_argument(
        "--ext",
        default=",".join(sorted(DEFAULT_EXTENSIONS)),
        help="Comma-separated list of file extensions to scan (default: %(default)s)",
    )
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable JSON report instead of text")
    parser.add_argument("--quiet", action="store_true", help="Text mode: only print the final PASS/FAIL summary")
    parser.add_argument(
        "--positives-only",
        action="store_true",
        help="Text mode: print ONLY the LIVE_REVIEW findings as 'path:line', one per line, nothing else",
    )
    parser.add_argument(
        "--show-live-safe", action="store_true", help="Text mode: also list LIVE_SAFE (receive-only) matches"
    )
    parser.add_argument("--show-inert", action="store_true", help="Text mode: also list INERT (comment/string) matches")
    args = parser.parse_args(argv)

    extensions = {e if e.startswith(".") else "." + e for e in args.ext.split(",") if e}
    files = iter_source_files(args.root, extensions)

    all_findings: List[Finding] = []
    for path in files:
        all_findings.extend(scan_file(path))

    if args.json:
        payload = {
            "root": os.path.abspath(args.root),
            "files_scanned": len(files),
            "total_matches": len(all_findings),
            "findings": [
                {
                    "path": f.path,
                    "line": f.line_no,
                    "col": f.col,
                    "category": f.category,
                    "pattern": f.pattern_label,
                    "context": f.context,
                    "classification": f.classification,
                    "snippet": f.snippet,
                }
                for f in all_findings
            ],
        }
        print(json.dumps(payload, indent=2))
    elif args.positives_only:
        live_review = [f for f in all_findings if f.classification == "LIVE_REVIEW"]
        for f in live_review:
            print(f"{f.path}:{f.line_no}")
    elif args.quiet:
        live_review = [f for f in all_findings if f.classification == "LIVE_REVIEW"]
        if live_review:
            print(f"FAIL -- {len(live_review)} live call(s) need review (rerun without --quiet for detail).")
        else:
            print("PASS")
    else:
        print(f"Scanned {len(files)} file(s) under {os.path.abspath(args.root)}\n")
        print_report(all_findings, show_live_safe=args.show_live_safe, show_inert=args.show_inert)

    has_live_review = any(f.classification == "LIVE_REVIEW" for f in all_findings)
    return 1 if has_live_review else 0


if __name__ == "__main__":
    sys.exit(main())
