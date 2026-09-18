# conduitscope -- Documentation

The manual this file used to be has been split into three documents, once
it grew past 11,000 lines. This page is now a short index instead of a
redirect page — kept in place because dozens of `--help` strings, error
messages, and inline report text compiled into the `conduitscope` binary
itself say "see docs/MANUAL.md" (grep the source for
`docs/MANUAL.md` if you're tracking these down); pointing that existing
text at a live index is simpler and safer than updating every call site
and its regression test in lockstep. If you're reading this because a
`conduitscope` command told you to, the page you actually want is one of
the three below.

- **[USER_GUIDE.md](USER_GUIDE.md)** -- start here to run the tool.
  Command syntax and options (`decode`, `info`, `interfaces`,
  `policy validate`, `inventory`, `version`), live capture, the policy
  file format (schema, function-level restrictions, JSON report schema),
  output formats (text/json/csv, name resolution), captured-frame padding,
  limitations, exit status, and worked examples.
- **[PROTOCOL_COVERAGE.md](PROTOCOL_COVERAGE.md)** -- the full per-protocol
  reference: what conduitscope recognizes on the wire, exactly what each
  decoder surfaces, and how much confidence to place in each detection.
  Read this before citing a `decode` finding in an audit report.
- **[DEVELOPMENT.md](DEVELOPMENT.md)** -- for anyone extending the
  codebase rather than just running it: an architecture snapshot, the
  September 2026 external code review and the engineering priorities that
  came out of it, protocol-detection dispatch order and collision
  handling, and the development roadmap.

See also the top-level [README.md](../README.md) for the project overview
and quick start, and [man/conduitscope.1](../man/conduitscope.1) for the
man page (built from the same material as USER_GUIDE.md).
