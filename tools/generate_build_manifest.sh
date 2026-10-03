#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# generate_build_manifest.sh -- produces a small, dependency-free JSON "build provenance
# manifest" for one built `conduitscope` binary: its own reported version/compiler/build type
# (conduitscope version), the exact system libpcap-dev package version it was actually linked
# against on this build host (dpkg-query, when available), the vendored CLI11 version (read back
# from third_party/CLI11/README.md's own "Version vendored" line -- a single source of truth,
# not a second hardcoded copy that can drift from it), the build host's kernel/arch, the commit
# this was built from (when CI's own GITHUB_SHA is set; "unknown" otherwise -- this repository
# itself has no VCS metadata to fall back on), and a timestamp.
#
# Written for docs/DEVELOPMENT.md ROADMAP item 124 (patch282 security review finding 7:
# "release reproducibility is still not deterministic" -- the review's own suggested "SBOM,
# dependency/license manifest" items). Deliberately NOT a full SPDX/CycloneDX SBOM -- this is a
# hand-rolled, narrow record of exactly the handful of facts this project's own release process
# can state with confidence, in the same spirit as src/yaml_mini.cpp's hand-rolled YAML parser:
# no new third-party tool/dependency pulled in just to produce this. See
# docs/THIRD_PARTY_NOTICES.md for the actual license/provenance text this manifest's fields point
# back at, and item 124's own write-up for why a real CycloneDX/SPDX generator and a pinned build
# container were deliberately scoped OUT of this pass rather than attempted half-verified.
#
# Usage: generate_build_manifest.sh <path-to-built-conduitscope-binary> <output-json-path>
#
# Linux-only as written (dpkg-query, uname -- matches this project's own Linux `release` CI job,
# the only leg that currently calls this script). The Windows release leg has its own, separate,
# already-pinned-and-verified Npcap SDK provenance (NPCAP_SDK_VERSION/NPCAP_SDK_SHA256 in
# .github/workflows/ci.yml); folding Windows into this same script was considered and deliberately
# not done -- it would need a second, PowerShell-flavored code path for a result that's already
# fully covered by what ci.yml itself already pins and verifies for that leg.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <path-to-built-conduitscope-binary> <output-json-path>" >&2
    exit 2
fi

BINARY="$1"
OUT="$2"

if [ ! -x "$BINARY" ]; then
    echo "generate_build_manifest.sh: '$BINARY' is not an executable file" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLI11_README="$REPO_ROOT/third_party/CLI11/README.md"

# json_escape: backslash- and quote-escape the handful of characters that can legally appear in
# any of the plain version/path/identifier strings this script deals with. None of these fields
# are expected to ever contain a literal newline or control character in practice, but escaping
# defensively costs nothing and means this script never has to assume that about its inputs.
json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# `conduitscope version` reports exactly:
#   conduitscope <version>  [<compiler id> <compiler version>, <os>, <build type>, live capture: <...>]
# (see version.hpp.in / cli_main.cpp's own version_cmd) -- parsed back here rather than
# duplicating CMake's own CMAKE_CXX_COMPILER_ID/VERSION logic in a second place.
VERSION_LINE="$("$BINARY" version)"
CS_VERSION="$(printf '%s\n' "$VERSION_LINE" | sed -n 's/^conduitscope \([^ ]*\).*/\1/p')"
BRACKET_CONTENTS="$(printf '%s\n' "$VERSION_LINE" | sed -n 's/^.*\[\(.*\)\].*$/\1/p')"
COMPILER_FIELD="$(printf '%s\n' "$BRACKET_CONTENTS" | awk -F', ' '{print $1}')"
OS_FIELD="$(printf '%s\n' "$BRACKET_CONTENTS" | awk -F', ' '{print $2}')"
BUILD_TYPE_FIELD="$(printf '%s\n' "$BRACKET_CONTENTS" | awk -F', ' '{print $3}')"

if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Version}' libpcap-dev >/dev/null 2>&1; then
    LIBPCAP_DEV_VERSION="$(dpkg-query -W -f='${Version}' libpcap-dev)"
else
    LIBPCAP_DEV_VERSION="unavailable (libpcap-dev not installed via dpkg on this build host, or this was a -DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF build)"
fi

if [ -f "$CLI11_README" ]; then
    CLI11_VERSION="$(sed -n 's/^- \*\*Version vendored:\*\* \([^,]*\),.*/\1/p' "$CLI11_README" | head -n1)"
    if [ -z "$CLI11_VERSION" ]; then
        CLI11_VERSION="unknown (third_party/CLI11/README.md's \"Version vendored\" line did not match the expected format -- update this script's sed pattern if that line's wording changed)"
    fi
else
    CLI11_VERSION="unknown (third_party/CLI11/README.md not found next to this checkout)"
fi

HOST_KERNEL="$(uname -srm 2>/dev/null || echo unknown)"
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# GITHUB_SHA is set by GitHub Actions for every workflow run (the commit the workflow is running
# against); this repository's own sandbox checkout has no git metadata at all to fall back on, so
# "unknown" here is honest rather than fabricated.
BUILT_FROM_COMMIT="${GITHUB_SHA:-unknown (no VCS metadata available in this build environment)}"

cat > "$OUT" <<JSON
{
  "schema": "conduitscope-build-manifest/1",
  "generated_at_utc": "$(json_escape "$GENERATED_AT")",
  "conduitscope_version": "$(json_escape "$CS_VERSION")",
  "built_from_commit": "$(json_escape "$BUILT_FROM_COMMIT")",
  "compiler": "$(json_escape "$COMPILER_FIELD")",
  "target_os": "$(json_escape "$OS_FIELD")",
  "build_type": "$(json_escape "$BUILD_TYPE_FIELD")",
  "build_host_kernel": "$(json_escape "$HOST_KERNEL")",
  "dependencies": {
    "libpcap_dev_package_version": "$(json_escape "$LIBPCAP_DEV_VERSION")",
    "cli11_vendored_version": "$(json_escape "$CLI11_VERSION")"
  },
  "notes": "Lightweight build-provenance record, not a full SPDX/CycloneDX SBOM. See docs/THIRD_PARTY_NOTICES.md for license/provenance detail on each dependency named above, and docs/DEVELOPMENT.md ROADMAP item 124 for what this manifest does and deliberately does not cover."
}
JSON

echo "Wrote build manifest to $OUT"
cat "$OUT"
