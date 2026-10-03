#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# verify_reproducible_build.sh -- proves (rather than merely asserting) that a `-DCMAKE_BUILD_
# TYPE=Release` conduitscope binary is byte-for-byte independent of the absolute filesystem path
# it was checked out or built at, by actually building it twice, from two independently-copied
# checkouts at two deliberately different absolute paths (different depths, different lengths,
# one nested under the other's structure and one not), and diffing the two stripped binaries.
#
# Written for docs/DEVELOPMENT.md ROADMAP item 124 (patch282 security review finding 7: "release
# build/reproducibility hardening is weaker than CI workflow hardening" -- the review's own
# suggested "reproducible build verification" item). The empirical finding this script continuously
# re-checks (confirmed when this script was first written): conduitscope's Release configuration
# already produces an identical binary across different build paths TODAY, with no new compiler
# flags needed, because (a) this project's own code never uses __DATE__/__TIME__/__FILE__/
# __LINE__ in a way that reaches a Release binary's bytes (grep finds none in src/include outside
# the three assert()-using files, and assert() itself expands to nothing once CMake's own default
# Release flags define NDEBUG -- see CMakeLists.txt's CMAKE_CXX_FLAGS_RELEASE), and (b) Release
# builds carry no `-g` debug info (so no DW_AT_comp_dir/DW_AT_name absolute-path records either).
# This script exists so that property is actively re-verified on every run that calls it (wired
# into .github/workflows/ci.yml's own reproducible-build-check job) rather than remaining a one-
# time claim in this comment -- a future change that adds -g to a shipped config, or an __DATE__/
# __FILE__ use that reaches compiled code, would make this fail loudly instead of silently
# shipping a build that is no longer actually reproducible.
#
# Usage: verify_reproducible_build.sh <path-to-conduitscope-checkout>
#
# Copies ONLY the files an out-of-tree build actually needs (src/, include/, third_party/,
# tools/, CMakeLists.txt) into two fresh scratch directories under $(mktemp -d) -- never the
# checkout's own build*/ directories, which can be large (see this project's own build-fuzz/
# directory) and are irrelevant to what's being proven here. Builds live-capture-disabled
# (-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF) specifically so this check has no dependency on
# whether libpcap-dev happens to be installed on whatever host runs it -- reproducibility of the
# OBJECT CODE conduitscope itself emits doesn't depend on that flag one way or the other, and
# CMakeLists.txt's own CONDUITSCOPE_ENABLE_LIVE_CAPTURE comment documents that this flag changes
# nothing about non-capture code generation.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <path-to-conduitscope-checkout>" >&2
    exit 2
fi

SRC_CHECKOUT="$(cd "$1" && pwd)"
for required in CMakeLists.txt src include third_party tools; do
    if [ ! -e "$SRC_CHECKOUT/$required" ]; then
        echo "verify_reproducible_build.sh: '$SRC_CHECKOUT' doesn't look like a conduitscope checkout (missing $required)" >&2
        exit 1
    fi
done

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

# Two deliberately mismatched absolute-path shapes: one short, one long and deeply nested under
# an unrelated extra subtree -- so this isn't just proving "the same relative layout at two
# different prefixes produces the same bytes" (which out-of-tree CMake builds would do trivially
# via relative object-file paths regardless of any real path-independence), but genuinely
# different path depths/lengths, which is what would expose an accidental absolute-path leak.
COPY_A="$SCRATCH/a"
COPY_B="$SCRATCH/deeply/nested/unrelated/path/segment/for/copy-b-which-is-considerably-longer"
mkdir -p "$COPY_A" "$COPY_B"

for item in CMakeLists.txt src include third_party tools; do
    cp -a "$SRC_CHECKOUT/$item" "$COPY_A/"
    cp -a "$SRC_CHECKOUT/$item" "$COPY_B/"
done

BUILD_A="$SCRATCH/out-build-short"
BUILD_B="$SCRATCH/another/differently/shaped/out/of/tree/build/dir"
mkdir -p "$BUILD_A" "$BUILD_B"

echo "Building copy A ($COPY_A -> $BUILD_A)..."
cmake -S "$COPY_A" -B "$BUILD_A" -DCMAKE_BUILD_TYPE=Release \
    -DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF -DCONDUITSCOPE_VERSION_OVERRIDE=0.0.0-repro-check \
    >"$SCRATCH/cmake-a.log" 2>&1
cmake --build "$BUILD_A" -j"$(nproc)" --target conduitscope >"$SCRATCH/build-a.log" 2>&1

echo "Building copy B ($COPY_B -> $BUILD_B)..."
cmake -S "$COPY_B" -B "$BUILD_B" -DCMAKE_BUILD_TYPE=Release \
    -DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF -DCONDUITSCOPE_VERSION_OVERRIDE=0.0.0-repro-check \
    >"$SCRATCH/cmake-b.log" 2>&1
cmake --build "$BUILD_B" -j"$(nproc)" --target conduitscope >"$SCRATCH/build-b.log" 2>&1

strip -o "$SCRATCH/a.stripped" "$BUILD_A/conduitscope"
strip -o "$SCRATCH/b.stripped" "$BUILD_B/conduitscope"

HASH_A="$(sha256sum "$SCRATCH/a.stripped" | awk '{print $1}')"
HASH_B="$(sha256sum "$SCRATCH/b.stripped" | awk '{print $1}')"

echo "Build A sha256: $HASH_A"
echo "Build B sha256: $HASH_B"

if [ "$HASH_A" != "$HASH_B" ]; then
    echo "FAIL: the two builds, from different absolute paths, produced DIFFERENT binaries." >&2
    echo "This means something in the current build now embeds an absolute build/source path" >&2
    echo "(or another non-deterministic input) into the compiled output -- see this script's" >&2
    echo "own header comment for the two things this used to NOT depend on (NDEBUG-stripped" >&2
    echo "asserts, no -g in Release) and check what changed." >&2
    echo "Leaving the two builds and cmake/build logs in place for inspection: $SCRATCH" >&2
    trap - EXIT
    exit 1
fi

echo "OK: Release build is reproducible across different absolute build/source paths (sha256: $HASH_A)"
