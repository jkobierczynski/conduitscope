# Third-party notices and dependency/license manifest

conduitscope itself is licensed under the Apache License, Version 2.0 (see the
repository root [`LICENSE`](../LICENSE)). This page is the single,
consolidated place that lists every other piece of software conduitscope's
*build* or *shipped binary* actually touches, what its licensing situation
is, and whether anything from it is redistributed -- written for
`docs/DEVELOPMENT.md` ROADMAP item 124 (patch282 security review finding 7,
"release build/reproducibility hardening is weaker than CI workflow
hardening," which named "SBOM, dependency/license manifest" among its
suggested future-hardening items). It deliberately points at each
dependency's own, already-existing, more detailed provenance note rather
than duplicating them here -- a second hand-copied version of a fact like
"CLI11 is BSD-3-Clause" is just one more place that fact can go stale.

| Dependency | Relationship | Redistributed? | License | Detail |
|---|---|---|---|---|
| CLI11 | Vendored single-header source, compiled into conduitscope | Source is vendored in this repository; the library's own code becomes part of the compiled binary | 3-clause BSD | [`third_party/CLI11/README.md`](../third_party/CLI11/README.md) |
| libpcap (Linux) / Npcap (Windows) | System/SDK dependency, linked at build time, loaded at run time from the end user's own separate install | **No** -- never bundled into the repository or into a shipped release artifact | See below | See below |
| GitHub Actions used by CI | Build/release infrastructure only; never shipped | No | See below | `.github/workflows/ci.yml`'s own per-action comments |

## libpcap (Linux)

`libpcap-dev` is installed from the build host's own OS package manager
(`apt-get install libpcap-dev` in every Linux CI job that builds live-capture
support -- see `.github/workflows/ci.yml`) and dynamically linked. The
Linux release package built by the `release` CI job
(`conduitscope-X.Y.Z-linux-x86_64.tar.gz`) contains only the `conduitscope`
binary itself plus docs/README/LICENSE/man -- never a copy of `libpcap.so`.
A user installs their own distribution's `libpcap` (almost universally
already present, or a single `apt`/`yum`/`dnf`/`pacman` package install
away) to get live capture; an offline `decode`/`policy validate`/`inventory`/
etc. run against an existing pcap file needs no `libpcap` at run time at all
(see `CMakeLists.txt`'s `CONDUITSCOPE_HAVE_PCAP` gating).

libpcap itself is distributed under a 3-clause BSD license (see
<https://github.com/the-tcpdump-group/libpcap/blob/master/LICENSE> for the
canonical text) -- this project does not redistribute it, so no separate
`NOTICE` entry beyond this note is required.

The *exact* libpcap-dev package version actually linked against on a given
CI build host is recorded per-build, not pinned here as a single fixed
value -- see "What's deliberately not pinned" below for why, and
`tools/generate_build_manifest.sh` for where that exact version ends up
recorded (the per-release build-provenance manifest described below).

## Npcap SDK (Windows)

The Windows release leg (`release-windows` in `.github/workflows/ci.yml`)
downloads the Npcap SDK (headers + `wpcap.lib`/`Packet.lib` import
libraries) at a pinned version (`NPCAP_SDK_VERSION`), with the downloaded
zip's SHA-256 verified against a pinned `NPCAP_SDK_SHA256` before anything
is extracted or built against it (docs/DEVELOPMENT.md ROADMAP item 15 --
this was itself a prior security-review finding, already fixed and
documented there). This SDK is needed only to *build* live-capture support
into `conduitscope.exe`; it is never copied into the shipped release
archive. The released `.exe` delay-loads `wpcap.dll` (see `CMakeLists.txt`'s
own comment) and relies entirely on whatever Npcap runtime the end user
separately installs on their own machine -- nothing from the SDK is
distributed, redistributed, or statically linked into the shipped binary.

Npcap's own license terms (distinct from libpcap's BSD license -- Npcap is
the Nmap Project's own Windows packet-capture driver/library, under its own
license with separate terms for certain redistribution/OEM scenarios) apply
to whatever a user separately downloads and installs from
<https://npcap.com/> themselves; conduitscope's own build/release process
never redistributes Npcap in any form, so those terms are the end user's
and Nmap Project's own relationship, not something this project's license
needs to account for. See <https://npcap.com/> for Npcap's current license
text rather than relying on a copy here, which could go stale.

## GitHub Actions (CI/release infrastructure only)

Every `uses:` step in `.github/workflows/ci.yml` is pinned to an immutable
commit SHA (not a mutable tag), each with its own `# vX.Y.Z` trailing
comment -- see that workflow's own top-of-file comment and
docs/DEVELOPMENT.md ROADMAP item 15 for the full rationale and bump
procedure. None of this is shipped in any release artifact; it only builds
and tests the project and (for tagged pushes) assembles the release archive
itself.

## Per-release build-provenance manifest

Since v0.2.10 (docs/DEVELOPMENT.md ROADMAP item 124), the Linux `release`
CI job runs `tools/generate_build_manifest.sh` against the just-built
binary and attaches the result --
`conduitscope-X.Y.Z-linux-x86_64.manifest.json` -- as a release asset
alongside the existing binary archive and its `.sha256` checksum. It
records that specific build's conduitscope version, the exact compiler
(id + version) and OS it was built with, the exact `libpcap-dev` package
version actually installed on the build host at the time, the vendored
CLI11 version (read back from `third_party/CLI11/README.md`'s own "Version
vendored" line rather than duplicated as a second hardcoded copy), the
build host's kernel/architecture, the commit it was built from
(`GITHUB_SHA`), and a UTC timestamp.

This is intentionally a small, hand-rolled, dependency-free JSON document
-- not a full SPDX or CycloneDX SBOM generated by a dedicated scanning
tool. That's a deliberate scope choice, not an oversight: conduitscope has
exactly one vendored dependency (CLI11) and one optional system dependency
(libpcap/Npcap), both already fully covered by the sections above, so
standing up a general-purpose SBOM toolchain for a two-dependency project
would add real tooling weight (a new CI dependency, a new file format to
keep current) for very little additional information over what this
project can already state plainly in prose. If conduitscope's dependency
surface grows materially beyond CLI11 and libpcap, revisit this decision --
a real SBOM generator earns its keep once there's enough of a dependency
graph that hand-maintained prose stops being the more honest, more
maintainable choice.

## What's deliberately not pinned (and why)

The patch282 review's own F7 finding also suggested a **pinned build
container** (building release artifacts inside a container at a specific,
digest-pinned base image, rather than whatever `ubuntu-latest`/
`windows-latest` GitHub-hosted runner image happens to be live that day)
and a **hard version pin on the `libpcap-dev` package itself** (the same
treatment the Npcap SDK already gets). Both were considered for item 124
and deliberately left undone, for concrete reasons rather than being
skipped silently:

- **Pinned build container.** Verifying a trustworthy container image
  digest requires reaching a container registry; this project's own CI
  development sandbox has no route to one (confirmed: a direct check
  against Docker Hub's registry endpoint was refused by this environment's
  own egress policy, the same class of restriction ROADMAP item 15 hit
  reaching npcap.com before that value could be filled in by hand). Unlike
  that case, a container migration isn't a single value to backfill later
  -- it changes the whole job's execution environment (the `CAP_NET_RAW`
  `setcap` grant path the live-capture tests rely on, the Windows SDK
  caching behavior, the exact toolchain available), and landing that
  unverified risks shipping a CI change that has never actually been run
  green for real. GitHub's own hosted runner images also receive security
  patches on their own cadence that a hand-pinned container would then be
  responsible for re-pinning to keep receiving -- a real tradeoff, not a
  pure improvement, and one worth a deliberate decision rather than a
  default.
- **Hard `libpcap-dev` version pin.** `apt-get install libpcap-dev=<exact
  version>` only works for as long as that exact version stays the
  *current* candidate in the live Ubuntu archive mirror CI's `apt-get
  update` reaches -- unlike a dedicated snapshot service, `archive.
  ubuntu.com` does not keep serving old package versions once a newer one
  replaces them, so a naive hard pin here is a time bomb: it keeps working
  right up until the next ordinary `libpcap` security update lands
  upstream, at which point every CI run starts failing with "Version
  '<pinned>' for 'libpcap-dev' was not found" for a reason that has nothing
  to do with this project's own code. Genuinely pinning libpcap the way
  the Npcap SDK is pinned would mean vendoring a specific upstream source
  tarball with a verified checksum and building it from source in every CI
  job -- a real option, but a materially bigger lift than this pass's
  scope, and not attempted half-way. What this pass does instead: the
  per-release build-provenance manifest above records the *exact* version
  that was actually used for that specific release, after the fact, which
  gives the traceability the review's finding was really asking for
  (knowing exactly what a given release was built against) without
  pretending to control an upstream archive this project doesn't own.
