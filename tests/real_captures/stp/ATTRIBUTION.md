# Provenance of these fixtures

Two real STP-family captures, both sourced from `ITI/ICS-Security-Tools` (the same public
collection this project's PROFINET, GOOSE, and SV real fixtures already cite -- see the sibling
`tests/real_captures/goose/ATTRIBUTION.md`).

| File in this directory              | Source |
|--------------------------------------|--------|
| `sample_file_mms_and_goose.pcap`     | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/IEC61850/Sample_File_MMS_and_GOOSE.pcap` -- copied verbatim, unmodified. Also used, independently, as a GOOSE real-capture fixture (`tests/real_captures/goose/sample_file_mms_and_goose.pcap`); both copies are byte-for-byte identical (same SHA256). |
| `plant1_stp_only.pcap`               | Derived from `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/Combined/Plant1.pcap` by extracting only its STP frames (see below) -- the underlying bytes are real, unmodified capture bytes, but the file itself is a trim, not a verbatim copy. |

## Why a trim was needed for `Plant1.pcap`

The original `Plant1.pcap` is 7.6 MB and roughly 55,800 frames -- almost all of it unrelated
traffic (this project already draws its PROFINET RT/DCP and CIP I/O real-capture fixtures from
this same file, trimmed the same way, for the same reason: committing a multi-megabyte capture
just to reach a few dozen frames of interest isn't reasonable for a test fixture). It was
protocol-filtered down to just its STP frames with:

```
tshark -r Plant1.pcap -Y stp -w plant1_stp_only.pcap
```

`tshark`'s `-Y`/write path re-serializes matching frames into a new pcapng file without altering
their captured bytes, so every frame's own header/body content is exactly what was actually on the
wire -- only the *set* of frames present, and the container format (pcap -> pcapng), differ from
the original file. This is the same "real bytes, filtered container" trim already used elsewhere
in this codebase (see `tests/real_captures/profinet/ATTRIBUTION.md`'s and
`tests/real_captures/cip-io/ATTRIBUTION.md`'s own trims of this same source file) when a source
capture is too large to commit whole.

## How these were found

`mrhenrike/PCAPTrafficAnalysis` (checked first, since it had already turned up usable real captures
for this project's EtherCAT and PROFINET fixtures) was scanned file-by-file with `tshark -Y stp`
and yielded nothing -- none of its `.pcap` samples contain any STP-family traffic.
`ITI/ICS-Security-Tools` was then cloned in full (`git clone`, not the sparse/LFS-restricted path
some other files in that org have needed) and every `.pcap` under it was scanned the same way.
Two files came back with STP frames: `pcaps/Combined/Plant1.pcap` (42 classic Configuration BPDUs)
and `pcaps/IEC61850/Sample_File_MMS_and_GOOSE.pcap` (12 RSTP RST BPDUs, mixed in with the MMS/GOOSE
traffic that file is more commonly cited for). No file anywhere in either collection contains a
real TCN BPDU or any MSTP (Version 3/MST-extension) traffic -- see "Gaps" below.

## `plant1_stp_only.pcap` (3988 bytes, 42 frames)

42 real classic Configuration BPDUs (Protocol Version 0), captured over an 82-second window, every
one of them structurally and semantically identical: `Root=32768/80/64:a0:e7:9a:05:80 Cost=4
Bridge=32768/80/64:ae:0c:34:a3:80 Port=0x8083`, steady state (no Topology Change or Topology
Change Acknowledgment flag ever set), one BPDU roughly every 2 seconds -- exactly the periodic
Hello-interval Configuration BPDU behavior IEEE 802.1D describes for a bridge port that has long
since converged, with the same bridge apparently the sole source across the whole window (no
competing Configuration BPDU with a different Bridge Identifier ever appears, so this fragment
alone can't show a root-bridge election or a topology-change ripple). Every one of the 42 frames is
exactly 60 bytes on the wire, with 8 bytes of Ethernet minimum-frame-size padding after the LLC
client-data the 802.3 Length field actually declares -- this is the frame this codebase's own
synthetic fixture's first packet (`tests/sample_stp.pcap`, packet 1; see
`tools/make_sample_pcap.py`'s `build_stp_sample`) reproduces byte-for-byte, confirmed by hand
before any CTest case existed by decoding both and diffing the output.

## `sample_file_mms_and_goose.pcap` (43379 bytes, 301 frames total, 12 of them STP)

12 real RSTP RST BPDUs (Protocol Version 2, BPDU Type 0x02), mixed in with unrelated NTP, SMB,
MMS/COTP, and GOOSE traffic across an 11.4-second window (see
`tests/real_captures/goose/ATTRIBUTION.md` and `tests/real_captures/mms/ATTRIBUTION.md`, which
already document the non-STP traffic in this same file). The 12 frames come in 6 back-to-back
pairs, one member of each pair from bridge port `0x8010` and the other from port `0x8013`, all from
the same bridge (`Bridge=32768/0/00:0a:dc:06:19:5c`), all agreeing on the same root
(`Root=28672/4095/00:40:15:18:1d:7c Cost=1100`) and the same steady-state Port Role/flag
combination -- `Role=Designated [Learning] [Forwarding]` every time, with Proposal and Agreement
both clear throughout. Like `plant1_stp_only.pcap`, this confirms periodic Hello-interval BPDU
transmission from a bridge that has already converged, but never exercises the Proposal/Agreement
rapid-transition handshake RSTP is named for, nor a non-Designated Port Role (Root,
Alternate/Backup) on a real frame -- those are exercised only by the synthetic fixture (see Gaps
below). This capture also confirms the LLC padding-trim path (`llc_trailing_bytes_trimmed`) at a
different byte count than the Plant1 capture: these are 64-byte frames with 7 bytes of trailing
padding after a slightly longer BPDU body (RST BPDUs carry one more byte, the Version 1 Length,
than classic Configuration BPDUs already had), versus Plant1's 60-byte frames with 8 trailing
bytes.

## Gaps: what these real captures do NOT exercise

Neither file contains a real TCN BPDU (Type 0x80), any MSTP/MST-extension traffic (Protocol
Version 3, Type 0x02 with a populated MST extension), or SPB traffic (Protocol Version 4) -- every
scan of both `mrhenrike/PCAPTrafficAnalysis` and `ITI/ICS-Security-Tools` for this project turned
up nothing further along those lines, and no other accessible source was found (see this project's
standing policy, echoed in the sibling ATTRIBUTION.md files already in this repository, of not
fabricating a capture when a real one can't be found). Neither file exercises the RST Port Role
values Root, Alternate, or Backup on real bytes (only Designated appears), nor the Proposal or
Agreement flags, nor any Configuration/RST BPDU with the Topology Change or Topology Change
Acknowledgment flags set, nor Cisco PVST+ (SNAP-encapsulated) framing, nor GARP/GVRP/GMRP traffic
sharing STP's own LLC DSAP/SSAP pair. All of that -- TCN under both a classic and an RSTP Protocol
Version, every RST Port Role and flag combination, the full MST BPDU extension (including two
different multi-MSTI-message and edge-case-Version-3-Length scenarios drawn directly from
`packet-bpdu.c`'s own documented behavior), SPB named-only recognition, PVST+ named-only
recognition, and GARP/GVRP/GMRP disambiguation by destination MAC -- is validated only against
`tests/sample_stp.pcap` (see `tools/make_sample_pcap.py`'s `build_stp_sample`), cross-checked
against the reference dissector's source rather than an independent real capture. This mirrors the
same honest gap already documented for this codebase's other protocols' less-common paths.
