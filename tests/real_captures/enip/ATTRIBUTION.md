# Provenance of these fixtures

Two real EtherNet/IP captures, both sourced from the same public collection (no explicit license;
included as real, non-sensitive protocol test vectors, same basis as
`tests/real_captures/dnp3/ATTRIBUTION.md` and `tests/real_captures/modbus/ATTRIBUTION.md`).

| File in this directory                       | Source |
|-----------------------------------------------|--------|
| `enip_list_identity.pcap`                     | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/EthernetIP/enip_test.pcap` -- copied verbatim, unmodified |
| `ethernetip_cip_explicit_messaging.pcap`      | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/EthernetIP/EthernetIP-CIP.pcap` -- **trimmed**, see below |

## `enip_list_identity.pcap` (925 bytes, 11 packets, unmodified)

A real ControlLogix engineering-workstation-to-bridge-module session: two TCP connections (ports
5262 and 37997, both to 44818) with mostly bare handshake/teardown segments, and one real
ListIdentity request/response exchange in the middle. The response's identity item decodes to
vendor=1 (Rockwell Automation), device_type=12 (Communications Adapter), product_code=58,
revision 4.3, serial 0x524d8e, product name `"1756-ENBT/A"` -- a real 1756-ENBT/A EtherNet/IP
bridge module for the ControlLogix rack. This is the fixture that validates the ListIdentity
device-fingerprinting decode path (including the socket-address structure's big-endian byte order)
against an independent real stack's actual wire encoding, not just `tests/sample_enip.pcap`'s
hand-constructed bytes.

## `ethernetip_cip_explicit_messaging.pcap` (450 packets, trimmed from a 2 MB / 10880-packet
## original)

The original `EthernetIP-CIP.pcap` is a long real capture of an industrial control system polling
loop, almost entirely `SendUnitData` traffic carrying `Multiple_Service_Packet` (service 0x0A)
requests/responses, each bundling several embedded CIP messages. Trimmed to its first 450 packets
(a small Python script slicing the classic-pcap record stream, keeping the global header and
per-record byte layout untouched) purely for fixture-size reasons -- the polling pattern repeats
throughout the file, so the first 450 packets are representative of the whole, not a
cherry-picked subset chosen for content.

This is the fixture that most directly validates the scoping decision documented in
`enip.hpp`'s file header comment and `cip_service_name`'s comment in `enip.cpp`: the embedded
members inside these `Multiple_Service_Packet` envelopes are a real-world mix of

- **1209 `Read_Tag` (service 0x4C) requests/responses** against symbolically-addressed (ANSI
  Extended Symbol segment 0x91) named tags -- decoded with full type+value semantics, and
- **1193 members using that exact same service code 0x4C against `Class=0x72 Instance=0x0`** --
  a vendor-specific object class, *not* the Rockwell Symbol object -- which this decoder
  deliberately shows as `Unknown (0x4C) request path=Class=0x72 Instance=0x0` with raw hex data
  rather than misdecoding as a tag read, and
- **70 `Read_Modify_Write_Tag` (service 0x4E) request/response pairs** against symbolically
  addressed tags, whose success responses carry zero data bytes -- confirmed here against real
  traffic, not assumed (see `decode_cip_response_data`'s comment on service 0x4E in `enip.cpp`).

In other words: this one real capture is exactly the evidence that motivated (and now
regression-guards) the symbolic-path-gating architecture -- without it, service 0x4C's ~1193
non-tag members here would have been confidently misdecoded as garbage tag reads.

## Why these specific fixtures

`tests/sample_enip.pcap` (hand-built, see `tools/make_sample_pcap.py`'s `build_enip_sample`)
covers RegisterSession/UnRegisterSession and a clean symbolic Read_Tag/Write_Tag round trip --
neither of which either real capture above happens to contain (`enip_list_identity.pcap`'s two
sessions never send RegisterSession at all, and `ethernetip_cip_explicit_messaging.pcap`'s tag
traffic is always wrapped in `Multiple_Service_Packet`, never a bare single-service `SendRRData`)
-- so the synthetic fixture is where those specific shapes are pinned down with hand-verifiable
exact expected values. These two real captures are where the CPF/List-Identity/Multiple_Service_
Packet/Unconnected_Send/Read_Modify_Write_Tag decode paths, and the symbolic-vs-class/instance
service-code disambiguation itself, are validated against independent real stacks' actual wire
encodings.

Neither capture happened to contain an EtherNet/IP encapsulation message split across a TCP
segment boundary -- consistent with explicit-messaging PDUs typically being small enough to fit
one segment. `enip_declared_length`'s cross-segment reassembly therefore remains exercised only by
the synthetic `tests/sample_tcp_reassembly.pcap`-style coverage used for the other protocols, not
by a captured real fragmentation event; see the ROADMAP in `docs/MANUAL.md`.
