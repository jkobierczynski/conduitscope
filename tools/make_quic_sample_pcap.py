#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generates tests/sample_quic.pcap -- a synthetic, byte-exact QUIC v1 capture proving quic.cpp's
own decryption pipeline end to end, not just its individual primitives (those already have their
own crypto_selftest, see tools/generate_crypto_test_vectors.py).

Deliberately a SEPARATE script from tools/make_sample_pcap.py, which documents its own "pure
standard library... no dependency on scapy/pymodbus/etc." design goal -- this script genuinely
needs the third-party `cryptography` package (AES-128-ECB for header protection, AES-128-GCM for
the AEAD layer; Python's stdlib has no AES at all), the same dependency
tools/generate_crypto_test_vectors.py already carries for the identical reason and with the
identical justification: an independently-implemented, audited library is what makes this fixture
a genuine end-to-end proof of quic.cpp's own from-scratch aes128.cpp/aes128_gcm.cpp/hkdf.cpp,
rather than merely self-consistent with them. Both scripts stay build-time/dev-time-only --
neither runs as part of the CMake build, and the fixtures/vectors they produce are committed like
any other file under tests/ or include/.

Requires: the `cryptography` package (pip install cryptography). Reuses make_sample_pcap.py's own
Ethernet/IPv4/UDP header builders and its tls_client_hello() ClientHello-body builder (see
build_doh_sample() there for the TCP/HTTPS-carried use of that same helper) rather than
duplicating them -- importing that module does not execute anything beyond function/constant
definitions (its own fixture generation is behind `if __name__ == "__main__":`).

Run it from the repository root:
    python3 tools/make_quic_sample_pcap.py
"""
import hashlib
import hmac
import struct
import sys
import pathlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import make_sample_pcap as msp  # noqa: E402  (needs sys.path set up first)

# RFC 9001 Appendix A.1's own published QUIC v1 initial_salt -- independently corroborated (not
# hand-transcribed from a single source) exactly as quic.cpp's own kInitialSaltV1 was; this script
# encrypting a packet that quic.cpp then successfully decrypts is itself a second, end-to-end
# confirmation that both copies of this constant agree.
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


# --- QUIC varint (RFC 9000 section 16) -----------------------------------------------------
def quic_varint(value: int, *, force_2byte: bool = False) -> bytes:
    """Encodes `value` as a QUIC variable-length integer. `force_2byte` always emits the 2-byte
    (14-bit) form regardless of whether a shorter encoding would fit -- used for this script's own
    Length field so the packet's header length is known before that field's own value is (the
    value depends on the ciphertext length, which depends on how much PADDING is added to reach
    the target datagram size, which is sized relative to the header -- fixing this one field's
    encoded WIDTH up front breaks that circularity). quic.cpp's own read_varint accepts any validly
    encoded width, not just the minimal one, so this is unambiguous to decode either way."""
    if force_2byte:
        assert 0 <= value < 0x4000
        return struct.pack("!H", 0x4000 | value)
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return struct.pack("!H", 0x4000 | value)
    if value < 0x40000000:
        return struct.pack("!I", 0x80000000 | value)
    return struct.pack("!Q", 0xC000000000000000 | value)


# --- HKDF (RFC 5869) / HKDF-Expand-Label (RFC 8446 7.1) -- mirrors hkdf.cpp/hkdf.hpp exactly ---
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    t, okm, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label.encode("ascii")
    info = struct.pack("!H", length) + bytes([len(full_label)]) + full_label + bytes([len(context)]) + context
    return hkdf_expand(secret, info, length)


def derive_initial_client_keys(dcid: bytes):
    initial_secret = hkdf_extract(INITIAL_SALT_V1, dcid)
    client_secret = hkdf_expand_label(initial_secret, "client in", b"", 32)
    key = hkdf_expand_label(client_secret, "quic key", b"", 16)
    iv = hkdf_expand_label(client_secret, "quic iv", b"", 12)
    hp = hkdf_expand_label(client_secret, "quic hp", b"", 16)
    return key, iv, hp


def aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


# --- One full QUIC v1 Initial packet, built and protected the same way a real client would -----
def build_quic_initial_packet(dcid: bytes, scid: bytes, plaintext_frames: bytes,
                               derive_keys_from: bytes = None) -> bytes:
    """Returns one complete, header-protected, AEAD-encrypted QUIC v1 Initial packet (the UDP
    payload) carrying `plaintext_frames` as its decrypted contents. `derive_keys_from`, if given,
    derives the protection keys from a DIFFERENT Destination Connection ID than the one actually
    written into the packet's own DCID field -- used once below to build a deliberately
    undecryptable packet (simulating anything that isn't the client's own first Initial packet;
    see quic.hpp's own file header comment for why only that one direction ever decrypts)."""
    key, iv, hp = derive_initial_client_keys(derive_keys_from if derive_keys_from is not None else dcid)

    pn_length = 2
    header_clear = bytes([0xC1])  # header form=1, fixed=1, type=Initial(00), reserved=00, pn_len-1=01
    header_clear += struct.pack("!I", 1)  # version 1
    header_clear += bytes([len(dcid)]) + dcid
    header_clear += bytes([len(scid)]) + scid
    header_clear += quic_varint(0)  # Token Length = 0, no Token
    ciphertext_and_tag_len = pn_length + len(plaintext_frames) + 16
    header_clear += quic_varint(ciphertext_and_tag_len, force_2byte=True)  # Length field
    pn_offset = len(header_clear)
    pn_bytes_clear = struct.pack("!H", 0)  # packet number 0, the first Initial packet's own space

    aad = header_clear + pn_bytes_clear
    nonce = bytes(a ^ b for a, b in zip(iv, (0).to_bytes(12, "big")))  # packet number 0 -> nonce == iv
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext_frames, aad)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]

    full_before_hp = header_clear + pn_bytes_clear + ciphertext + tag
    sample = full_before_hp[pn_offset + 4: pn_offset + 4 + 16]
    mask = aes_ecb_encrypt_block(hp, sample)

    protected_byte0 = header_clear[0] ^ (mask[0] & 0x0F)
    protected_pn = bytes(b ^ m for b, m in zip(pn_bytes_clear, mask[1:1 + pn_length]))

    return bytes([protected_byte0]) + header_clear[1:] + protected_pn + ciphertext + tag


def crypto_frame(handshake_bytes: bytes) -> bytes:
    return quic_varint(0x06) + quic_varint(0) + quic_varint(len(handshake_bytes)) + handshake_bytes


def client_initial_plaintext(sni_hostname: str, *, pad_to: int = 1160) -> bytes:
    """A CRYPTO frame (Offset 0) carrying a minimal, syntactically-valid ClientHello with `sni`,
    followed by PADDING (0x00) frames out to `pad_to` bytes -- real client Initial packets are
    padded to at least a 1200-byte total UDP datagram (RFC 9000 14.1); 1160 bytes of frame stream
    plus this packet's own 44-byte header/PN/tag overhead lands right at that floor. reuses
    make_sample_pcap.py's own tls_client_hello() (see that function's own docstring) sliced past
    its 5-byte TLS record header -- QUIC's CRYPTO frame carries the raw Handshake message with no
    record-layer wrapper at all (RFC 9001 section 4), exactly what's left after that slice."""
    handshake = msp.tls_client_hello(sni_hostname, alpn=["h3"])[5:]
    frame = crypto_frame(handshake)
    assert len(frame) <= pad_to, "ClientHello grew past this fixture's fixed padding budget"
    return frame + bytes(pad_to - len(frame))


def minimal_long_header(long_type_bits: int, dcid: bytes, scid: bytes, version: int = 1,
                         trailer: bytes = b"") -> bytes:
    """A long-header packet with nothing beyond DCID/SCID/trailer -- the caller supplies whatever
    per-type trailing structure quic.cpp's own try_recognize_quic now requires before it will name
    a 0-RTT/Handshake/Retry packet (see 0rtt_handshake_trailer()/retry_trailer() below): the same
    post-fix-bug structural cross-check every other long-header type already had (Version
    Negotiation's own whole-number-of-versions check; Initial's own Length-field/captured-bytes
    cross-check)."""
    byte0 = 0xC0 | (long_type_bits << 4) | 0x00  # form=1, fixed=1, type bits, reserved/pnlen=0000
    return (bytes([byte0]) + struct.pack("!I", version) +
            bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + trailer)


def zero_rtt_or_handshake_trailer(payload_and_tag_len: int = 16) -> bytes:
    """A structurally self-consistent trailer for a 0-RTT/Handshake long-header packet: Length
    (a 1-byte QUIC varint, RFC 9000 section 16 -- values 0-63 fit in one byte with the top two bits
    clear) covering a 1-byte Packet Number plus `payload_and_tag_len` more bytes standing in for
    the (never-decrypted, so content doesn't matter) protected payload+tag -- Length must total at
    least 17 (1-byte Packet Number + 16-byte AEAD tag minimum) to pass quic.cpp's own check."""
    pn_length = 1
    length_value = pn_length + payload_and_tag_len
    assert length_value < 64, "keep this fixture's Length field a 1-byte varint for simplicity"
    return bytes([length_value]) + bytes(length_value)  # Length varint, then PN + payload/tag bytes


def retry_trailer(token_len: int = 4) -> bytes:
    """A structurally self-consistent trailer for a Retry long-header packet: an arbitrary-length
    Retry Token followed by the mandatory 16-byte Retry Integrity Tag (RFC 9000 section 17.2.5) --
    quic.cpp's own check only requires at least 16 trailing bytes total, so the split between
    "token" and "tag" bytes below is illustrative, not itself checked."""
    return bytes(token_len) + bytes(16)


def version_negotiation_packet(dcid: bytes, scid: bytes, versions: list) -> bytes:
    byte0 = 0x80  # header form=1; the rest of this byte is unused by spec for a VN packet
    body = bytes([byte0]) + struct.pack("!I", 0) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    for v in versions:
        body += struct.pack("!I", v)
    return body


def build_quic_sample():
    packets = []

    def add_udp(payload: bytes, sport: int = 54100, dport: int = 443):
        udp = msp.udp_header(sport, dport, payload)
        ip = msp.ipv4_header(msp.HMI_IP, msp.PLC_IP, 17, len(udp), 0x7300 + len(packets))
        packets.append(msp.eth_header(msp.PLC_MAC, msp.HMI_MAC, 0x0800) + ip + udp)

    dcid = bytes([0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71])
    scid = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])

    # 1) A genuine client Initial packet -- decrypted, ClientHello SNI extracted.
    plaintext = client_initial_plaintext("scada-vendor-cloud.example.com")
    add_udp(build_quic_initial_packet(dcid, scid, plaintext), sport=54100)

    # 2) Version Negotiation -- named only, no decrypt attempted; two supported versions offered.
    add_udp(version_negotiation_packet(dcid, scid, [1, 0x6B3343CF]), sport=54101)

    # 3) Handshake packet (long_type=2) -- named only (ServerHello onward; never another
    #    ClientHello, and encrypted under Handshake-level keys this decoder never has). Needs a
    #    structurally self-consistent Length field (see the post-fix-bug comment on
    #    zero_rtt_or_handshake_trailer/try_recognize_quic's own comment in quic.cpp).
    add_udp(minimal_long_header(0b10, dcid, scid, trailer=zero_rtt_or_handshake_trailer()), sport=54102)

    # 4) 0-RTT packet (long_type=1) -- named only (needs the connection's own resumption secret).
    add_udp(minimal_long_header(0b01, dcid, scid, trailer=zero_rtt_or_handshake_trailer()), sport=54103)

    # 5) Retry packet (long_type=3) -- named only (no protected payload at all in a real Retry).
    #    Needs the mandatory 16-byte Retry Integrity Tag (see retry_trailer()'s own comment).
    add_udp(minimal_long_header(0b11, dcid, scid, trailer=retry_trailer()), sport=54104)

    # 6) Short-header (1-RTT) packet on the default QUIC port -- the weakest-gate, port-only
    #    fallback (Fixed Bit set, nothing else checkable once the handshake has completed).
    add_udp(bytes([0x40]) + bytes(range(20)), sport=54105)

    # 7) An Initial packet that LOOKS well-formed but was encrypted under a different DCID's keys
    #    than the one in its own header -- simulates anything that isn't the client's own first
    #    Initial (a server's reply, most realistically -- see quic.hpp's own file header comment
    #    for why only the client's own packet is ever actually decryptable here). AEAD tag
    #    verification must fail cleanly, falling back to "recognized, not decrypted".
    other_dcid = bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88])
    mismatched = build_quic_initial_packet(dcid, scid, client_initial_plaintext("unreachable.invalid"),
                                            derive_keys_from=other_dcid)
    add_udp(mismatched, sport=54106)

    # 8) Not QUIC at all -- Header Form bit AND Fixed Bit both clear -- must fall through to the
    #    generic "udp" tag, not be misdetected as a short-header QUIC packet. Byte 1 is pinned to
    #    0x99 (not one of HART-IP's own 5 valid MessageType values 0/1/2/3/15) rather than left as
    #    part of a plain bytes(range(...)) fill: an earlier version of this fixture used 0x00 there,
    #    which -- entirely by accident of the arbitrary filler chosen, not a real protocol-level
    #    collision -- also happened to be a valid HART-IP MessageType/MessageID/MsgLength, making
    #    this packet misdetect as [hartip] instead of falling through to generic udp as intended.
    add_udp(bytes([0x00, 0x99]) + bytes(range(2, 16)), sport=54107)

    # 9) Short-header (1-RTT) packet again, same shape as #6, but on a non-standard port (34567,
    #    neither of the two default QUIC ports nor a port any other fixture packet uses) -- proves
    #    try_recognize_quic's own internal port gate for this weakest fallback: falls through to
    #    generic "udp" by default, and is recognized only once --lateral-movement-port widens the
    #    expected range to include it (see quic_extra_port_widens_short_header_match's own comment).
    #    Byte 1 is pinned to 0x99 for the same reason packet #8's is -- a plain bytes(range(...))
    #    fill starting at 0 coincidentally re-creates a valid HART-IP MessageType/MessageID/
    #    MsgLength at this byte range too (HART-IP's UDP dispatch has no port exclusion for 34567,
    #    unlike QUIC's own hardened byte-range collision with HART-IP on 443 -- see decoder.cpp's
    #    dispatch-ordering comment -- so on a port QUIC doesn't structurally out-prioritize, this
    #    fixture must simply avoid the coincidence rather than rely on ordering to resolve it).
    add_udp(bytes([0x40, 0x99]) + bytes(range(2, 21)), sport=54108, dport=34567)

    # 10) Regression fixture for the bug fix above (see quic.cpp's own comment on
    #     try_recognize_quic): a 0-RTT-shaped long-header packet whose byte0 satisfies Header
    #     Form/Fixed Bit/type bits -- exactly what this decoder used to accept unconditionally --
    #     but whose trailer is the SAME too-short, structurally-inconsistent shape packets #3/#4
    #     used before this fix (just 4 zero bytes, no self-consistent Length field). This is the
    #     general shape of collision a real capture surfaced in the wild: a busy NBT-NS (UDP port
    #     137) broadcast segment's own 2-byte Transaction ID landing on byte0/byte1 here just as
    #     easily as any other arbitrary UDP traffic's leading bytes could. Must now fall through to
    #     the generic "udp" tag rather than being misdetected as [quic] -- and, since this packet is
    #     specifically designed to fall all the way through QUIC's own check, it uses a version
    #     value (0x12345678, arbitrary and deliberately non-QUIC-v1) whose first byte (0x12) is NOT
    #     one of HART-IP's own 5 valid MessageType values {0,1,2,3,15} -- avoiding the SAME
    #     documented, systematic QUIC/HART-IP byte-position collision this section's own header
    #     comment describes for QUIC v1's Version field specifically (0x00000001's first two bytes,
    #     0x00/0x00, are themselves both valid MessageType/MessageID values) -- a real QUIC v1
    #     packet never reaches this fall-through path at all (recognized by QUIC first), but a
    #     deliberately-QUIC-v1-shaped negative-control fixture like this one otherwise would, which
    #     would test the wrong thing (HART-IP's own already-documented collision hazard, not this
    #     bug fix).
    add_udp(minimal_long_header(0b01, dcid, scid, version=0x12345678, trailer=bytes(4)), sport=54109)

    # 11) Regression fixture, round two (Jurgen's own second report against the same real NBT-NS
    #     capture): an Initial-shaped long-header packet (byte0 satisfies Header Form/Fixed Bit/
    #     type==Initial) whose trailer decodes to a Token Length of 0 immediately followed by a
    #     Length field that ALSO decodes to 0 -- exactly the shape try_recognize_quic's own Initial
    #     branch used to wave through as "truncated capture" before this round's fix (a length_field
    #     of 0 can never hold the mandatory 1-byte Packet Number + 16-byte AEAD tag, so it isn't a
    #     truncated real Initial packet at all, just an inconsistent field -- see quic.cpp's own
    #     comment). This is the literal shape of one of the two NBT-NS collision groups the real
    #     capture contained: NBT-NS's own Flags/QDCOUNT bytes, read as this Token-Length/Length-field
    #     pair, happened to decode to 0/0. Must now fall through to the generic "udp" tag. Same
    #     HART-IP-collision-avoidance version value as packet #10, for the same reason.
    add_udp(minimal_long_header(0b00, dcid, scid, version=0x12345678, trailer=bytes([0x00, 0x00])),
            sport=54110)

    # 12) Regression fixture, round two, the other NBT-NS collision group: a Retry-shaped long-header
    #     packet (byte0 satisfies Header Form/Fixed Bit/type==Retry) with a fully self-consistent
    #     16-byte trailer -- exactly what round one's own Retry check required and considered
    #     sufficient -- but a Version field that is NOT QUIC v1 (0x12345678, arbitrary). Retry has no
    #     Length field of its own to cross-check (see quic.cpp's own comment on why not), so round
    #     one's fix left it checking only "are there 16 trailing bytes," true of nearly any
    #     ordinary-sized UDP payload; round two adds an exact Version match, the one field Retry does
    #     have that a real capture's NBT-NS traffic never coincidentally lands on. Must now fall
    #     through to the generic "udp" tag rather than being misdetected as [quic].
    add_udp(minimal_long_header(0b11, dcid, scid, version=0x12345678, trailer=retry_trailer()),
            sport=54111)

    # 13) Positive control for round two's Initial fix: a GENUINELY truncated real QUIC v1 Initial
    #     packet -- Token Length 0, then a Length field that decodes to a large, entirely plausible
    #     value (1200, comfortably >= the 17-byte minimum), but with only a handful of bytes actually
    #     following it in the capture (nowhere near the 1200 the Length field declares). Proves round
    #     two's split of the old combined check didn't overcorrect: a length_field that IS plausible
    #     but wasn't fully captured must still produce the tolerant "truncated capture" name-only
    #     match, exactly as it did before this round's fix -- only the previously-conflated
    #     `length_field < 17` case (packet #11 above) was ever meant to change.
    _truncated_trailer = quic_varint(0) + quic_varint(1200, force_2byte=True) + bytes(5)
    add_udp(minimal_long_header(0b00, dcid, scid, trailer=_truncated_trailer), sport=54112)

    data = msp.pcap_global_header()
    for i, pkt in enumerate(packets):
        data += msp.pcap_record(pkt, 1_700_038_000 + i, i * 1000)
    (msp.TESTS_DIR / "sample_quic.pcap").write_bytes(data)
    print("wrote", msp.TESTS_DIR / "sample_quic.pcap")


if __name__ == "__main__":
    msp.TESTS_DIR.mkdir(exist_ok=True)
    build_quic_sample()
