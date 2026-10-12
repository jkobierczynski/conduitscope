#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generates the TLS-decryption test fixtures under tests/ (ROADMAP item 150 --
docs/DEVELOPMENT.md, --tls-keylog/pcapng-DSB decryption for MQTTS/FOXS/WinRM-over-HTTPS).

Deliberately NOT folded into tools/make_sample_pcap.py, and deliberately NOT stdlib-only like
that script insists on being for every other fixture: producing a session this project's own
tls_decrypt.cpp can actually decrypt means generating REAL AES-128/256-GCM and ChaCha20-Poly1305
ciphertext under real HKDF/PRF-derived keys -- hand-rolling an AEAD cipher in pure Python purely
to avoid a test-only dependency would be exactly the "reinvent a primitive instead of reusing a
trusted implementation" mistake this very feature's own crypto-approach decision (OpenSSL over
extending the hand-rolled aes128.hpp/hkdf.hpp quartet, see tls_decrypt.hpp's file header) already
rejected -- so this script depends on the `cryptography` package (already a hard dependency of
this project's own standalone verification harnesses during development; `pip install
cryptography` if regenerating). Every other fixture generator keeps make_sample_pcap.py's
stdlib-only promise untouched.

Run from the repository root (regenerates only the tests/sample_tls_*.pcap(ng)/*_keylog.txt files
below -- it never touches any fixture make_sample_pcap.py itself owns):
    python3 tools/gen_tls_decrypt_fixtures.py

Produces:
  tests/sample_tls_mqtts.pcap          -- MQTTS (port 8883), TLS 1.3, TLS_AES_128_GCM_SHA256,
                                           real MQTT v3.1.1 CONNECT/CONNACK as the app data.
  tests/sample_tls_mqtts_keylog.txt    -- the matching --tls-keylog file (4 TLS 1.3 secrets).
  tests/sample_tls_winrms.pcap         -- WinRM-over-HTTPS (port 5986), TLS 1.2,
                                           TLS_RSA_WITH_AES_256_GCM_SHA384, a real WS-Management
                                           SOAP Create request/response as the app data.
  tests/sample_tls_winrms_keylog.txt   -- the matching --tls-keylog file (1 CLIENT_RANDOM line).
  tests/sample_tls_foxs.pcap           -- FOXS (port 4911), TLS 1.3, TLS_CHACHA20_POLY1305_SHA256,
                                           a real Fox `hello` request/reply as the app data.
  tests/sample_tls_foxs_keylog.txt     -- the matching --tls-keylog file.
  tests/sample_tls_dsb.pcapng          -- a second, independent MQTTS session (its own fresh
                                           client_random/keys), secrets embedded as a pcapng
                                           Decryption Secrets Block INSIDE the capture itself --
                                           decodable with NO --tls-keylog flag at all.
  tests/sample_tls_unsupported_cipher.pcap -- a TLS 1.2 ClientHello/ServerHello negotiating a CBC
                                           suite (0xC013) this build deliberately does not decrypt,
                                           WITH a matching keylog entry -- proves the "negotiated a
                                           cipher suite this build does not decrypt" give-up path,
                                           not just the simpler "no matching key" one.
  tests/sample_tls_4tuple_reuse.pcap   -- ROADMAP item 157 (docs/DEVELOPMENT.md), patch315 security
                                           review finding F3: TWO independent, genuinely fresh TLS
                                           1.3 MQTTS sessions (each its own client_random/server_
                                           random/derived keys, each its own real MQTT v3.1.1
                                           CONNECT/CONNACK) on the EXACT SAME TCP 4-tuple, with a
                                           bare SYN (no ACK) in between positively marking the
                                           second one as a brand-new connection -- proves the second
                                           session's own ClientHello is recognized and decrypted on
                                           its own terms rather than silently inheriting the first
                                           session's now-stale TlsSessionState (handshake_resolved/
                                           keys_derived/epoch/sequence numbers all already set).
  tests/sample_tls_4tuple_reuse_keylog.txt -- the matching --tls-keylog file (both sessions' own
                                           4 TLS 1.3 secrets each, 8 lines total).

Every produced ciphertext round-trips through this same script's own independent HKDF/PRF+AEAD
implementation (via the `cryptography` package) -- not through conduitscope's own tls_decrypt.cpp
-- exactly the "verified against an independent implementation, not just the engine's own code"
discipline tls_decrypt.cpp's own development already followed (see the TLS decrypt ROADMAP item's
own verification notes).

CAUTION, learned the hard way while adding this script's own 6th fixture (ROADMAP item 157): every
builder here uses `secrets.token_bytes()` with no fixed seed, so re-running `__main__` regenerates
EVERY fixture's random/key material from scratch, not just the one you actually meant to change --
and tests/sample_tls_keylog_many_entries_then_mqtts.txt (built by hand for ROADMAP item 153, NOT by
this script) hand-embeds sample_tls_mqtts.pcap's own exact client_random/secrets as its own last 4
lines, so blindly re-running this whole script silently desyncs that hand-built file from a freshly
regenerated sample_tls_mqtts.pcap/sample_tls_mqtts_keylog.txt (loudly, not silently, in the sense
that item 153's own CTest entries that depend on it would then fail -- but still a real, easy-to-
trip footgun). If you only need to add or change ONE fixture, call that one builder function
directly (e.g. `python3 -c "import tools.gen_tls_decrypt_fixtures as g; g.build_4tuple_reuse_
fixture()"` from the repo root) rather than running this file's own `__main__`, and if you must
regenerate sample_tls_mqtts.pcap/sample_tls_mqtts_keylog.txt specifically, regenerate
sample_tls_keylog_many_entries_then_mqtts.txt's own last 4 lines from the new keylog file's content
in the same pass."""
import importlib.util
import pathlib
import secrets
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests"

# Load make_sample_pcap.py as a module (not a package import -- it has no __init__.py) so this
# script can reuse its low-level frame builders (tcp_header/ipv4_header/eth_header/pcap_record/
# pcapng_*) and its real MQTT/Fox payload builders (mqtt_packet/mqtt_str/mqtt_bin, fox_header/
# fox_frame/fox_tuple) instead of duplicating any of them. Guarded by `if __name__ == "__main__"`
# at its own bottom, so importing it runs no code.
_spec = importlib.util.spec_from_file_location("make_sample_pcap", ROOT / "tools" / "make_sample_pcap.py")
msp = importlib.util.module_from_spec(_spec)
sys.modules["make_sample_pcap"] = msp
_spec.loader.exec_module(msp)

HMI_MAC, PLC_MAC = msp.HMI_MAC, msp.PLC_MAC
HMI_IP, PLC_IP = msp.HMI_IP, msp.PLC_IP
TCP_PSH, TCP_ACK = msp.TCP_PSH, msp.TCP_ACK

MQTT_TLS_PORT = 8883
WINRM_TLS_PORT = 5986
FOX_TLS_PORT = 4911

PCAPNG_SECRETS_TYPE_TLS = 0x544C534B  # "TLSK" -- see tools/make_sample_pcap.py's own constant.


# --- shared TLS record-layer helpers (independent of conduitscope's own tls_decrypt.cpp) --------

def handshake_msg(hs_type: int, body: bytes) -> bytes:
    return bytes([hs_type]) + len(body).to_bytes(3, "big") + body


def cleartext_record(content_type: int, body: bytes) -> bytes:
    return bytes([content_type, 0x03, 0x03]) + struct.pack(">H", len(body)) + body


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label
    info = (struct.pack(">H", length) + bytes([len(full_label)]) + full_label +
            bytes([len(context)]) + context)
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def nonce_for(iv: bytes, seq: int) -> bytes:
    seq_bytes = seq.to_bytes(8, "big")
    n = bytearray(iv)
    for i in range(8):
        n[4 + i] ^= seq_bytes[i]
    return bytes(n)


def tls13_record(aead_cls, content_type: int, key: bytes, iv: bytes, seq: int, inner_content: bytes,
                  inner_type: int) -> bytes:
    plaintext = inner_content + bytes([inner_type])
    aad = bytes([content_type, 0x03, 0x03]) + struct.pack(">H", len(plaintext) + 16)
    ct = aead_cls(key).encrypt(nonce_for(iv, seq), plaintext, aad)
    return bytes([content_type, 0x03, 0x03]) + struct.pack(">H", len(ct)) + ct


def hmac_once(secret: bytes, data: bytes, hashalg) -> bytes:
    h = HMAC(secret, hashalg)
    h.update(data)
    return h.finalize()


def tls12_prf(secret: bytes, label: bytes, seed: bytes, length: int, hashalg) -> bytes:
    seed = label + seed
    result = b""
    a = hmac_once(secret, seed, hashalg)
    while len(result) < length:
        result += hmac_once(secret, a + seed, hashalg)
        a = hmac_once(secret, a, hashalg)
    return result[:length]


def tls12_gcm_record(content_type: int, key: bytes, iv_salt: bytes, seq: int, plaintext: bytes) -> bytes:
    explicit_nonce = secrets.token_bytes(8)
    nonce = iv_salt + explicit_nonce
    aad = seq.to_bytes(8, "big") + bytes([content_type, 0x03, 0x03]) + struct.pack(">H", len(plaintext))
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    body = explicit_nonce + ct
    return bytes([content_type, 0x03, 0x03]) + struct.pack(">H", len(body)) + body


# --- a tiny bidirectional-TCP-session helper, mirroring amqp_tcp_session's own closure shape -----

def tcp_session(packets: list, ident_box: list, port_a: int, port_b: int):
    state = {"aseq": 4000, "bseq": 8000}

    def next_ident() -> int:
        v = ident_box[0]
        ident_box[0] += 1
        return v & 0xFFFF

    def client_to_server(payload: bytes):
        tcp = msp.tcp_header(port_a, port_b, state["aseq"], state["bseq"], TCP_PSH | TCP_ACK,
                              len(payload)) + payload
        ip = msp.ipv4_header(HMI_IP, PLC_IP, 6, len(tcp), next_ident())
        packets.append(msp.eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip + tcp)
        state["aseq"] += len(payload)

    def server_to_client(payload: bytes):
        tcp = msp.tcp_header(port_b, port_a, state["bseq"], state["aseq"], TCP_PSH | TCP_ACK,
                              len(payload)) + payload
        ip = msp.ipv4_header(PLC_IP, HMI_IP, 6, len(tcp), next_ident())
        packets.append(msp.eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip + tcp)
        state["bseq"] += len(payload)

    return client_to_server, server_to_client


def write_pcap(packets: list, path: pathlib.Path):
    data = msp.pcap_global_header()
    for i, pkt in enumerate(packets):
        data += msp.pcap_record(pkt, 1_700_300_000 + i, i * 1000)
    path.write_bytes(data)
    print("wrote", path)


# --- WinRM SOAP-over-HTTP payload (minimal, mirrors make_sample_pcap.py's build_winrm_sample's own
#     soap_envelope()/http_message() shape, inlined here since those are local closures there) -----

def winrm_soap_envelope(action: str, resource_uri: str, selector_set_xml: str, body_xml: str) -> bytes:
    xml = (
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" '
        'xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">'
        "<s:Header>"
        "<a:To>https://192.168.1.10:5986/wsman</a:To>"
        "<a:ReplyTo><a:Address mustUnderstand=\"true\">"
        "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
        f'<a:Action mustUnderstand="true">{action}</a:Action>'
        f"<w:ResourceURI>{resource_uri}</w:ResourceURI>"
        '<w:MaxEnvelopeSize mustUnderstand="true">512000</w:MaxEnvelopeSize>'
        "<a:MessageID>uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</a:MessageID>"
        "<w:OperationTimeout>PT60S</w:OperationTimeout>"
        f"{selector_set_xml}"
        "</s:Header>"
        f"<s:Body>{body_xml}</s:Body>"
        "</s:Envelope>"
    )
    return xml.encode("utf-8")


def http_message(start_line: str, headers: list, body: bytes) -> bytes:
    lines = [start_line] + [f"{k}: {v}" for k, v in headers] + [f"Content-Length: {len(body)}"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


# ==================================================================================================
# 1) MQTTS -- TLS 1.3, TLS_AES_128_GCM_SHA256 (0x1301), real MQTT v3.1.1 CONNECT/CONNACK app data.
# ==================================================================================================

def build_mqtts_fixture():
    client_random = secrets.token_bytes(32)
    server_random = secrets.token_bytes(32)
    client_hs_secret = secrets.token_bytes(32)
    server_hs_secret = secrets.token_bytes(32)
    client_app_secret = secrets.token_bytes(32)
    server_app_secret = secrets.token_bytes(32)

    def derive_key_iv(secret):
        return hkdf_expand_label(secret, b"key", b"", 16), hkdf_expand_label(secret, b"iv", b"", 12)

    client_hs_key, client_hs_iv = derive_key_iv(client_hs_secret)
    server_hs_key, server_hs_iv = derive_key_iv(server_hs_secret)
    client_app_key, client_app_iv = derive_key_iv(client_app_secret)
    server_app_key, server_app_iv = derive_key_iv(server_app_secret)

    ch_body = (struct.pack(">H", 0x0303) + client_random + bytes([0]) +
               struct.pack(">H", 2) + bytes([0x13, 0x01]) + bytes([1, 0]) + struct.pack(">H", 0))
    ch_record = cleartext_record(0x16, handshake_msg(1, ch_body))

    ext_supported_versions = struct.pack(">HH", 0x002b, 2) + struct.pack(">H", 0x0304)
    sh_body = (struct.pack(">H", 0x0303) + server_random + bytes([0]) + bytes([0x13, 0x01]) +
               bytes([0]) + struct.pack(">H", len(ext_supported_versions)) + ext_supported_versions)
    sh_record = cleartext_record(0x16, handshake_msg(2, sh_body))

    ee_msg = handshake_msg(8, b"\x00\x00")
    fin_msg_server = handshake_msg(20, secrets.token_bytes(32))
    server_ee_fin_record = tls13_record(AESGCM, 0x17, server_hs_key, server_hs_iv, 0,
                                         ee_msg + fin_msg_server, 0x16)

    fin_msg_client = handshake_msg(20, secrets.token_bytes(32))
    client_fin_record = tls13_record(AESGCM, 0x17, client_hs_key, client_hs_iv, 0, fin_msg_client, 0x16)

    # Real MQTT v3.1.1 CONNECT (clean session, 60s keepalive, client id) / CONNACK (accepted).
    connect_body = (msp.mqtt_str("MQTT") + bytes([4]) + bytes([0x02]) + struct.pack(">H", 60) +
                    msp.mqtt_str("plc1-hmi-tls"))
    connect_plain = msp.mqtt_packet(1, 0, connect_body)
    connack_plain = msp.mqtt_packet(2, 0, bytes([0x00, 0x00]))
    client_app_record = tls13_record(AESGCM, 0x17, client_app_key, client_app_iv, 0, connect_plain, 0x17)
    server_app_record = tls13_record(AESGCM, 0x17, server_app_key, server_app_iv, 0, connack_plain, 0x17)

    packets, ident_box = [], [0xA100]
    client, server = tcp_session(packets, ident_box, 52000, MQTT_TLS_PORT)
    client(ch_record)
    server(sh_record)
    server(server_ee_fin_record)
    client(client_fin_record)
    client(client_app_record)
    server(server_app_record)
    write_pcap(packets, TESTS_DIR / "sample_tls_mqtts.pcap")

    keylog = (
        f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {client_random.hex()} {client_hs_secret.hex()}\n"
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {client_random.hex()} {server_hs_secret.hex()}\n"
        f"CLIENT_TRAFFIC_SECRET_0 {client_random.hex()} {client_app_secret.hex()}\n"
        f"SERVER_TRAFFIC_SECRET_0 {client_random.hex()} {server_app_secret.hex()}\n"
    )
    (TESTS_DIR / "sample_tls_mqtts_keylog.txt").write_text(keylog)
    print("wrote", TESTS_DIR / "sample_tls_mqtts_keylog.txt")
    return client_random, keylog


# ==================================================================================================
# 2) WinRM-over-HTTPS -- TLS 1.2, TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009D), a real WS-Management
#    Create request/response (shell-opened) as the app data.
# ==================================================================================================

def build_winrms_fixture():
    client_random = secrets.token_bytes(32)
    server_random = secrets.token_bytes(32)
    master_secret = secrets.token_bytes(48)
    cipher_suite_be = bytes([0x00, 0x9D])  # TLS_RSA_WITH_AES_256_GCM_SHA384

    seed = server_random + client_random
    key_len = 32
    key_block = tls12_prf(master_secret, b"key expansion", seed, 2 * (key_len + 4), hashes.SHA384())
    off = 0
    client_write_key = key_block[off:off + key_len]; off += key_len
    server_write_key = key_block[off:off + key_len]; off += key_len
    client_write_iv = key_block[off:off + 4]; off += 4
    server_write_iv = key_block[off:off + 4]; off += 4

    ch_body = (struct.pack(">H", 0x0303) + client_random + bytes([0]) +
               struct.pack(">H", 2) + cipher_suite_be + bytes([1, 0]) + struct.pack(">H", 0))
    ch_record = cleartext_record(0x16, handshake_msg(1, ch_body))
    sh_body = (struct.pack(">H", 0x0303) + server_random + bytes([0]) + cipher_suite_be +
               bytes([0]) + struct.pack(">H", 0))
    sh_record = cleartext_record(0x16, handshake_msg(2, sh_body))
    ccs_client = cleartext_record(0x14, bytes([1]))
    ccs_server = cleartext_record(0x14, bytes([1]))

    client_fin_record = tls12_gcm_record(0x16, client_write_key, client_write_iv, 0,
                                          handshake_msg(20, secrets.token_bytes(12)))
    server_fin_record = tls12_gcm_record(0x16, server_write_key, server_write_iv, 0,
                                          handshake_msg(20, secrets.token_bytes(12)))

    create_body = (
        '<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams>'
        '<rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>'
    )
    create_req_xml = winrm_soap_envelope(
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd", "", create_body)
    create_req = http_message(
        "POST /wsman HTTP/1.1",
        [("Host", "192.168.1.10:5986"), ("Content-Type", "application/soap+xml;charset=UTF-8"),
         ("Authorization", "Negotiate")], create_req_xml)

    create_resp_body = (
        '<x:ResourceCreated><a:Address>https://192.168.1.10:5986/wsman</a:Address>'
        '<a:ReferenceParameters><w:ResourceURI>'
        'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>'
        '<w:SelectorSet><w:Selector Name="ShellId">A1B2C3D4-0001-0002-0003-000400050006'
        '</w:Selector></w:SelectorSet></a:ReferenceParameters></x:ResourceCreated>'
        '<rsp:Shell><rsp:ShellId>A1B2C3D4-0001-0002-0003-000400050006</rsp:ShellId></rsp:Shell>'
    )
    create_resp_xml = winrm_soap_envelope(
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse",
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd", "", create_resp_body)
    create_resp = http_message("HTTP/1.1 200 OK",
                                [("Content-Type", "application/soap+xml;charset=UTF-8")], create_resp_xml)

    client_app_record = tls12_gcm_record(0x17, client_write_key, client_write_iv, 1, create_req)
    server_app_record = tls12_gcm_record(0x17, server_write_key, server_write_iv, 1, create_resp)

    packets, ident_box = [], [0xB200]
    client, server = tcp_session(packets, ident_box, 53000, WINRM_TLS_PORT)
    client(ch_record)
    server(sh_record)
    client(ccs_client)
    client(client_fin_record)
    server(ccs_server)
    server(server_fin_record)
    client(client_app_record)
    server(server_app_record)
    write_pcap(packets, TESTS_DIR / "sample_tls_winrms.pcap")

    keylog = f"CLIENT_RANDOM {client_random.hex()} {master_secret.hex()}\n"
    (TESTS_DIR / "sample_tls_winrms_keylog.txt").write_text(keylog)
    print("wrote", TESTS_DIR / "sample_tls_winrms_keylog.txt")


# ==================================================================================================
# 3) FOXS -- TLS 1.3, TLS_CHACHA20_POLY1305_SHA256 (0x1303), a real Fox `hello` request/reply.
# ==================================================================================================

def build_foxs_fixture():
    client_random = secrets.token_bytes(32)
    server_random = secrets.token_bytes(32)
    client_hs_secret = secrets.token_bytes(32)
    server_hs_secret = secrets.token_bytes(32)
    client_app_secret = secrets.token_bytes(32)
    server_app_secret = secrets.token_bytes(32)

    def derive_key_iv(secret):
        return hkdf_expand_label(secret, b"key", b"", 32), hkdf_expand_label(secret, b"iv", b"", 12)

    client_hs_key, client_hs_iv = derive_key_iv(client_hs_secret)
    server_hs_key, server_hs_iv = derive_key_iv(server_hs_secret)
    client_app_key, client_app_iv = derive_key_iv(client_app_secret)
    server_app_key, server_app_iv = derive_key_iv(server_app_secret)

    ch_body = (struct.pack(">H", 0x0303) + client_random + bytes([0]) +
               struct.pack(">H", 2) + bytes([0x13, 0x03]) + bytes([1, 0]) + struct.pack(">H", 0))
    ch_record = cleartext_record(0x16, handshake_msg(1, ch_body))
    ext_supported_versions = struct.pack(">HH", 0x002b, 2) + struct.pack(">H", 0x0304)
    sh_body = (struct.pack(">H", 0x0303) + server_random + bytes([0]) + bytes([0x13, 0x03]) +
               bytes([0]) + struct.pack(">H", len(ext_supported_versions)) + ext_supported_versions)
    sh_record = cleartext_record(0x16, handshake_msg(2, sh_body))

    ee_msg = handshake_msg(8, b"\x00\x00")
    fin_msg_server = handshake_msg(20, secrets.token_bytes(32))
    server_ee_fin_record = tls13_record(ChaCha20Poly1305, 0x17, server_hs_key, server_hs_iv, 0,
                                         ee_msg + fin_msg_server, 0x16)
    fin_msg_client = handshake_msg(20, secrets.token_bytes(32))
    client_fin_record = tls13_record(ChaCha20Poly1305, 0x17, client_hs_key, client_hs_iv, 0,
                                      fin_msg_client, 0x16)

    hello_rq_tuples = (
        msp.fox_tuple("fox.version", "s", "1.0") + msp.fox_tuple("id", "s", "1") +
        msp.fox_tuple("hostName", "s", "ENGINEER-LAPTOP-TLS") +
        msp.fox_tuple("hostAddress", "s", HMI_IP) + msp.fox_tuple("app.name", "s", "Workbench") +
        msp.fox_tuple("brandId", "s", "niagara")
    )
    hello_rq = msp.fox_frame(msp.fox_header("a", 1, -1, "fox", "hello"), hello_rq_tuples)
    hello_ac_tuples = (
        msp.fox_tuple("fox.version", "s", "1.0") + msp.fox_tuple("id", "s", "1") +
        msp.fox_tuple("hostName", "s", "NIAGARA-STATION-TLS") +
        msp.fox_tuple("hostAddress", "s", PLC_IP) + msp.fox_tuple("app.name", "s", "Station") +
        msp.fox_tuple("brandId", "s", "tridium")
    )
    hello_ac = msp.fox_frame(msp.fox_header("r", 100, 1, "fox", "hello"), hello_ac_tuples)

    client_app_record = tls13_record(ChaCha20Poly1305, 0x17, client_app_key, client_app_iv, 0,
                                      hello_rq, 0x17)
    server_app_record = tls13_record(ChaCha20Poly1305, 0x17, server_app_key, server_app_iv, 0,
                                      hello_ac, 0x17)

    packets, ident_box = [], [0xC300]
    client, server = tcp_session(packets, ident_box, 54000, FOX_TLS_PORT)
    client(ch_record)
    server(sh_record)
    server(server_ee_fin_record)
    client(client_fin_record)
    client(client_app_record)
    server(server_app_record)
    write_pcap(packets, TESTS_DIR / "sample_tls_foxs.pcap")

    keylog = (
        f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {client_random.hex()} {client_hs_secret.hex()}\n"
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {client_random.hex()} {server_hs_secret.hex()}\n"
        f"CLIENT_TRAFFIC_SECRET_0 {client_random.hex()} {client_app_secret.hex()}\n"
        f"SERVER_TRAFFIC_SECRET_0 {client_random.hex()} {server_app_secret.hex()}\n"
    )
    (TESTS_DIR / "sample_tls_foxs_keylog.txt").write_text(keylog)
    print("wrote", TESTS_DIR / "sample_tls_foxs_keylog.txt")


# ==================================================================================================
# 4) A second, independent MQTTS session with its secrets embedded via a pcapng Decryption Secrets
#    Block instead of an external --tls-keylog file -- proves the DSB-ingestion path end to end.
# ==================================================================================================

def build_dsb_fixture():
    client_random = secrets.token_bytes(32)
    server_random = secrets.token_bytes(32)
    client_hs_secret = secrets.token_bytes(32)
    server_hs_secret = secrets.token_bytes(32)
    client_app_secret = secrets.token_bytes(32)
    server_app_secret = secrets.token_bytes(32)

    def derive_key_iv(secret):
        return hkdf_expand_label(secret, b"key", b"", 16), hkdf_expand_label(secret, b"iv", b"", 12)

    client_hs_key, client_hs_iv = derive_key_iv(client_hs_secret)
    server_hs_key, server_hs_iv = derive_key_iv(server_hs_secret)
    client_app_key, client_app_iv = derive_key_iv(client_app_secret)
    server_app_key, server_app_iv = derive_key_iv(server_app_secret)

    ch_body = (struct.pack(">H", 0x0303) + client_random + bytes([0]) +
               struct.pack(">H", 2) + bytes([0x13, 0x01]) + bytes([1, 0]) + struct.pack(">H", 0))
    ch_record = cleartext_record(0x16, handshake_msg(1, ch_body))
    ext_supported_versions = struct.pack(">HH", 0x002b, 2) + struct.pack(">H", 0x0304)
    sh_body = (struct.pack(">H", 0x0303) + server_random + bytes([0]) + bytes([0x13, 0x01]) +
               bytes([0]) + struct.pack(">H", len(ext_supported_versions)) + ext_supported_versions)
    sh_record = cleartext_record(0x16, handshake_msg(2, sh_body))

    ee_msg = handshake_msg(8, b"\x00\x00")
    fin_msg_server = handshake_msg(20, secrets.token_bytes(32))
    server_ee_fin_record = tls13_record(AESGCM, 0x17, server_hs_key, server_hs_iv, 0,
                                         ee_msg + fin_msg_server, 0x16)
    fin_msg_client = handshake_msg(20, secrets.token_bytes(32))
    client_fin_record = tls13_record(AESGCM, 0x17, client_hs_key, client_hs_iv, 0, fin_msg_client, 0x16)

    connect_body = (msp.mqtt_str("MQTT") + bytes([4]) + bytes([0x02]) + struct.pack(">H", 30) +
                    msp.mqtt_str("dsb-sourced-client"))
    connect_plain = msp.mqtt_packet(1, 0, connect_body)
    connack_plain = msp.mqtt_packet(2, 0, bytes([0x00, 0x00]))
    client_app_record = tls13_record(AESGCM, 0x17, client_app_key, client_app_iv, 0, connect_plain, 0x17)
    server_app_record = tls13_record(AESGCM, 0x17, server_app_key, server_app_iv, 0, connack_plain, 0x17)

    packets, ident_box = [], [0xD400]
    client, server = tcp_session(packets, ident_box, 55000, MQTT_TLS_PORT)
    client(ch_record)
    server(sh_record)
    server(server_ee_fin_record)
    client(client_fin_record)
    client(client_app_record)
    server(server_app_record)

    keylog = (
        f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {client_random.hex()} {client_hs_secret.hex()}\n"
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {client_random.hex()} {server_hs_secret.hex()}\n"
        f"CLIENT_TRAFFIC_SECRET_0 {client_random.hex()} {client_app_secret.hex()}\n"
        f"SERVER_TRAFFIC_SECRET_0 {client_random.hex()} {server_app_secret.hex()}\n"
    ).encode("ascii")

    data = msp.pcapng_shb() + msp.pcapng_idb() + msp.pcapng_dsb(PCAPNG_SECRETS_TYPE_TLS, keylog)
    for i, pkt in enumerate(packets):
        data += msp.pcapng_epb(0, 1_700_400_000_000_000 + i * 1000, pkt)
    (TESTS_DIR / "sample_tls_dsb.pcapng").write_bytes(data)
    print("wrote", TESTS_DIR / "sample_tls_dsb.pcapng")


# ==================================================================================================
# 5) An unsupported-cipher-suite negative case: TLS 1.2 negotiating a CBC suite (0xC013, TLS_ECDHE_
#    RSA_WITH_AES_128_CBC_SHA) this build deliberately never decrypts (RFC 5288/5289 GCM suites
#    only) -- WITH a matching keylog entry present, so the give-up reason is genuinely "cipher
#    suite", not merely "no matching key" (see tls_decrypt.hpp's own scope). ClientHello/ServerHello
#    only -- there is no key material this script could derive for a cipher it cannot itself
#    implement either, and none is needed: the give-up happens at ServerHello, before any
#    application data would ever be looked at.
# ==================================================================================================

def build_unsupported_cipher_fixture():
    client_random = secrets.token_bytes(32)
    server_random = secrets.token_bytes(32)
    master_secret = secrets.token_bytes(48)  # never actually used to derive keys -- see above.

    ch_body = (struct.pack(">H", 0x0303) + client_random + bytes([0]) +
               struct.pack(">H", 2) + bytes([0xC0, 0x13]) + bytes([1, 0]) + struct.pack(">H", 0))
    ch_record = cleartext_record(0x16, handshake_msg(1, ch_body))
    sh_body = (struct.pack(">H", 0x0303) + server_random + bytes([0]) + bytes([0xC0, 0x13]) +
               bytes([0]) + struct.pack(">H", 0))
    sh_record = cleartext_record(0x16, handshake_msg(2, sh_body))

    packets, ident_box = [], [0xE500]
    client, server = tcp_session(packets, ident_box, 56000, MQTT_TLS_PORT)
    client(ch_record)
    server(sh_record)
    write_pcap(packets, TESTS_DIR / "sample_tls_unsupported_cipher.pcap")

    keylog = f"CLIENT_RANDOM {client_random.hex()} {master_secret.hex()}\n"
    (TESTS_DIR / "sample_tls_unsupported_cipher_keylog.txt").write_text(keylog)
    print("wrote", TESTS_DIR / "sample_tls_unsupported_cipher_keylog.txt")


# ==================================================================================================
# 6) ROADMAP item 157 (docs/DEVELOPMENT.md), patch315 security review finding F3: two independent,
#    genuinely fresh TLS 1.3 MQTTS sessions reusing the EXACT SAME TCP 4-tuple, with a bare SYN (no
#    ACK) marking the second one as a brand-new connection -- see this script's own module-level
#    docstring above for the full rationale. Each session is byte-for-byte the same shape
#    build_mqtts_fixture() above already produces and already proves decrypts correctly on its
#    own -- the only things genuinely new here are (a) a SECOND, completely independent set of
#    random/secret material for session B, (b) both sessions sharing one port pair instead of each
#    getting its own, and (c) the bare SYN packet positively marking the handoff between them.
# ==================================================================================================

def _mqtts_tls13_session(client_random, server_random, client_id: str):
    """Returns (ch_record, sh_record, server_ee_fin_record, client_fin_record, client_app_record,
    server_app_record, keylog_text) for one complete, genuinely fresh TLS 1.3
    TLS_AES_128_GCM_SHA256 MQTTS session -- byte-for-byte build_mqtts_fixture()'s own derivation
    and record construction, factored out so this section can build two independent instances of
    it without duplicating that logic."""
    client_hs_secret = secrets.token_bytes(32)
    server_hs_secret = secrets.token_bytes(32)
    client_app_secret = secrets.token_bytes(32)
    server_app_secret = secrets.token_bytes(32)

    def derive_key_iv(secret):
        return hkdf_expand_label(secret, b"key", b"", 16), hkdf_expand_label(secret, b"iv", b"", 12)

    client_hs_key, client_hs_iv = derive_key_iv(client_hs_secret)
    server_hs_key, server_hs_iv = derive_key_iv(server_hs_secret)
    client_app_key, client_app_iv = derive_key_iv(client_app_secret)
    server_app_key, server_app_iv = derive_key_iv(server_app_secret)

    ch_body = (struct.pack(">H", 0x0303) + client_random + bytes([0]) +
               struct.pack(">H", 2) + bytes([0x13, 0x01]) + bytes([1, 0]) + struct.pack(">H", 0))
    ch_record = cleartext_record(0x16, handshake_msg(1, ch_body))

    ext_supported_versions = struct.pack(">HH", 0x002b, 2) + struct.pack(">H", 0x0304)
    sh_body = (struct.pack(">H", 0x0303) + server_random + bytes([0]) + bytes([0x13, 0x01]) +
               bytes([0]) + struct.pack(">H", len(ext_supported_versions)) + ext_supported_versions)
    sh_record = cleartext_record(0x16, handshake_msg(2, sh_body))

    ee_msg = handshake_msg(8, b"\x00\x00")
    fin_msg_server = handshake_msg(20, secrets.token_bytes(32))
    server_ee_fin_record = tls13_record(AESGCM, 0x17, server_hs_key, server_hs_iv, 0,
                                         ee_msg + fin_msg_server, 0x16)

    fin_msg_client = handshake_msg(20, secrets.token_bytes(32))
    client_fin_record = tls13_record(AESGCM, 0x17, client_hs_key, client_hs_iv, 0, fin_msg_client, 0x16)

    connect_body = (msp.mqtt_str("MQTT") + bytes([4]) + bytes([0x02]) + struct.pack(">H", 60) +
                    msp.mqtt_str(client_id))
    connect_plain = msp.mqtt_packet(1, 0, connect_body)
    connack_plain = msp.mqtt_packet(2, 0, bytes([0x00, 0x00]))
    client_app_record = tls13_record(AESGCM, 0x17, client_app_key, client_app_iv, 0, connect_plain, 0x17)
    server_app_record = tls13_record(AESGCM, 0x17, server_app_key, server_app_iv, 0, connack_plain, 0x17)

    keylog_text = (
        f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {client_random.hex()} {client_hs_secret.hex()}\n"
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {client_random.hex()} {server_hs_secret.hex()}\n"
        f"CLIENT_TRAFFIC_SECRET_0 {client_random.hex()} {client_app_secret.hex()}\n"
        f"SERVER_TRAFFIC_SECRET_0 {client_random.hex()} {server_app_secret.hex()}\n"
    )
    return (ch_record, sh_record, server_ee_fin_record, client_fin_record, client_app_record,
            server_app_record, keylog_text)


def build_4tuple_reuse_fixture():
    reuse_port = 57000  # distinct from every other fixture's own client port in this script.

    client_random_a = secrets.token_bytes(32)
    server_random_a = secrets.token_bytes(32)
    (ch_a, sh_a, ee_fin_a, fin_a, app_a, connack_a, keylog_a) = _mqtts_tls13_session(
        client_random_a, server_random_a, "plc1-hmi-tls-reused-a")

    client_random_b = secrets.token_bytes(32)
    server_random_b = secrets.token_bytes(32)
    (ch_b, sh_b, ee_fin_b, fin_b, app_b, connack_b, keylog_b) = _mqtts_tls13_session(
        client_random_b, server_random_b, "plc1-hmi-tls-reused-b")

    packets, ident_box = [], [0xF600]

    # --- Session A: a complete, ordinary TLS 1.3 MQTTS session (own client/server randoms) -------
    client_a, server_a = tcp_session(packets, ident_box, reuse_port, MQTT_TLS_PORT)
    client_a(ch_a)
    server_a(sh_a)
    server_a(ee_fin_a)
    client_a(fin_a)
    client_a(app_a)
    server_a(connack_a)

    # --- The handoff: a bare SYN (SYN set, ACK clear) on the EXACT SAME 4-tuple -- decoder.cpp's
    # own TCP-segment entry point reads this as "a brand-new TCP connection has positively been
    # observed on this 4-tuple" and bumps that 4-tuple's own TcpConnectionGenerationState, which is
    # what this whole fixture exists to exercise (see tls_session_state_for(), decoder.cpp). Built
    # directly with msp.tcp_header/ipv4_header/eth_header rather than through tcp_session()'s own
    # closures, since those only ever build PSH+ACK data segments -- a bare SYN needs its own
    # one-off construction. The client's new ISN (9000) is deliberately unrelated to session A's
    # own final sequence number -- a real new connection's ISN has no relationship to whatever a
    # prior connection on the same 4-tuple last used, and (see this fixture's own module-level
    # comment) the generic byte-level TCP reassembler never buffers MQTTS traffic across packets
    # for either session here, so this discontinuity is harmless to that unrelated layer.
    syn_tcp = msp.tcp_header(reuse_port, MQTT_TLS_PORT, 9000, 0, msp.TCP_SYN, 0)
    syn_ip = msp.ipv4_header(HMI_IP, PLC_IP, 6, len(syn_tcp), ident_box[0] & 0xFFFF)
    ident_box[0] += 1
    packets.append(msp.eth_header(PLC_MAC, HMI_MAC, 0x0800) + syn_ip + syn_tcp)

    # --- Session B: a SECOND, completely independent TLS 1.3 MQTTS session (fresh client/server
    # randoms, fresh derived keys) reusing the exact same (reuse_port, MQTT_TLS_PORT) 4-tuple. Its
    # own tcp_session() call starts a fresh local seq-number counter (4000/8000, the same starting
    # values session A itself used) -- again harmless, per the same reassembly note above.
    client_b, server_b = tcp_session(packets, ident_box, reuse_port, MQTT_TLS_PORT)
    client_b(ch_b)
    server_b(sh_b)
    server_b(ee_fin_b)
    client_b(fin_b)
    client_b(app_b)
    server_b(connack_b)

    write_pcap(packets, TESTS_DIR / "sample_tls_4tuple_reuse.pcap")
    (TESTS_DIR / "sample_tls_4tuple_reuse_keylog.txt").write_text(keylog_a + keylog_b)
    print("wrote", TESTS_DIR / "sample_tls_4tuple_reuse_keylog.txt")


if __name__ == "__main__":
    build_mqtts_fixture()
    build_winrms_fixture()
    build_foxs_fixture()
    build_dsb_fixture()
    build_unsupported_cipher_fixture()
    build_4tuple_reuse_fixture()
    print("done")
