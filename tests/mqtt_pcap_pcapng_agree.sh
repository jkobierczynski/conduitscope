#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# mqtt_pcap_pcapng_agree.sh -- see CMakeLists.txt's real_mqtt_pcap_and_pcapng_containers_agree and
# tests/real_captures/mqtt/ATTRIBUTION.md. mqtt_packets_tcpdump.pcap and mqtt_packets.pcapng are two
# different container formats of the exact same underlying capture (both from
# pradeesi/MQTT-Wireshark-Capture) -- this asserts this decoder's own JSON output is byte-for-byte
# identical between the two, a small independent regression check that the pcap and pcapng readers
# agree on real, third-party-produced input.
set -eu

CONDUITSCOPE="$1"
PCAP_FILE="$2"
PCAPNG_FILE="$3"

OUT_PCAP="$(mktemp)"
OUT_PCAPNG="$(mktemp)"
trap 'rm -f "$OUT_PCAP" "$OUT_PCAPNG"' EXIT

"$CONDUITSCOPE" decode --read "$PCAP_FILE" --format json > "$OUT_PCAP"
"$CONDUITSCOPE" decode --read "$PCAPNG_FILE" --format json > "$OUT_PCAPNG"

diff "$OUT_PCAP" "$OUT_PCAPNG"
