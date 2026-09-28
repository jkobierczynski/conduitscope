#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# inventory_diagram_and_policy_out.sh -- see CMakeLists.txt's inventory_diagram_and_policy_out_smoke
# test. `inventory --diagram`/`--policy-out` write to a FILE, not stdout, so (like
# mqtt_pcap_pcapng_agree.sh) this drives conduitscope from a shell script and prints every file's
# content to stdout so a single PASS_REGULAR_EXPRESSION in CMakeLists.txt can check all of it,
# including closing the "discover, then enforce" loop for real: the --policy-out file this script
# generates is fed straight back into `policy validate` against the same capture.
set -eu

CONDUITSCOPE="$1"
INVENTORY_PCAP="$2"
EMPTY_PCAP="$3"

MMD="$(mktemp)"
DOT="$(mktemp)"
POLICY="$(mktemp)"
EMPTY_POLICY="$(mktemp)"
ACL_CISCO="$(mktemp)"
ACL_FORTINET="$(mktemp)"
ACL_PALOALTO="$(mktemp)"
EMPTY_ACL="$(mktemp)"
trap 'rm -f "$MMD" "$DOT" "$POLICY" "$EMPTY_POLICY" "$ACL_CISCO" "$ACL_FORTINET" "$ACL_PALOALTO" "$EMPTY_ACL"' EXIT

echo "=== mermaid diagram ==="
"$CONDUITSCOPE" inventory --read "$INVENTORY_PCAP" --diagram "$MMD" --output /dev/null
cat "$MMD"

echo "=== dot diagram ==="
"$CONDUITSCOPE" inventory --read "$INVENTORY_PCAP" --diagram "$DOT" --diagram-format dot --output /dev/null
cat "$DOT"

echo "=== policy-out ==="
"$CONDUITSCOPE" inventory --read "$INVENTORY_PCAP" --policy-out "$POLICY" --output /dev/null
cat "$POLICY"

echo "=== round-trip through policy validate ==="
"$CONDUITSCOPE" policy validate --read "$INVENTORY_PCAP" --policy "$POLICY"

echo "=== empty-capture policy-out ==="
"$CONDUITSCOPE" inventory --read "$EMPTY_PCAP" --policy-out "$EMPTY_POLICY" --output /dev/null
cat "$EMPTY_POLICY"

echo "=== acl-out (cisco) ==="
"$CONDUITSCOPE" inventory --read "$INVENTORY_PCAP" --acl-out "$ACL_CISCO" --output /dev/null
cat "$ACL_CISCO"

echo "=== acl-out (fortinet) ==="
"$CONDUITSCOPE" inventory --read "$INVENTORY_PCAP" --acl-out "$ACL_FORTINET" --acl-format fortinet --output /dev/null
cat "$ACL_FORTINET"

echo "=== acl-out (paloalto) ==="
"$CONDUITSCOPE" inventory --read "$INVENTORY_PCAP" --acl-out "$ACL_PALOALTO" --acl-format paloalto --output /dev/null
cat "$ACL_PALOALTO"

echo "=== empty-capture acl-out ==="
"$CONDUITSCOPE" inventory --read "$EMPTY_PCAP" --acl-out "$EMPTY_ACL" --output /dev/null
cat "$EMPTY_ACL"
