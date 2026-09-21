// SPDX-License-Identifier: Apache-2.0
// notable_it_protocols.hpp - the shared tier lookup for ROADMAP item 18's "IT protocols an OT
// auditor flags" family (it_protocols.hpp's Tiers 1-4, tunnel_vpn.hpp's Tier 5, plus the three
// EtherType-keyed protocols -- eapol.hpp/pppoe.hpp/mpls.hpp -- that live outside both of those
// files), plus QUIC (quic.hpp), which joins Tier 2 alongside HTTPS -- see that file's own file
// header comment for why. `decode` (and, as a normal consequence of protocol dispatch, `policy
// validate`/`inventory` already) has recognized all 43 of these protocol names by their own
// `DecodedPacket::protocol` value since QUIC completed the family -- see docs/DEVELOPMENT.md's
// ROADMAP item 18. What this file adds is the second half of that same item: a single place
// PolicyEngine::observe (policy_engine.cpp) and AssetInventoryEngine::observe (asset_inventory.cpp)
// both call to ask "is this one of the 43 protocols an OT auditor flags, and if so which tier?" --
// so `policy validate` and `inventory` can each surface every one of these protocols' mere PRESENCE
// as its own finding, independent of whatever a conduit's own allow-list decides about it (see
// PolicyReport::notable_protocols' and AssetInventoryReport::notable_protocols' own comments for
// exactly how that finding is aggregated and reported).
//
// Deliberately just a name -> tier lookup, nothing more: every one of these 43 protocol values is
// already fully named by decode's own dispatch (it_protocols.hpp/tunnel_vpn.hpp/eapol.hpp/pppoe.hpp/
// mpls.hpp/quic.hpp) before a DecodedPacket ever reaches this file, so there is no decoding work
// here, only the tier classification those six ROADMAP item 18 paragraphs already establish in
// prose.
#pragma once

#include <optional>
#include <string>

namespace conduitscope {

// Returns the tier name for `protocol` -- "remote-access" (Tier 1: rdp/vnc/teamviewer/anydesk/
// zoom), "lateral-movement" (Tier 2: smb/ssh/http/https/snmp/telnet/ftp/tftp/quic -- quic.hpp's
// own file header comment explains why QUIC joins this tier alongside HTTPS), "enterprise-trust"
// (Tier 3: ntp/dhcp/ldap/ldaps/radius/tacacs-plus/eapol), "wireless-backhaul" (Tier 4: capwap-
// control/capwap-data/lwapp-control/lwapp-data/gtp-u/pppoe), or "tunnel-vpn" (Tier 5: gre/nvgre/
// eoip/esp/ah/ip-in-ip/6in4/l2tp/ike/vxlan/geneve/wireguard/openvpn/dtls-tunnel/stt/mpls) -- when
// `protocol` is one of these 43 values `DecodedPacket::protocol` can be set to (see decoder.hpp's
// own comment on that field). std::nullopt for anything else, which includes every OT protocol this
// codebase decodes (modbus/dnp3/s7comm/enip/bacnet/iec104/hartip/opcua/mms/mqtt/ffhse/...) and every
// other recognized-but-unrelated protocol (arp/lldp/icmp/dns/profinet/goose/sv/ethercat/...) --
// PolicyEngine::observe and AssetInventoryEngine::observe both call this unconditionally, first,
// before their own existing dispatch, so a std::nullopt result must be cheap and common.
//
// EAPOL and PPPoE are tagged "enterprise-trust"/"wireless-backhaul" here -- the same prose tier
// docs/DEVELOPMENT.md's ROADMAP item 18 places them in -- even though decoder.hpp gives each its own
// separate `--protocol` filter value (ProtocolFilter::EapolOnly/PppoeOnly) rather than folding them
// into ItEnterpriseTrustMatch/ItWirelessBackhaulMatch, since both ride raw Ethernet (no port) and
// can't share those structs' port-based matching. MPLS is tagged "tunnel-vpn" for the identical
// reason, one architectural tier down.
std::optional<std::string> notable_it_protocol_tier(const std::string& protocol);

}  // namespace conduitscope
