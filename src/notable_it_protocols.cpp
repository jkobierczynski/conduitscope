// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/notable_it_protocols.hpp"

#include <unordered_map>

namespace conduitscope {

namespace {

const std::unordered_map<std::string, std::string>& tier_by_protocol() {
    static const std::unordered_map<std::string, std::string> table = {
        // Tier 1 -- interactive remote control (it_protocols.hpp: ItRemoteAccessMatch::protocol).
        {"rdp", "remote-access"},
        {"vnc", "remote-access"},
        {"teamviewer", "remote-access"},
        {"anydesk", "remote-access"},
        {"zoom", "remote-access"},

        // Tier 2 -- lateral-movement/credential-harvesting (it_protocols.hpp:
        // ItLateralMovementMatch::protocol).
        {"smb", "lateral-movement"},
        {"ssh", "lateral-movement"},
        {"http", "lateral-movement"},
        {"https", "lateral-movement"},
        {"snmp", "lateral-movement"},
        {"telnet", "lateral-movement"},
        {"ftp", "lateral-movement"},
        {"tftp", "lateral-movement"},
        {"quic", "lateral-movement"},  // quic.hpp -- joins Tier 2 alongside HTTPS, see that file's
                                        // own file header comment for why

        // Tier 3 -- enterprise-trust-boundary (it_protocols.hpp: ItEnterpriseTrustMatch::protocol),
        // plus EAPOL (eapol.hpp), which is architecturally EtherType-keyed but the same ROADMAP tier.
        {"ntp", "enterprise-trust"},
        {"dhcp", "enterprise-trust"},
        {"ldap", "enterprise-trust"},
        {"ldaps", "enterprise-trust"},
        {"radius", "enterprise-trust"},
        {"tacacs-plus", "enterprise-trust"},
        {"eapol", "enterprise-trust"},

        // Tier 4 -- wireless-backhaul-and-cellular (it_protocols.hpp:
        // ItWirelessBackhaulMatch::protocol), plus PPPoE (pppoe.hpp), same "EtherType-keyed but same
        // tier" shape as EAPOL above.
        {"capwap-control", "wireless-backhaul"},
        {"capwap-data", "wireless-backhaul"},
        {"lwapp-control", "wireless-backhaul"},
        {"lwapp-data", "wireless-backhaul"},
        {"gtp-u", "wireless-backhaul"},
        {"pppoe", "wireless-backhaul"},

        // Tier 5 -- generic tunnel/VPN encapsulation (tunnel_vpn.hpp), plus MPLS (mpls.hpp), same
        // "EtherType-keyed but same tier" shape as EAPOL/PPPoE above.
        {"gre", "tunnel-vpn"},
        {"nvgre", "tunnel-vpn"},
        {"eoip", "tunnel-vpn"},
        {"esp", "tunnel-vpn"},
        {"ah", "tunnel-vpn"},
        {"ip-in-ip", "tunnel-vpn"},
        {"6in4", "tunnel-vpn"},
        {"l2tp", "tunnel-vpn"},
        {"ike", "tunnel-vpn"},
        {"vxlan", "tunnel-vpn"},
        {"geneve", "tunnel-vpn"},
        {"wireguard", "tunnel-vpn"},
        {"openvpn", "tunnel-vpn"},
        {"dtls-tunnel", "tunnel-vpn"},
        {"stt", "tunnel-vpn"},
        {"mpls", "tunnel-vpn"},
    };
    return table;
}

}  // namespace

std::optional<std::string> notable_it_protocol_tier(const std::string& protocol) {
    const auto& table = tier_by_protocol();
    auto it = table.find(protocol);
    if (it == table.end()) return std::nullopt;
    return it->second;
}

}  // namespace conduitscope
