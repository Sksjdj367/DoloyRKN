// SPDX-License-Identifier: GPL-3.0-or-later

#include <unordered_map>
#include <cstring>
#include <string>

#include "util/log.hpp"
#include "cli/params.hpp"
#include "net/protocol/l3.hpp"
#include "net/protocol/packet.hpp"
#include "net/util/checksum.hpp"

#include "circumvention/dns.hpp"

using namespace Logs;
using namespace cli;
using namespace Net;

namespace Circumvention
{
struct DNSKeyIPv4
{
    uint32_t ip;
    uint16_t src_port;
    uint16_t transaction_id;

    bool operator==(const DNSKeyIPv4& key) const
    {
        return key.ip == ip && key.src_port == src_port && transaction_id == key.transaction_id;
    }
};
} // namespace Circumvention

namespace std
{
template <> struct hash<Circumvention::DNSKeyIPv4>
{
    size_t operator()(const Circumvention::DNSKeyIPv4& key) const noexcept
    {
        size_t h1 = std::hash<uint32_t>{}(key.ip);
        size_t h2 = std::hash<uint16_t>{}(key.src_port);
        size_t h3 = std::hash<uint32_t>{}(key.transaction_id);

        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};
} // namespace std

namespace Circumvention
{
namespace
{
std::unordered_map<DNSKeyIPv4, uint32_t> DNSIPv4Cache{};

constexpr uint8_t DNSRequestResponseCounter[]{0, 0, 0, 0, 0, 0};

constexpr auto minimalDNSPayloadLen = 16;

DNSKeyIPv4 constructKey(Packet* outbound_packet)
{
    uint16_t transaction_id;

    memcpy(&transaction_id, outbound_packet->payload, sizeof(transaction_id));

    return {.ip = reinterpret_cast<IPv4Hdr*>(outbound_packet->network_hdr)->src_ip,
        .src_port = reinterpret_cast<UDPHdr*>(outbound_packet->transport_hdr)->src_port,
        .transaction_id = transaction_id};
}

DNSKeyIPv4 reconstructKey(Packet* inbound_packet)
{
    uint16_t transaction_id;

    memcpy(&transaction_id, inbound_packet->payload, sizeof(transaction_id));

    return {.ip = reinterpret_cast<IPv4Hdr*>(inbound_packet->network_hdr)->dst_ip,
        .src_port = reinterpret_cast<UDPHdr*>(inbound_packet->transport_hdr)->dst_port,
        .transaction_id = transaction_id};
}
} // namespace

bool isDNSRequest(const Packet* packet)
{
    if (packet->transport_protocol != TransportProtocol::UDP)
        return false;

    if (packet->payload_len < minimalDNSPayloadLen)
        return false;

    if (memcmp(packet->payload + 6, DNSRequestResponseCounter, 5) != 0)
        return false;

    if (reinterpret_cast<UDPHdr*>(packet->transport_hdr)->getDstPort() != 53)
        return false;

    return true;
}

bool isDNSResponse(const Packet* packet)
{
    if (packet->transport_protocol != TransportProtocol::UDP)
        return false;

    if (packet->payload_len < minimalDNSPayloadLen)
        return false;

    if (reinterpret_cast<UDPHdr*>(packet->transport_hdr)->getSrcPort() != 53)
        return false;

    return true;
}

void handleDNSRequest(const Params* params, Packet* packet)
{
    auto iph = reinterpret_cast<IPv4Hdr*>(packet->network_hdr);
    auto key = constructKey(packet);
    DNSIPv4Cache[key] = iph->dst_ip;
    iph->dst_ip = params->dr_ipv4;
    calcChecksum(packet);
}

void handleDNSResponse(Packet* packet)
{
    auto key = reconstructKey(packet);
    auto ip = DNSIPv4Cache[key];
    if (!ip)
    {
        prErr("Could not find cache for DNS\n");
        return;
    }
    DNSIPv4Cache.erase(key);
    reinterpret_cast<IPv4Hdr*>(packet->network_hdr)->src_ip = ip;
    calcChecksum(packet);
}
} // namespace Circumvention