#include "PacketAnalyzer.h"
#include <iostream>
#include <iomanip>
#include <algorithm>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

PacketAnalyzer::PacketAnalyzer() : total_packets_(0) {
}

void PacketAnalyzer::analyzePacket(const CapturedPacket& packet) {
    std::lock_guard lock(stats_mutex_);
    ++total_packets_;

    const std::string protocol = getProtocolName(packet);
    ++protocol_count_[protocol];

    // Extract IP addresses for top talkers
    if (packet.data.size() >= sizeof(struct ethhdr)) {
        const auto* eth = reinterpret_cast<const struct ethhdr*>(packet.data.data());

        // Проверка дали е IP пакет и дали има достатъчно данни
        if (ntohs(eth->h_proto) == ETH_P_IP && packet.data.size() >= sizeof(ethhdr) + sizeof(ip)) {
            const auto* iph = reinterpret_cast<const ip*>(packet.data.data() + sizeof(ethhdr));

            // Convert IP addresses to strings
            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN];

#ifdef _WIN32
            const in_addr src_addr = iph->ip_src;
            const in_addr dst_addr = iph->ip_dst;
            InetNtopA(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
            InetNtopA(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);
#else
            inet_ntop(AF_INET, &(iph->ip_src), src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(iph->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
#endif
            updateTopTalkers(src_ip_str, dst_ip_str);
        }
    }
}

void PacketAnalyzer::printAnalysis() const {
    std::lock_guard lock(stats_mutex_);

    std::cout << "\n=== Protocol Distribution ===" << std::endl;
    auto distribution = getProtocolDistribution();

    // Използваме C++17 structured bindings, тъй като CMake е настроен на 17
    for (const auto& [protocol, stats] : distribution) {
        std::cout << protocol << ": " << stats.count << " packets ("
                  << std::fixed << std::setprecision(2) << stats.percentage << "%)" << std::endl;
    }

    std::cout << "\n=== Top Talkers ===" << std::endl;
    const auto top_talkers = getTopTalkers(10);
    for (const auto&[address, packet_count] : top_talkers) {
        std::cout << address << ": " << packet_count << " packets" << std::endl;
    }
}

void PacketAnalyzer::reset() {
    std::lock_guard lock(stats_mutex_);
    protocol_count_.clear();
    top_talkers_.clear();
    total_packets_ = 0;
}

std::map<std::string, PacketAnalyzer::ProtocolStats> PacketAnalyzer::getProtocolDistribution() const {
    std::lock_guard lock(stats_mutex_);
    std::map<std::string, ProtocolStats> distribution;

    for (const auto& [protocol, count] : protocol_count_) {
        const double percentage = (total_packets_ > 0) ? count * 100.0 / total_packets_ : 0;
        distribution[protocol] = {count, percentage};
    }

    return distribution;
}

std::vector<PacketAnalyzer::TopTalker> PacketAnalyzer::getTopTalkers(const int limit) const {
    std::lock_guard lock(stats_mutex_);
    std::vector<TopTalker> talkers;

    for (const auto& [address, count] : top_talkers_) {
        talkers.push_back({address, count});
    }

    std::sort(talkers.begin(), talkers.end(),
             [](const TopTalker& a, const TopTalker& b) {
                 return a.packet_count > b.packet_count;
             });

    if (limit > 0 && talkers.size() > static_cast<size_t>(limit)) {
        talkers.resize(limit);
    }

    return talkers;
}

uint64_t PacketAnalyzer::getTotalPackets() const {
    std::lock_guard lock(stats_mutex_);
    return total_packets_;
}

std::string PacketAnalyzer::getProtocolName(const CapturedPacket& packet) {
    if (packet.data.size() < sizeof(ethhdr)) {
        return "Too-Small";
    }

    const auto* eth = reinterpret_cast<const struct ethhdr*>(packet.data.data());

    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return "Non-IP";
    }

    if (packet.data.size() < sizeof(ethhdr) + sizeof(ip)) {
        return "Truncated-IP";
    }

    const auto* iph = reinterpret_cast<const struct ip*>(packet.data.data() + sizeof(struct ethhdr));

    switch (iph->ip_p) {
        case IPPROTO_TCP: {
            if (packet.data.size() >= sizeof(ethhdr) + (IP_HL(iph) * 4) + sizeof(tcphdr)) {
                const auto* tcp_header = reinterpret_cast<const struct tcphdr*>(
                    packet.data.data() + sizeof(struct ethhdr) + IP_HL(iph) * 4);
                std::string service = getServiceName(ntohs(tcp_header->dest), true);
                if (!service.empty()) {
                    return "TCP-" + service;
                }
                service = getServiceName(ntohs(tcp_header->source), true);
                if (!service.empty()) {
                    return "TCP-" + service;
                }
            }
            return "TCP";
        }
        case IPPROTO_UDP: {
            if (packet.data.size() >= sizeof(ethhdr) + IP_HL(iph) * 4 + sizeof(udphdr)) {
                const auto* udp_header = reinterpret_cast<const struct udphdr*>(
                    packet.data.data() + sizeof(struct ethhdr) + IP_HL(iph) * 4);
                std::string service = getServiceName(ntohs(udp_header->dest), false);
                if (!service.empty()) {
                    return "UDP-" + service;
                }
                service = getServiceName(ntohs(udp_header->source), false);
                if (!service.empty()) {
                    return "UDP-" + service;
                }
            }
            return "UDP";
        }
        case IPPROTO_ICMP:
            return "ICMP";
        default:
            return "Other";
    }
}

// FIX: Закоментирахме името на параметъра /*is_tcp*/, за да махнем warning-а
std::string PacketAnalyzer::getServiceName(const uint16_t port, bool /*is_tcp*/) {
    switch (port) {
        case 80: return "HTTP";
        case 443: return "HTTPS";
        case 22: return "SSH";
        case 53: return "DNS";
        case 25: return "SMTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 21: return "FTP";
        case 23: return "TELNET";
        case 67: return "DHCP-Server";
        case 68: return "DHCP-Client";
        case 123: return "NTP";
        case 161: return "SNMP";
        case 389: return "LDAP";
        case 636: return "LDAPS";
        case 3306: return "MySQL";
        case 5432: return "PostgreSQL";
        case 8080: return "HTTP-Alt";
        default: return "";
    }
}

void PacketAnalyzer::updateTopTalkers(const std::string& src_ip, const std::string& dst_ip) {
    ++top_talkers_[src_ip];
    ++top_talkers_[dst_ip];
}