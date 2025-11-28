#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include "types/Packet.h"
#include <map>
#include <string>
#include <mutex>
#include <vector>
#include <cstdint>

class PacketAnalyzer {
public:
    struct ProtocolStats {
        uint64_t count;
        double percentage;
    };

    struct TopTalker {
        std::string address;
        uint64_t packet_count;
    };

    PacketAnalyzer();

    void analyzePacket(const CapturedPacket& packet);
    void printAnalysis() const;
    void reset();

    std::map<std::string, ProtocolStats> getProtocolDistribution() const;
    std::vector<TopTalker> getTopTalkers(int limit = 10) const;
    uint64_t getTotalPackets() const;

private:
    static std::string getProtocolName(const CapturedPacket& packet) ;
    static std::string getServiceName(uint16_t port, bool is_tcp);
    void updateTopTalkers(const std::string& src_ip, const std::string& dst_ip);

    mutable std::mutex stats_mutex_;
    std::map<std::string, uint64_t> protocol_count_;
    std::map<std::string, uint64_t> top_talkers_;
    uint64_t total_packets_;
};

#endif