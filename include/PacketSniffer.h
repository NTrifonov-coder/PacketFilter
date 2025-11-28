#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include "types/Packet.h"
#include "types/Statistics.h"
#include "PacketProcessor.h"
#include "StatisticsCollector.h"
#include "PacketAnalyzer.h"
#include <pcap.h>
#include <memory>
#include <string>
#include <functional>
#include <thread>
#include <atomic>

class PacketSniffer {
public:
    using PacketCallback = std::function<void(const CapturedPacket&)>;

    PacketSniffer(size_t max_packets = 0, bool verbose = false, bool show_live_stats = true);
    ~PacketSniffer();

    // Non-copyable
    PacketSniffer(const PacketSniffer&) = delete;
    PacketSniffer& operator=(const PacketSniffer&) = delete;

    // Interface management
    static bool listInterfaces();
    bool initialize(const std::string& interFace, const std::string& filter = "");
    bool setFilter(const std::string& filter) const;

    // Sniffer control
    void start();
    void stop();
    bool isRunning() const;

    // Configuration
    void setPacketCallback(const PacketCallback &callback) const;
    void setVerbose(bool verbose);
    void setMaxPackets(size_t max_packets);

    // Statistics and analysis
    const SnifferStats& getStats() const;
    void printFinalReport() const;

    // Getters
    std::shared_ptr<PacketAnalyzer> getPacketAnalyzer() const;
    int getDataLinkType() const { return data_link_type_; }

private:
    void captureLoop();
    void processCapturedPacket(const pcap_pkthdr* header, const u_char* packet) const;
    static void printPacketDetails(const CapturedPacket& packet) ;
    const ip* extractIPHeader(const CapturedPacket& packet) const;

    pcap_t* handle_;
    char errbuf_[PCAP_ERRBUF_SIZE]{};
    int data_link_type_;

    std::atomic<bool> running_{false};
    std::thread captureThread_;

    std::shared_ptr<SnifferStats> stats_;
    std::unique_ptr<PacketProcessor> packet_processor_;
    std::unique_ptr<StatisticsCollector> stats_collector_;
    std::shared_ptr<PacketAnalyzer> packet_analyzer_;

    size_t max_packets_;
    bool verbose_;
    bool show_live_stats_;
    uint64_t packets_captured_;
};

#endif