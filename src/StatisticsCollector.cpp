#include "StatisticsCollector.h"
#include <iostream>
#include <iomanip>

StatisticsCollector::StatisticsCollector(const std::shared_ptr<SnifferStats>& stats)
    : stats_(stats), show_live_stats_(true), collection_interval_ms_(2000) {
}

StatisticsCollector::~StatisticsCollector() {
    stopCollection();
}

void StatisticsCollector::startCollection(const int interval_ms) {
    if (running_) return;

    collection_interval_ms_ = interval_ms;
    running_ = true;
    collectionThread_ = std::thread(&StatisticsCollector::collectionLoop, this);
}

void StatisticsCollector::stopCollection() {
    if (!running_) return;

    running_ = false;
    if (collectionThread_.joinable()) {
        collectionThread_.join();
    }
}

bool StatisticsCollector::isRunning() const {
    return running_;
}

void StatisticsCollector::setStatsCallback(const StatsCallback& callback) {
    statsCallback_ = callback;
}

void StatisticsCollector::setLiveStatsEnabled(const bool enabled) {
    show_live_stats_ = enabled;
}

void StatisticsCollector::analyzePacket(const CapturedPacket& packet) const {
    if (!stats_) return;

    // Try to extract an IP header
    if (const ip* iph = extractIPHeaderFromPacket(packet)) {
        processIPPacket(iph);
    } else {
        // Not an IP packet or unable to parse
        ++stats_->other_packets;
    }
}

const ip* StatisticsCollector::extractIPHeaderFromPacket(const CapturedPacket& packet) {
    // Minimum size for Ethernet + IP headers
    if (packet.data.size() < sizeof(ethhdr) + 20) { // Minimum IP header size
        return nullptr;
    }

    const u_char* data = packet.data.data();

    // Parse Ethernet header
    const auto* eth = reinterpret_cast<const struct ethhdr*>(data);

    // Check if it's an IP packet
    if (const uint16_t ether_type = ntohs(eth->h_proto); ether_type == ETH_P_IP) {
        const auto* iph = reinterpret_cast<const struct ip*>(data + sizeof(struct ethhdr));
        // Check IP version using a new macro
        if (IP_V(iph) == 4) {
            return iph;
        }
    }

    return nullptr;
}

void StatisticsCollector::processIPPacket(const ip* iph) const {
    if (!stats_) return;

    switch (iph->ip_p) {
        case IPPROTO_TCP:
            ++stats_->tcp_packets;
            break;
        case IPPROTO_UDP:
            ++stats_->udp_packets;
            break;
        case IPPROTO_ICMP:
            ++stats_->icmp_packets;
            break;
        default:
            ++stats_->other_packets;
            break;
    }
}

void StatisticsCollector::collectionLoop() const {
    auto last_stats_time = std::chrono::steady_clock::now();

    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stats_time);

        if (elapsed.count() >= collection_interval_ms_) {
            if (show_live_stats_ && stats_) {
                std::cout << "\r[Live] Packets: " << stats_->total_packets
                          << " | TCP: " << stats_->tcp_packets
                          << " | UDP: " << stats_->udp_packets
                          << " | ICMP: " << stats_->icmp_packets
                          << " | Other: " << stats_->other_packets
                          << " | Drops: " << stats_->queue_drops
                          << "      " << std::flush;
            }

            if (statsCallback_ && stats_) {
                statsCallback_(*stats_);
            }

            last_stats_time = now;
        }
    }

    if (show_live_stats_) {
        std::cout << std::endl;
    }
}
