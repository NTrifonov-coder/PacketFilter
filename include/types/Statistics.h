#ifndef STATISTICS_H
#define STATISTICS_H

#include <atomic>
#include <cstdint>
#include <iostream>

struct SnifferStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> icmp_packets{0};
    std::atomic<uint64_t> other_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> queue_drops{0};
    std::atomic<uint64_t> processing_errors{0};

    void reset();
    void print() const;
};

#endif