#include "types/Statistics.h"

void SnifferStats::reset() {
    total_packets = 0;
    tcp_packets = 0;
    udp_packets = 0;
    icmp_packets = 0;
    other_packets = 0;
    total_bytes = 0;
    queue_drops = 0;
    processing_errors = 0;
}

void SnifferStats::print() const {
    std::cout << "\n=== Capture Statistics ===" << std::endl;
    std::cout << "Total Packets: " << total_packets << std::endl;
    std::cout << "TCP Packets: " << tcp_packets << std::endl;
    std::cout << "UDP Packets: " << udp_packets << std::endl;
    std::cout << "ICMP Packets: " << icmp_packets << std::endl;
    std::cout << "Other Packets: " << other_packets << std::endl;
    std::cout << "Total Bytes: " << total_bytes << std::endl;
    std::cout << "Queue Drops: " << queue_drops << std::endl;
    std::cout << "Processing Errors: " << processing_errors << std::endl;
}