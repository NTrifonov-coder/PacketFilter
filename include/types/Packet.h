#ifndef PACKET_H
#define PACKET_H

#include <vector>
#include <chrono>
#include <pcap.h>
#include "NetworkTypes.h"

struct CapturedPacket {
    pcap_pkthdr header{};
    std::vector<uint8_t> data;
    std::chrono::steady_clock::time_point capture_time;

    CapturedPacket(const pcap_pkthdr* hdr, const u_char* packet_data, uint32_t len);
};

#endif