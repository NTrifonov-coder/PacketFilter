#include "types/Packet.h"

CapturedPacket::CapturedPacket(const pcap_pkthdr* hdr, const u_char* packet_data, const uint32_t len)
    : capture_time(std::chrono::steady_clock::now()) {
    header = *hdr;
    data.assign(packet_data, packet_data + len);
}