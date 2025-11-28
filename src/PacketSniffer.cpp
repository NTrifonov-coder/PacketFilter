#include "PacketSniffer.h"
#include <iostream>
#include <iomanip>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

PacketSniffer::PacketSniffer(const size_t max_packets, const bool verbose, const bool show_live_stats)
    : handle_(nullptr),
      data_link_type_(-1),
      running_(false),
      max_packets_(max_packets),
      verbose_(verbose),
      show_live_stats_(show_live_stats),
      packets_captured_(0) {
    std::memset(errbuf_, 0, PCAP_ERRBUF_SIZE);

    stats_ = std::make_shared<SnifferStats>();
    packet_analyzer_ = std::make_shared<PacketAnalyzer>();
    packet_processor_ = std::make_unique<PacketProcessor>();
    stats_collector_ = std::make_unique<StatisticsCollector>(stats_);

    // Setup callbacks
    packet_processor_->setStatisticsCollector(stats_);
    packet_processor_->setPacketCallback([this](const CapturedPacket& packet) {
        stats_collector_->analyzePacket(packet);
        packet_analyzer_->analyzePacket(packet);
    });

    stats_collector_->setLiveStatsEnabled(show_live_stats_);
}

PacketSniffer::~PacketSniffer() {
    // stop() ще затвори capture thread-а и pcap дескриптора (ако все още е отворен)
    stop();
    // не правим допълнителен pcap_close тук, защото stop() вече го извършва безопасно
}

bool PacketSniffer::listInterfaces() {
    pcap_if_t* alldevs;
    char local_errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, local_errbuf) == -1) {
        std::cerr << "Error finding devices: " << local_errbuf << std::endl;
        return false;
    }

    std::cout << "\n=== Available Network Interfaces ===" << std::endl;
    int i = 0;
    for (const pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::cout << i++ << ". " << d->name;
        if (d->description) {
            std::cout << " (" << d->description << ")";
        }
        std::cout << std::endl;

        for (const pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
#ifdef _WIN32
                const auto* addr_in = reinterpret_cast<struct sockaddr_in*>(a->addr);
                InetNtopA(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN);
#else
                struct sockaddr_in* addr_in = reinterpret_cast<struct sockaddr_in*>(a->addr);
                inet_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN);
#endif
                std::cout << "    IPv4: " << ip << std::endl;
            }
        }
    }

    if (i == 0) {
        std::cout << "No interfaces found!" << std::endl;
        pcap_freealldevs(alldevs);
        return false;
    }

    pcap_freealldevs(alldevs);
    return true;
}

bool PacketSniffer::initialize(const std::string& interFace, const std::string& filter) {
    handle_ = pcap_open_live(interFace.c_str(), BUFSIZ, 1, 100, errbuf_);

    if (!handle_) {
        std::cerr << "Couldn't open device " << interFace << ": " << errbuf_ << std::endl;
        return false;
    }

    // Store and display data link type
    data_link_type_ = pcap_datalink(handle_);
    const char* dlt_name = pcap_datalink_val_to_name(data_link_type_);
    const char* dlt_desc = pcap_datalink_val_to_description(data_link_type_);

    std::cout << "Data link type: " << data_link_type_ << " (" << (dlt_name ? dlt_name : "unknown")
              << ") - " << (dlt_desc ? dlt_desc : "unknown") << std::endl;

    // Accept common Windows data link types
    if (data_link_type_ != DLT_EN10MB && data_link_type_ != DLT_RAW && data_link_type_ != DLT_NULL) {
        std::cerr << "Unsupported data link type: " << data_link_type_
                  << " (" << (dlt_name ? dlt_name : "unknown") << ")" << std::endl;
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }

    if (!filter.empty()) {
        if (!setFilter(filter)) {
            pcap_close(handle_);
            handle_ = nullptr;
            return false;
        }
    }

    std::cout << "Sniffer initialized on interface: " << interFace << std::endl;
    if (!filter.empty()) {
        std::cout << "Filter: " << filter << std::endl;
    }
    return true;
}

bool PacketSniffer::setFilter(const std::string& filter) const {
    if (!handle_) {
        std::cerr << "Sniffer not initialized!" << std::endl;
        return false;
    }

    bpf_program fp{};
    constexpr bpf_u_int32 netmask = 0;

    if (pcap_compile(handle_, &fp, filter.c_str(), 0, netmask) == -1) {
        std::cerr << "Couldn't parse filter '" << filter << "': " << pcap_geterr(handle_) << std::endl;
        return false;
    }

    if (pcap_setfilter(handle_, &fp) == -1) {
        std::cerr << "Couldn't install filter '" << filter << "': " << pcap_geterr(handle_) << std::endl;
        pcap_freecode(&fp);
        return false;
    }

    pcap_freecode(&fp);
    return true;
}

void PacketSniffer::start() {
    if (!handle_) {
        std::cerr << "Sniffer not initialized!" << std::endl;
        return;
    }

    if (running_) {
        std::cerr << "Sniffer already running!" << std::endl;
        return;
    }

    running_ = true;
    packets_captured_ = 0;
    stats_->reset();
    packet_analyzer_->reset();

    packet_processor_->startProcessing();
    stats_collector_->startCollection();

    captureThread_ = std::thread(&PacketSniffer::captureLoop, this);

    std::cout << "\nPacket sniffer started!" << std::endl;
    std::cout << "Max packets: " << (max_packets_ == 0 ? "unlimited" : std::to_string(max_packets_)) << std::endl;
    std::cout << "Press Ctrl+C to stop..." << std::endl;
}

void PacketSniffer::stop() {
    // If not running and handle already closed, nothing to do
    if (!running_ && !handle_) return;

    // Signal stop
    running_ = false;

    // If the pcap handle exists, attempt to interrupt any blocking calls.
    // pcap_breakloop is primarily for pcap_loop, but calling it is harmless.
    if (handle_) {
        // Attempt to break any internal loop in pcap (no-op if not used),
        // this helps with certain driver/backends that may block.
        pcap_breakloop(handle_);
    }

    // Wait for the capture thread to finish
    if (captureThread_.joinable()) {
        captureThread_.join();
    }

    // Stop background workers
    stats_collector_->stopCollection();
    packet_processor_->stopProcessing();

    // Close and NULL the handle so destructor/stop won't double-close
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }

    std::cout << "\nPacket sniffer stopped." << std::endl;
}

bool PacketSniffer::isRunning() const {
    return running_;
}

void PacketSniffer::setPacketCallback(const PacketCallback &callback) const {
    packet_processor_->setPacketCallback(callback);
}

void PacketSniffer::setVerbose(const bool verbose) {
    verbose_ = verbose;
}

void PacketSniffer::setMaxPackets(const size_t max_packets) {
    max_packets_ = max_packets;
}

const SnifferStats& PacketSniffer::getStats() const {
    return *stats_;
}

void PacketSniffer::printFinalReport() const {
    stats_->print();
    packet_analyzer_->printAnalysis();
}

std::shared_ptr<PacketAnalyzer> PacketSniffer::getPacketAnalyzer() const {
    return packet_analyzer_;
}

const ip* PacketSniffer::extractIPHeader(const CapturedPacket& packet) const {
    if (packet.data.size() < sizeof(ip)) {
        return nullptr;
    }

    const u_char* data = packet.data.data();
    size_t offset = 0;

    switch (data_link_type_) {
        case DLT_EN10MB:  // Ethernet
            if (packet.data.size() >= sizeof(ethhdr) + sizeof(ip)) {
                const auto* eth = reinterpret_cast<const struct ethhdr*>(data);
                if (ntohs(eth->h_proto) == ETH_P_IP) {
                    offset = sizeof(ethhdr);
                }
            }
            break;

        case DLT_RAW:  // Raw IP
            // No header, IP starts immediately
            offset = 0;
            break;

        case DLT_NULL:  // Loopback
            if (packet.data.size() >= 4 + sizeof(ip)) {
                offset = 4;  // 4-byte loopback header
            }
            break;

        default:
            return nullptr;
    }

    if (packet.data.size() >= offset + sizeof(ip)) {
        const auto iph = reinterpret_cast<const struct ip*>(data + offset);

        // Use the new IP version check
        if (IP_V(iph) == 4) {
            return iph;
        }
    }

    return nullptr;
}

void PacketSniffer::captureLoop() {
    // Keep a local copy of max_packets for slight performance / atomic-safety reasons
    while (running_ && (max_packets_ == 0 || packets_captured_ < max_packets_)) {
        struct pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;

        const int result = pcap_next_ex(handle_, &header, &packet);

        if (result == 1 && header && packet) {
            processCapturedPacket(header, packet);
            ++packets_captured_;

            // Ако достигнем лимита — излизаме от цикъла (оставяме stop() да затвори handle-а)
            if (max_packets_ > 0 && packets_captured_ >= max_packets_) {
                break;
            }
        } else if (result == 0) {
            // timeout, просто продължаваме
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } else if (result == -1) {
            std::cerr << "Error reading packet: " << pcap_geterr(handle_) << std::endl;
            ++stats_->processing_errors;
            break;
        } else if (result == -2) {
            // pcap_next_ex returns -2 when EOF or capture terminated by pcap_breakloop
            break;
        }
        // loop continues while running_ is true
    }

    // Ensure running_ is false when the loop finishes
    running_ = false;
    // Do not close handle_ here — let stop() close it (to avoid races with the main thread)
}

void PacketSniffer::processCapturedPacket(const pcap_pkthdr* header, const u_char* packet) const {
    auto captured_packet = std::make_unique<CapturedPacket>(header, packet, static_cast<uint32_t>(header->caplen));

    if (stats_) {
        ++stats_->total_packets;        // Тук броим общия брой
        stats_->total_bytes += header->len;
    }

    if (verbose_) {
        printPacketDetails(*captured_packet);
    }

    if (!packet_processor_->addPacket(std::move(captured_packet))) {
        if (verbose_) {
            std::cerr << "Queue full, packet dropped!" << std::endl;
        }
    }
}

void PacketSniffer::printPacketDetails(const CapturedPacket& packet) {
    // 1. Проверка за минимален размер (Ethernet header)
    if (packet.data.size() < sizeof(struct ethhdr)) {
        return;
    }

    // Достъп до Ethernet хедъра
    const auto* eth = reinterpret_cast<const struct ethhdr*>(packet.data.data());

    // 2. Обработка само на IPv4 пакети (0x0800)
    uint16_t ether_type = ntohs(eth->h_proto);
    if (ether_type == ETH_P_IP) {
        // Проверка дали пакетът е достатъчно голям за IP хедър
        if (packet.data.size() < sizeof(struct ethhdr) + sizeof(struct ip)) {
            return;
        }

        // Достъп до IP хедъра (веднага след Ethernet)
        const auto* iph = reinterpret_cast<const struct ip*>(packet.data.data() + sizeof(struct ethhdr));

        // Буфери за текстовото представяне на IP адресите
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        // Конвертиране от Binary (Network Byte Order) към String (192.168.x.x)
#ifdef _WIN32
        // Windows изисква малко по-различно подаване на struct in_addr
        const in_addr src_addr = iph->ip_src;
        const in_addr dst_addr = iph->ip_dst;
        InetNtopA(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
        InetNtopA(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);
#else
        // Linux implementation
        inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);
#endif

        // Определяне на протокола (TCP/UDP/ICMP) за визуализация
        std::string proto_str;
        switch (iph->ip_p) {
            case IPPROTO_TCP:  proto_str = "[TCP] "; break;
            case IPPROTO_UDP:  proto_str = "[UDP] "; break;
            case IPPROTO_ICMP: proto_str = "[ICMP]"; break;
            default:           proto_str = "[IP]  "; break;
        }

        // 3. Принтиране на резултата
        std::cout << proto_str << " "
                  << src_ip << " -> " << dst_ip
                  << " | Len: " << packet.header.len << " bytes"
                  << std::endl;
    }
    else if (ether_type == ETH_P_ARP) {
        std::cout << "[ARP]  Who has / Tell" << std::endl;
    }
    else if (ether_type == ETH_P_IPV6) {
        std::cout << "[IPv6] (Details omitted)" << std::endl;
    }
}
