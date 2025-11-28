#ifndef NETWORK_TYPES_H
#define NETWORK_TYPES_H

#include <cstdint>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>

    // =========================================================
    // WINDOWS STRUCTURES (Manual Definition)
    // =========================================================

    // ВАЖНО: Казваме на компилатора да НЕ слага padding (изравняване).
    // "push, 1" означава: запомни старите настройки и задай подравняване на 1 байт.
    #pragma pack(push, 1)

    // Ethernet header
    struct ethhdr {
        unsigned char h_dest[6];   // Destination address
        unsigned char h_source[6]; // Source address
        uint16_t      h_proto;     // Packet type ID field
    };

    // IP header (IPv4)
    struct ip {
        uint8_t  ip_vhl;          // Version (4 bits) + Header Length (4 bits)
        uint8_t  ip_tos;          // Type of service
        uint16_t ip_len;          // Total length
        uint16_t ip_id;           // Identification
        uint16_t ip_off;          // Fragment offset field
        uint8_t  ip_ttl;          // Time to live
        uint8_t  ip_p;            // Protocol
        uint16_t ip_sum;          // Checksum
        in_addr ip_src;    // Source address
        in_addr ip_dst;    // Destination address
    };

    // TCP header
    struct tcphdr {
        uint16_t source;
        uint16_t dest;
        uint32_t seq;
        uint32_t ack_seq;
        // Little Endian (x86/Windows) bitfields order:
        uint16_t res1:4;
        uint16_t doff:4;
        uint16_t fin:1;
        uint16_t syn:1;
        uint16_t rst:1;
        uint16_t psh:1;
        uint16_t ack:1;
        uint16_t urg:1;
        uint16_t res2:2;
        uint16_t window;
        uint16_t check;
        uint16_t urg_ptr;
    };

    // UDP header
    struct udphdr {
        uint16_t source;
        uint16_t dest;
        uint16_t len;
        uint16_t check;
    };

    // ВАЖНО: Връщаме нормалните настройки за подравняване на паметта.
    // Това е редът, който липсваше и предизвикваше грешката.
    #pragma pack(pop)

    // Ethernet protocol IDs (ако липсват в Windows хедърите)
    #ifndef ETH_P_IP
        #define ETH_P_IP    0x0800
    #endif
    #ifndef ETH_P_ARP
        #define ETH_P_ARP   0x0806
    #endif
    #ifndef ETH_P_IPV6
        #define ETH_P_IPV6  0x86DD
    #endif

#else
    // =========================================================
    // LINUX STRUCTURES (System Headers)
    // =========================================================
    #include <netinet/if_ether.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <arpa/inet.h>
#endif

// =========================================================
// COMMON HELPER MACROS
// =========================================================

// Макроси за извличане на Версия и Дължина от IP хедъра
#ifndef IP_V
    #define IP_V(ip) (((ip)->ip_vhl) >> 4)
#endif

#ifndef IP_HL
    #define IP_HL(ip) (((ip)->ip_vhl) & 0x0F)
#endif

// Common protocol numbers
#ifndef IPPROTO_TCP
    #define IPPROTO_TCP   6
#endif
#ifndef IPPROTO_UDP
    #define IPPROTO_UDP   17
#endif
#ifndef IPPROTO_ICMP
    #define IPPROTO_ICMP  1
#endif

#endif // NETWORK_TYPES_H