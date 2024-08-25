#ifndef __TC_H__
#define __TC_H__

// Define the maximum length of task names (e.g., process names)
#define TASK_LEN 16

// Enumeration for different IP protocols
enum ip_proto {
    UDP_V6, // UDP over IPv6
    TCP_V4, // TCP over IPv4
    TCP_V6, // TCP over IPv6
    UDP_V4, // UDP over IPv4
};

// Enumeration for packet state
enum pkt_state {
    BLOCKED, // Packet is blocked
    ALLOWED, // Packet is allowed
};

// Structure to hold IP address and port information
struct ip_info {
    enum ip_proto ipp; // Protocol type (UDP/TCP) and IP version (IPv4/IPv6)
    
    // Union to accommodate either IPv4 or IPv6 address
    union {
        uint8_t ipv6_daddr[16]; // IPv6 address (16 bytes)
        uint8_t ipv4_daddr[4];  // IPv4 address (4 bytes)
    } addr;
    
    uint16_t port; // Port number
};

// Structure for holding information about network events
struct tc_evt {
    enum pkt_state pkt_state; // State of the packet (BLOCKED/ALLOWED)
    pid_t tgid;               // Thread group ID (usually the process ID)
    pid_t pid;                // Process ID
    char comm[TASK_LEN];      // Command name of the process (up to TASK_LEN characters)
    uint16_t eth_type;        // Ethernet type (for example, to distinguish between IPv4 and IPv6)

    // Union to accommodate either IP information or ARP header
    union {
        struct ip_info ip;  // IP information (for IP packets)
        struct arphdr arp; // ARP header (for ARP packets)
    };
};

#endif // __TC_H__
