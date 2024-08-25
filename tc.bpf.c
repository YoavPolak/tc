#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "tc.h"

#define ETH_ALEN 6  // Length of the Ethernet address
#define ETH_P_IP 0x0800  // Ethernet protocol type for IPv4
#define ETH_P_IPV6 0X86DD  // Ethernet protocol type for IPv6
#define ETH_P_ARP 0x0806  // Ethernet protocol type for ARP

// Define possible actions for Traffic Control (TC) in BPF
#define TC_ACT_UNSPEC   (-1)
#define TC_ACT_OK       0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT     2
#define TC_ACT_PIPE     3
#define TC_ACT_STOLEN   4
#define TC_ACT_QUEUED   5
#define TC_ACT_REPEAT   6
#define TC_ACT_REDIRECT 7
#define TC_ACT_TRAP     8

// Define byte-order conversion macros
#define ntohs bpf_ntohs
#define ntohl bpf_ntohl

// Define BPF maps here: ports, ringbuffer
// Map to store allowed ports
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(value, u16);
    __type(key, u32);
} ports SEC(".maps");

// Ring buffer for event logging
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024); // Size of the ring buffer
} rb SEC (".maps");

pid_t my_pid = 0; // PID of the process to be excluded from packet reporting

// Function to determine if the Ethernet frame is IPv4
struct iphdr* is_ipv4(struct ethhdr *eth, void *data_end)
{
    struct iphdr *iph = NULL;
    if (!eth || !data_end) return NULL;
    if((void*)eth + sizeof(*eth) + sizeof(*iph) > data_end) return NULL;

    if(eth->h_proto == bpf_htons(ETH_P_IP)) { // Check if protocol is IPv4
        iph = (struct iphdr*)((void*)eth + sizeof(*eth));
    }
    return iph;
}

// Function to determine if the Ethernet frame is IPv6
struct ipv6hdr* is_ipv6(struct ethhdr *eth, void *data_end)
{
    struct ipv6hdr *iph = NULL;
    if (!eth || !data_end) return NULL;
    if((void*)eth + sizeof(*eth) + sizeof(*iph) > data_end) return NULL;

    if(eth->h_proto == bpf_htons(ETH_P_IPV6)) { // Check if protocol is IPv6
        iph = (struct ipv6hdr*)((void*)eth + sizeof(*eth));
    }
    return iph;
}

// Function to determine if the Ethernet frame is ARP
struct arphdr* is_arp(struct ethhdr *eth, void *data_end)
{
    struct arphdr *arp = NULL;
    if (!eth || !data_end) return NULL;
    if((void*)eth + sizeof(*eth) + sizeof(*arp) > data_end) return NULL;

    if(eth->h_proto == bpf_htons(ETH_P_ARP)) { // Check if protocol is ARP
        arp = (struct arphdr*)((void*)eth + sizeof(*eth));
    }
    return arp;
}

// BPF program for packet classification
SEC("classifier")
int handle_egress(struct __sk_buff *skb)
{
    int rc = TC_ACT_SHOT; // Default action is to drop the packet
    struct task_struct *t = (struct task_struct*)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(t, pid);
    pid_t tgid = BPF_CORE_READ(t, tgid);

    // Skip processing if the packet is from the current process
    if (tgid == my_pid) {
        rc = TC_ACT_OK; // Allow the packet
        bpf_printk("don't report me!"); // Log message for debugging
        return rc;
    }

    // Read packet data from the socket buffer
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void*)(unsigned long long)skb->data;
    struct ethhdr *eth = data;

    // Check if there is enough data for Ethernet header
    if((void*)(eth+1) > data_end) goto err;

    // Identify protocol type
    struct iphdr *iph = is_ipv4(eth, data_end);
    struct ipv6hdr *iph6 = is_ipv6(eth, data_end);
    struct arphdr *arp = is_arp(eth, data_end);

    // Reserve space in the ring buffer for event logging
    struct tc_evt *evt = NULL;
    evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt) {
        bpf_printk("no ringbuff"); // Log message if ring buffer is full
        goto rb_err;
    }

    __builtin_memset(evt, 0, sizeof(*evt)); // Initialize the event structure
    evt->eth_type = bpf_htons(BPF_CORE_READ(eth, h_proto)); // Store Ethernet type
    bpf_probe_read_kernel_str(evt->comm, TASK_LEN, BPF_CORE_READ(t, group_leader, comm)); // Store process name
    evt->pid = pid;
    evt->tgid = tgid;
    bpf_printk("comm is: %s eth_type is 0x%04x", evt->comm,  evt->eth_type);

    if(iph) {
        struct tcphdr *tcph = NULL;
        struct udphdr *udph = NULL;

        if(iph->protocol == IPPROTO_UDP) { // Handle UDP packets
            udph = (void*)(iph + 1);
            if ((void*)(udph + 1) > data_end) goto err;
            bpf_printk("is udp %d", ntohs(udph->source)); 
            bpf_printk("  %d\n", ntohs(udph->dest));

            evt->ip.ipp = UDP_V4;
            evt->ip.port = ntohs(udph->dest);
        } else if (iph->protocol == IPPROTO_TCP) { // Handle TCP packets
            tcph = (void*)(iph + 1);
            if((void*)(tcph + 1) > data_end) goto err;
            bpf_printk("\nis tcp %d\n", ntohs(tcph->source));
            bpf_printk(" %d\n", ntohs(tcph->dest));

            evt->ip.ipp = TCP_V4;
            evt->ip.port = ntohs(tcph->dest);
        }

        u32 daddr = iph->daddr;
        if(tcph || udph) {
            bpf_printk("dest ip is %08x", ntohl(daddr));
        } else {
            goto err;
        }

        bpf_probe_read_kernel(&evt->ip.addr.ipv4_daddr, sizeof(evt->ip.addr.ipv4_daddr), &daddr);

    } else if (iph6) {
        struct udphdr *udph = NULL;
        struct tcphdr *tcph = NULL;

        if(iph6->nexthdr == IPPROTO_UDP) { // Handle UDP packets for IPv6
            udph = (void*)(iph6 + 1);
            if ((void*)(udph + 1) > data_end) goto err;

            bpf_printk("is udp %d", ntohs(udph->source)); 
            bpf_printk("  %d\n", ntohs(udph->dest));

            evt->ip.ipp = UDP_V4;
            evt->ip.port = ntohs(udph->dest);
        } else if (iph6->nexthdr == IPPROTO_TCP) { // Handle TCP packets for IPv6
            tcph = (void*)(iph6 + 1);
            if((void*)(tcph + 1) > data_end) goto err;

            bpf_printk("\nis tcp %d\n", ntohs(tcph->source));
            bpf_printk(" %d\n", ntohs(tcph->dest));

            evt->ip.ipp = TCP_V4;
            evt->ip.port = ntohs(tcph->dest);
        } else {
            goto err;
        }

        if(tcph || udph) {
            // Extract and log the destination IPv6 address
            __be32 daddr_high = iph6->daddr.in6_u.u6_addr32[0];
            __be32 daddr_mid = iph6->daddr.in6_u.u6_addr32[1];
            __be32 daddr_low = iph6->daddr.in6_u.u6_addr32[2];
            __be32 daddr_last = iph6->daddr.in6_u.u6_addr32[3];

            bpf_printk("dest ip is %08x:%08x:%08x:%08x\n", ntohl(daddr_high), ntohl(daddr_mid), ntohl(daddr_low), ntohl(daddr_last));
        } else {
            goto err;
        }

        bpf_probe_read_kernel(&evt->ip.addr.ipv6_daddr, sizeof(evt->ip.addr.ipv6_daddr), &iph6->daddr.in6_u.u6_addr8);

    } else if (arp) { // Handle ARP packets
        bpf_probe_read_kernel(&evt->arp, sizeof(evt->arp), arp);
        bpf_printk("arp");
    }

    rc = TC_ACT_SHOT; // Default to dropping the packet
    if(evt->eth_type == ETH_P_ARP) rc = TC_ACT_OK; // Allow ARP packets
    bpf_printk("%d\n", evt->ip.port);

    // Check if the packet's destination port is in the allowed list
    u32 i = 0;
    for(i = 0; i < 10; i++) {
        u16 *port;
        u32 key = i;
        port = bpf_map_lookup_elem(&ports, &key);
        if(port && evt->ip.port == *port && *port != 0) {
            rc = TC_ACT_OK; // Allow packets to/from allowed ports
        }
    }

    if(rc == TC_ACT_SHOT) {
        evt->pkt_state = BLOCKED; // Mark the packet as blocked
    } else {
        evt->pkt_state = ALLOWED; // Mark the packet as allowed
    }
    bpf_ringbuf_submit(evt, 0); // Submit the event to the ring buffer
    evt = NULL;

err:
    if (evt) bpf_ringbuf_discard(evt, 0); // Discard the event if not submitted
rb_err:
    return rc; // Return the action to take on the packet
}

// License declaration
char LICENSE[] SEC("license") = "GPL";
