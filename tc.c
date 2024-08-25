#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/pkt_cls.h>
#include <linux/if_arp.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <string.h>

#include "tc.h"
#include "tc.skel.h"

#define LO_IFINDEX 2  // Index of the loopback interface
#define BUFFER_SIZE 256

static volatile bool exiting = false;  // Flag to signal exit

// Function to return the string representation of the IP protocol
char* print_proto(enum ip_proto ipp)
{
	switch(ipp) {
    default:
      return "OTHER";  // Default case for unknown protocols
		case TCP_V4:
			return "TCP ipv4";  // IPv4 TCP protocol
		case TCP_V6:
			return "TCP ipv6";  // IPv6 TCP protocol
		case UDP_V4:
			return "UDP ipv4";  // IPv4 UDP protocol
		case UDP_V6:
			return "UDP ipv6";  // IPv6 UDP protocol
	}
}

// Function to perform reverse DNS lookup to get the hostname and service name
void reverse_lookup(const char *ip, int port) {
    struct sockaddr_storage sa;  // Structure to hold address information (IPv4/IPv6)
    char host[1024];  // Buffer to store hostname
    char service[20];  // Buffer to store service name
    memset(&sa, 0, sizeof(sa));  // Initialize the address structure to zero

    // Determine if the IP is IPv4 or IPv6 and set up the address structure accordingly
    if (strchr(ip, ':')) {  // Check for ':' to identify IPv6 address
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sa;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip, &sa6->sin6_addr) != 1) {
            fprintf(stderr, "Invalid IPv6 address: %s\n", ip);
            return;
        }
    } else {  // Otherwise, treat as IPv4 address
        struct sockaddr_in *sa4 = (struct sockaddr_in *)&sa;
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &sa4->sin_addr) != 1) {
            fprintf(stderr, "Invalid IPv4 address: %s\n", ip);
            return;
        }
    }

    // Perform reverse DNS lookup
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), service, sizeof(service), 0) != 0) {
        fprintf(stderr, "Could not resolve hostname for IP: %s, Port: %d\n", ip, port);
        return;
    }

    // Print the resolved hostname and service
    printf("Hostname: %s\n", host);
    if (strlen(service) == 0 || strcmp(service, "0") == 0 || atoi(service) == port) {
        printf("Service: Unknown\n");  // If service name is empty or matches port, report as unknown
    } else {
        printf("Service: %s\n", service);  // Print the resolved service name
    } 
}

// Function to increase the memory lock limit (RLIMIT_MEMLOCK)
static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

// Signal handler to set the exiting flag
static void sig_handler(int sig)
{
	exiting = true;
}

// Function to handle events from the BPF ring buffer
static int handle_evt(void *ctx, void *data, size_t sz)
{	
	struct tc_evt *evt = data;  // Cast the data to the expected event type

	// Print whether the packet is allowed or blocked
	if(evt->pkt_state == ALLOWED) printf("ALLOWED ");
	else printf("BLOCKED ");

	// Handle events based on Ethernet type
	if(evt->eth_type == ETH_P_IP || evt->eth_type == ETH_P_IPV6) {
		fflush(stdout);

		// Print the command name, thread group ID, and process ID
		printf("comm %s\n", evt->comm);
		printf("tgid %d :: pid %d\n", evt->tgid, evt->pid);	
		
		// Handle IPv4 and IPv6 packets
		if(evt->ip.ipp == TCP_V4 || evt->ip.ipp == UDP_V4) {
			char addr[15];
			memset(addr, 0, sizeof(addr));
			snprintf(addr, sizeof(addr), "%d.%d.%d.%d",
				evt->ip.addr.ipv4_daddr[0],
				evt->ip.addr.ipv4_daddr[1],
				evt->ip.addr.ipv4_daddr[2],
				evt->ip.addr.ipv4_daddr[3]);
			printf("dest: %s\n", addr);

      reverse_lookup(addr, evt->ip.port);  // Perform reverse lookup for IPv4 address

		} else {
			printf("dest: ");
      char addr[30];
      char a[6];
      memset(addr, 0, sizeof(addr));
      for (int i = 0; i < 14; i+=2) {
        snprintf(a, 6, "%02x%02x:",
                 evt->ip.addr.ipv6_daddr[i],
                 evt->ip.addr.ipv6_daddr[i+1]);
        strncat(addr, a, 6);
      }
      snprintf(a, 6, "%02x%02x",
               evt->ip.addr.ipv6_daddr[14],
               evt->ip.addr.ipv6_daddr[15]);
      strncat(addr, a, 6);
      printf("%s\n", addr);
      
      reverse_lookup(addr, evt->ip.port);  // Perform reverse lookup for IPv6 address
		}
		printf("port: %d\n", evt->ip.port);
		printf("protocol %s\n", print_proto(evt->ip.ipp));  // Print the protocol type
	} else {  // Handle ARP packets
		printf("eth type 0x%04x\n", evt->eth_type);
		printf("comm: %s\n", evt->comm);  // Print the command name (appears twice which might be unnecessary)
		printf("tgid %d :: pid %d\n", evt->tgid, evt->pid);

		// Print ARP packet details
		printf("hardware: %d\n", evt->arp.ar_hrd);
		printf("proto: %d\n", evt->arp.ar_pro);
		printf("len hard: %d\n", evt->arp.ar_hln);
		printf("len proto: %d\n", evt->arp.ar_pln);
		printf("op: %d\n", evt->arp.ar_op);
	}

	printf("\n");
	fflush(stdout);
	return 0;
}

// Function to add a port to the allowed ports map
void allow_port(int map_fd, uint16_t port)
{
	static uint32_t key = 0;
	bpf_map_update_elem(map_fd, &key, &port, BPF_ANY);  // Update the map with the new port
	key ++;
}

int main(int argc, char **argv)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = LO_IFINDEX, .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1);
	bump_memlock_rlimit();  // Increase memory lock limit

	signal(SIGINT, sig_handler);  // Set up signal handlers for graceful exit
	signal(SIGTERM, sig_handler);

	struct tc *skel = tc__open_and_load();  // Load the BPF program
	skel->bss->my_pid = getpid();  // Set the current process ID in the BPF program

	// Configure and attach the BPF TC program to the egress hook
	bpf_tc_hook_create(&hook);
	hook.attach_point = BPF_TC_CUSTOM;
	hook.parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
	opts.prog_fd = bpf_program__fd(skel->progs.handle_egress);
	opts.prog_id = 0;
	opts.flags = BPF_TC_F_REPLACE;

	bpf_tc_attach(&hook, &opts);

	// Add allowed ports from command-line arguments to the BPF map
	int map_fd = bpf_map__fd(skel->maps.ports);
	for (int i = 0; i < argc; i++) {
		int port = atoi(argv[i]);
		allow_port(map_fd, port);
	}

	// Create a ring buffer for event handling
	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_evt, NULL, NULL);
	
	// Poll for events until the exit signal is received
	while (!exiting) {
		ring_buffer__poll(rb, 1000);
	}

	// Detach and destroy the BPF TC program
	opts.flags = opts.prog_id = opts.prog_fd = 0;
    int dtch = bpf_tc_detach(&hook, &opts);
    int dstr = bpf_tc_hook_destroy(&hook);

    // Print the results of detach and destroy operations
    printf("%d -- %d\n", dtch, dstr);
    
    return 0;
}
