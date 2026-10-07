/*
Program Name: raw_ip_router_parse.c
Purpose: Capture an actual IPv4 packet and demonstrate router processing: Parse IPv4 header, check destination, check TTL, perform longest-prefix matching, select next hop/interface, decrement TTL, and recalculate checksum.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define BUFFER_SIZE 65536
#define MAX_ROUTES 10

typedef struct {
    const char *network;
    unsigned int prefix_length;
    const char *next_hop;
    const char *outgoing_interface;
} route_definition_t;

typedef struct {
    uint32_t network;
    uint32_t mask;
    unsigned int prefix_length;
    uint32_t next_hop;
    char outgoing_interface[IFNAMSIZ];
} route_entry_t;

/* Students may modify this routing table according to their Practical 3 topology. */
static const route_definition_t route_definitions[] = {
    {"10.0.0.0", 24, "0.0.0.0", "enp0s8"},
    {"11.0.0.0", 24, "0.0.0.0", "enp0s9"},
    {"192.168.0.0", 16, "10.0.2.2", "enp0s3"},
    {"0.0.0.0", 0, "10.0.2.2", "enp0s3"}
};

static unsigned short calculate_checksum(const void *data, size_t length) {
    const unsigned short *words = data;
    unsigned long sum = 0;
    while (length > 1) {
        sum += *words++;
        length -= 2;
    }
    if (length == 1) {
        unsigned short final_byte = 0;
        *((unsigned char *)&final_byte) = *((const unsigned char *)words);
        sum += final_byte;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFUL) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}

static uint32_t prefix_to_mask(unsigned int prefix_length) {
    if (prefix_length == 0) {
        return 0;
    }
    return htonl(0xFFFFFFFFU << (32U - prefix_length));
}

static int initialise_routes(route_entry_t *routes, size_t route_count) {
    for (size_t index = 0; index < route_count; index++) {
        struct in_addr network_address;
        struct in_addr next_hop_address;

        if (inet_pton(AF_INET, route_definitions[index].network, &network_address) != 1) { return -1; }
        if (inet_pton(AF_INET, route_definitions[index].next_hop, &next_hop_address) != 1) { return -1; }

        routes[index].mask = prefix_to_mask(route_definitions[index].prefix_length);
        routes[index].network = network_address.s_addr & routes[index].mask;
        routes[index].prefix_length = route_definitions[index].prefix_length;
        routes[index].next_hop = next_hop_address.s_addr;
        strncpy(routes[index].outgoing_interface, route_definitions[index].outgoing_interface, IFNAMSIZ - 1);
        routes[index].outgoing_interface[IFNAMSIZ - 1] = '\0';
    }
    return 0;
}

static const route_entry_t *longest_prefix_match(uint32_t destination_ip, const route_entry_t *routes, size_t route_count) {
    const route_entry_t *best_route = NULL;
    int best_prefix_length = -1;

    for (size_t index = 0; index < route_count; index++) {
        if ((destination_ip & routes[index].mask) == routes[index].network) {
            if ((int)routes[index].prefix_length > best_prefix_length) {
                best_route = &routes[index];
                best_prefix_length = (int)routes[index].prefix_length;
            }
        }
    }
    return best_route;
}

static int get_interface_index(int socket_fd, const char *interface_name) {
    struct ifreq request;
    memset(&request, 0, sizeof(request));
    strncpy(request.ifr_name, interface_name, IFNAMSIZ - 1);
    if (ioctl(socket_fd, SIOCGIFINDEX, &request) < 0) {
        perror("Unable to obtain interface index");
        return -1;
    }
    return request.ifr_ifindex;
}

static void print_ip_address(uint32_t address, char *output, size_t output_size) {
    struct in_addr value = { .s_addr = address };
    inet_ntop(AF_INET, &value, output, output_size);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: sudo %s <incoming-interface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *incoming_interface = argv[1];
    route_entry_t routes[MAX_ROUTES];
    const size_t route_count = sizeof(route_definitions) / sizeof(route_definitions[0]);

    if (route_count > MAX_ROUTES) {
        fprintf(stderr, "Too many routing-table entries.\n");
        return EXIT_FAILURE;
    }
    if (initialise_routes(routes, route_count) < 0) {
        fprintf(stderr, "Invalid routing-table definition.\n");
        return EXIT_FAILURE;
    }

    int socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (socket_fd < 0) {
        perror("Raw socket creation failed");
        fprintf(stderr, "Run the program using sudo.\n");
        return EXIT_FAILURE;
    }

    int interface_index = get_interface_index(socket_fd, incoming_interface);
    if (interface_index < 0) {
        close(socket_fd);
        return EXIT_FAILURE;
    }

    struct sockaddr_ll bind_address;
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_IP);
    bind_address.sll_ifindex = interface_index;

    if (bind(socket_fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) < 0) {
        perror("Socket bind failed");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    printf("========================================\n");
    printf("IPv4 Router Processing Demonstration\n");
    printf("========================================\n");
    printf("Incoming interface: %s\n\n", incoming_interface);
    printf("Configured routing table:\n");

    for (size_t index = 0; index < route_count; index++) {
        char network[INET_ADDRSTRLEN];
        char next_hop[INET_ADDRSTRLEN];
        print_ip_address(routes[index].network, network, sizeof(network));
        print_ip_address(routes[index].next_hop, next_hop, sizeof(next_hop));
        printf("%s/%u via %s dev %s\n", network, routes[index].prefix_length, next_hop, routes[index].outgoing_interface);
    }

    printf("\nWaiting for an IPv4 packet...\n");
    unsigned char buffer[BUFFER_SIZE];

    while (1) {
        struct sockaddr_ll packet_information;
        socklen_t information_length = sizeof(packet_information);
        ssize_t received_length = recvfrom(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&packet_information, &information_length);

        if (received_length < 0) {
            perror("Packet reception failed");
            close(socket_fd);
            return EXIT_FAILURE;
        }

        if (packet_information.sll_pkttype == PACKET_OUTGOING) { continue; }
        if ((size_t)received_length < sizeof(struct ethhdr) + sizeof(struct iphdr)) { continue; }

        struct ethhdr *ethernet_header = (struct ethhdr *)buffer;
        if (ntohs(ethernet_header->h_proto) != ETH_P_IP) { continue; }

        struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        unsigned int ip_header_length = ip_header->ihl * 4U;

        if (ip_header_length < sizeof(struct iphdr)) { continue; }

        char source_ip[INET_ADDRSTRLEN];
        char destination_ip[INET_ADDRSTRLEN];
        print_ip_address(ip_header->saddr, source_ip, sizeof(source_ip));
        print_ip_address(ip_header->daddr, destination_ip, sizeof(destination_ip));

        printf("\n========================================\n");
        printf("Packet received\n");
        printf("========================================\n");
        printf("Source IP       : %s\n", source_ip);
        printf("Destination IP  : %s\n", destination_ip);
        printf("Incoming TTL    : %u\n", ip_header->ttl);
        printf("Protocol        : %u\n", ip_header->protocol);
        printf("Incoming checksum: 0x%04X\n", ntohs(ip_header->check));

        if (ip_header->ttl <= 1) {
            printf("Router decision : Drop packet\n");
            printf("Reason          : TTL would become zero\n");
            printf("Expected action : Send ICMP Time Exceeded\n");
            break;
        }

        const route_entry_t *selected_route = longest_prefix_match(ip_header->daddr, routes, route_count);

        if (selected_route == NULL) {
            printf("Router decision : Drop packet\n");
            printf("Reason          : No matching route\n");
            printf("Expected action : Send ICMP Destination Unreachable\n");
            break;
        }

        char route_network[INET_ADDRSTRLEN];
        char next_hop[INET_ADDRSTRLEN];
        print_ip_address(selected_route->network, route_network, sizeof(route_network));
        print_ip_address(selected_route->next_hop, next_hop, sizeof(next_hop));

        printf("Selected route  : %s/%u\n", route_network, selected_route->prefix_length);

        if (selected_route->next_hop == 0) {
            printf("Next hop        : Directly connected destination\n");
        } else {
            printf("Next hop        : %s\n", next_hop);
        }
        printf("Outgoing interface: %s\n", selected_route->outgoing_interface);

        /* Use a copy so the received packet buffer is not retransmitted or altered outside this demonstration. */
        unsigned char modified_header[60];
        if (ip_header_length > sizeof(modified_header)) {
            printf("IPv4 header is too large for demonstration.\n");
            break;
        }

        memcpy(modified_header, ip_header, ip_header_length);
        struct iphdr *forward_header = (struct iphdr *)modified_header;
        
        forward_header->ttl--;
        forward_header->check = 0;
        forward_header->check = calculate_checksum(forward_header, ip_header_length);

        printf("Outgoing TTL    : %u\n", forward_header->ttl);
        printf("New checksum    : 0x%04X\n", ntohs(forward_header->check));
        printf("ARP requirement : Resolve the next-hop IP to a MAC address on the outgoing network.\n");
        printf("Forwarding result: Packet is ready for re-encapsulation in a new Ethernet frame.\n");
        break;
    }

    close(socket_fd);
    return EXIT_SUCCESS;
}