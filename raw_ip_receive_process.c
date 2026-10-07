/*
Program Name: raw_ip_receive_process.c
Purpose: Capture actual IPv4 packets from a Linux interface and process: IPv4 version, Header length, Total length, Identification, TTL, Protocol, Header checksum, Source and destination IP addresses.
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
#define PACKET_COUNT 10

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

static const char *protocol_name(unsigned char protocol) {
    switch (protocol) {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        default: return "Other";
    }
}

int main(int argc, char *argv[]) {
    int socket_fd;
    int interface_index;
    unsigned char buffer[BUFFER_SIZE];

    if (argc != 2) {
        fprintf(stderr, "Usage: sudo %s <interface-name>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *interface_name = argv[1];

    socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (socket_fd < 0) {
        perror("Raw socket creation failed");
        fprintf(stderr, "Run the program using sudo.\n");
        return EXIT_FAILURE;
    }

    interface_index = get_interface_index(socket_fd, interface_name);
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

    printf("Capturing IPv4 packets on %s...\n", interface_name);
    printf("Generate traffic using ping or a web browser.\n\n");

    for (int packet_number = 1; packet_number <= PACKET_COUNT; packet_number++) {
        struct sockaddr_ll packet_information;
        socklen_t information_length = sizeof(packet_information);
        ssize_t received_length = recvfrom(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&packet_information, &information_length);

        if (received_length < 0) {
            perror("Packet reception failed");
            close(socket_fd);
            return EXIT_FAILURE;
        }

        if (packet_information.sll_pkttype == PACKET_OUTGOING) {
            packet_number--;
            continue;
        }

        if ((size_t)received_length < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
            packet_number--;
            continue;
        }

        struct ethhdr *ethernet_header = (struct ethhdr *)buffer;
        if (ntohs(ethernet_header->h_proto) != ETH_P_IP) {
            packet_number--;
            continue;
        }

        struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        unsigned int ip_header_length = ip_header->ihl * 4U;

        if (ip_header_length < sizeof(struct iphdr)) {
            printf("Invalid IPv4 header length.\n");
            continue;
        }

        char source_ip[INET_ADDRSTRLEN];
        char destination_ip[INET_ADDRSTRLEN];

        struct in_addr source_address = { .s_addr = ip_header->saddr };
        struct in_addr destination_address = { .s_addr = ip_header->daddr };

        inet_ntop(AF_INET, &source_address, source_ip, sizeof(source_ip));
        inet_ntop(AF_INET, &destination_address, destination_ip, sizeof(destination_ip));

        printf("========================================\n");
        printf("IPv4 Packet Number: %d\n", packet_number);
        printf("========================================\n");
        printf("Captured length     : %zd bytes\n", received_length);
        printf("Version             : %u\n", ip_header->version);
        printf("Header length       : %u bytes\n", ip_header_length);
        printf("Total length        : %u bytes\n", ntohs(ip_header->tot_len));
        printf("Identification      : %u\n", ntohs(ip_header->id));
        printf("TTL                 : %u\n", ip_header->ttl);
        printf("Protocol            : %u (%s)\n", ip_header->protocol, protocol_name(ip_header->protocol));
        printf("Header checksum     : 0x%04X\n", ntohs(ip_header->check));
        printf("Source IP           : %s\n", source_ip);
        printf("Destination IP      : %s\n", destination_ip);

        if (ip_header->ttl == 0) {
            printf("Decision            : Drop packet; TTL is zero.\n");
        } else {
            printf("Decision            : Packet can be processed.\n");
        }
        printf("\n");
    }

    close(socket_fd);
    return EXIT_SUCCESS;
}