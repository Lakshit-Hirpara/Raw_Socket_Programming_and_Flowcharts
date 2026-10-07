/*
Compile:
gcc raw_ethernet_capture.c -o raw_ethernet_capture
Run:
sudo ./raw_ethernet_capture
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

void print_mac(unsigned char *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", mac[i]);
        if (i < 5) {
            printf(":");
        }
    }
}

int main() {
    int sockfd;
    unsigned char buffer[65536];

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Raw socket creation failed");
        printf("Try running with sudo.\n");
        return 1;
    }

    printf("Capturing Ethernet frames...\n");
    printf("Press Ctrl+C to stop.\n\n");

    while (1) {
        ssize_t data_size = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size < 0) {
            perror("Packet receive failed");
            close(sockfd);
            return 1;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;

        printf("----------------------------------\n");
        printf("Frame Length      : %ld bytes\n", data_size);
        printf("Destination MAC   : ");
        print_mac(eth->h_dest);
        printf("\nSource MAC        : ");
        print_mac(eth->h_source);

        unsigned short ether_type = ntohs(eth->h_proto);
        printf("\nEtherType         : 0x%04X", ether_type);

        if (ether_type == ETH_P_IP) {
            printf(" (IPv4)");
        }
        else if (ether_type == ETH_P_ARP) {
            printf(" (ARP)");
        }
        else if (ether_type == ETH_P_IPV6) {
            printf(" (IPv6)");
        }
        else {
            printf(" (Other)");
        }
        printf("\n");
    }

    close(sockfd);
    return 0;
}