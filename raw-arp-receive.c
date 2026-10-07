/*
Program Name: raw-arp-receive.c
Purpose:
Capture real ARP packets and display Ethernet + ARP header fields.

Compile:
gcc raw-arp-receive.c -o raw-arp-receive

Run:
sudo ./raw-arp-receive <interface>

Example:
sudo ./raw-arp-receive eth0

Generate ARP traffic in another terminal:
ping -c 4 <gateway-ip>
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define ARP_CAPTURE_COUNT 5

struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_size;
    unsigned char protocol_size;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};

void printMAC(unsigned char *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", mac[i]);
        if (i < 5) printf(":");
    }
}

void printIP(unsigned char *ip) {
    printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

int getInterfaceIndex(int sockfd, const char *interfaceName) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Unable to get interface index");
        return -1;
    }
    return ifr.ifr_ifindex;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: sudo %s <interface>\n", argv[0]);
        return 1;
    }

    char *interfaceName = argv[1];

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("Raw socket creation failed");
        printf("Run using sudo.\n");
        return 1;
    }

    int ifIndex = getInterfaceIndex(sockfd, interfaceName);
    if (ifIndex < 0) {
        close(sockfd);
        return 1;
    }

    struct sockaddr_ll socketAddress;
    memset(&socketAddress, 0, sizeof(socketAddress));
    socketAddress.sll_family = AF_PACKET;
    socketAddress.sll_protocol = htons(ETH_P_ARP);
    socketAddress.sll_ifindex = ifIndex;

    if (bind(sockfd, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return 1;
    }

    printf("\nCapturing ARP packets on interface: %s\n", interfaceName);
    printf("Generate traffic using: ping -c 4 <gateway-ip>\n");

    for (int count = 1; count <= ARP_CAPTURE_COUNT; count++) {
        unsigned char buffer[65536];
        ssize_t length = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);

        if (length < 0) {
            perror("Receive failed");
            close(sockfd);
            return 1;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;
        struct arp_header *arp = (struct arp_header *)(buffer + sizeof(struct ethhdr));

        printf("\n=====================================\n");
        printf("ARP Packet No. %d\n", count);
        printf("=====================================\n");

        printf("\n[ Ethernet Header ]\n");
        printf("Destination MAC : ");
        printMAC(eth->h_dest);
        printf("\nSource MAC      : ");
        printMAC(eth->h_source);
        printf("\nEtherType       : 0x%04X", ntohs(eth->h_proto));

        printf("\n\n[ ARP Header ]\n");
        printf("Hardware Type   : %u\n", ntohs(arp->hardware_type));
        printf("Protocol Type   : 0x%04X\n", ntohs(arp->protocol_type));
        printf("Hardware Size   : %u\n", arp->hardware_size);
        printf("Protocol Size   : %u\n", arp->protocol_size);

        unsigned short opcode = ntohs(arp->opcode);
        printf("Opcode          : %u ", opcode);
        if (opcode == ARPOP_REQUEST) {
            printf("(ARP Request)\n");
        }
        else if (opcode == ARPOP_REPLY) {
            printf("(ARP Reply)\n");
        }
        else {
            printf("(Other)\n");
        }

        printf("Sender MAC      : ");
        printMAC(arp->sender_mac);
        printf("\nSender IP       : ");
        printIP(arp->sender_ip);
        printf("\nTarget MAC      : ");
        printMAC(arp->target_mac);
        printf("\nTarget IP       : ");
        printIP(arp->target_ip);
        printf("\n");
    }

    close(sockfd);
    return 0;
}