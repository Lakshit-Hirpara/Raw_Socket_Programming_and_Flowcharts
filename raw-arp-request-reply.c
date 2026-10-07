/*
Program Name: raw-arp-request-reply.c
Purpose:
Send real ARP Request and capture ARP Reply.

Compile:
gcc raw-arp-request-reply.c -o raw-arp-request-reply

Run:
sudo ./raw-arp-request-reply <interface> <target-ip>

Example:
sudo ./raw-arp-request-reply eth0 192.168.1.1

If no ARP reply is received, stop the program using Ctrl+C and verify that the target IP is active and belongs to the same local subnet.
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

int getInterfaceInfo(int sockfd, const char *interfaceName,
                     int *ifIndex,
                     unsigned char *mac,
                     unsigned char *ip) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Unable to get interface index");
        return -1;
    }
    *ifIndex = ifr.ifr_ifindex;

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Unable to get MAC address");
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("Unable to get IP address");
        return -1;
    }
    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(ip, &ipaddr->sin_addr, 4);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: sudo %s <interface> <target-ip>\n", argv[0]);
        printf("Example: sudo %s eth0 192.168.1.1\n", argv[0]);
        return 1;
    }

    char *interfaceName = argv[1];
    char *targetIPString = argv[2];

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("Raw socket creation failed");
        printf("Run using sudo.\n");
        return 1;
    }

    int ifIndex;
    unsigned char sourceMAC[6];
    unsigned char sourceIP[4];

    if (getInterfaceInfo(sockfd, interfaceName, &ifIndex, sourceMAC, sourceIP) < 0) {
        close(sockfd);
        return 1;
    }

    unsigned char targetIP[4];
    if (inet_pton(AF_INET, targetIPString, targetIP) != 1) {
        printf("Invalid target IP address.\n");
        close(sockfd);
        return 1;
    }

    unsigned char broadcastMAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char zeroMAC[6] = {0, 0, 0, 0, 0, 0};

    unsigned char packet[sizeof(struct ethhdr) + sizeof(struct arp_header)];
    memset(packet, 0, sizeof(packet));

    struct ethhdr *eth = (struct ethhdr *)packet;
    struct arp_header *arp = (struct arp_header *)(packet + sizeof(struct ethhdr));

    memcpy(eth->h_dest, broadcastMAC, 6);
    memcpy(eth->h_source, sourceMAC, 6);
    eth->h_proto = htons(ETH_P_ARP);

    arp->hardware_type = htons(ARPHRD_ETHER);
    arp->protocol_type = htons(ETH_P_IP);
    arp->hardware_size = 6;
    arp->protocol_size = 4;
    arp->opcode = htons(ARPOP_REQUEST);
    memcpy(arp->sender_mac, sourceMAC, 6);
    memcpy(arp->sender_ip, sourceIP, 4);
    memcpy(arp->target_mac, zeroMAC, 6);
    memcpy(arp->target_ip, targetIP, 4);

    struct sockaddr_ll socketAddress;
    memset(&socketAddress, 0, sizeof(socketAddress));
    socketAddress.sll_family = AF_PACKET;
    socketAddress.sll_ifindex = ifIndex;
    socketAddress.sll_halen = ETH_ALEN;
    memcpy(socketAddress.sll_addr, broadcastMAC, 6);

    printf("\n=====================================\n");
    printf("Sending ARP Request\n");
    printf("=====================================\n");
    printf("Source MAC : ");
    printMAC(sourceMAC);
    printf("\nSource IP  : ");
    printIP(sourceIP);
    printf("\nTarget IP  : ");
    printIP(targetIP);
    printf("\nDestination MAC : FF:FF:FF:FF:FF:FF\n");

    ssize_t sent = sendto(sockfd, packet, sizeof(packet), 0,
                          (struct sockaddr *)&socketAddress,
                          sizeof(socketAddress));

    if (sent < 0) {
        perror("ARP Request send failed");
        close(sockfd);
        return 1;
    }

    printf("\nARP Request sent successfully.\n");
    printf("Waiting for ARP Reply...\n");

    while (1) {
        unsigned char buffer[65536];
        ssize_t length = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);

        if (length < 0) {
            perror("Receive failed");
            close(sockfd);
            return 1;
        }

        struct ethhdr *recvEth = (struct ethhdr *)buffer;
        if (ntohs(recvEth->h_proto) != ETH_P_ARP) {
            continue;
        }

        struct arp_header *recvArp =
            (struct arp_header *)(buffer + sizeof(struct ethhdr));

        if (ntohs(recvArp->opcode) == ARPOP_REPLY &&
            memcmp(recvArp->sender_ip, targetIP, 4) == 0) {
            printf("\n=====================================\n");
            printf("ARP Reply Received\n");
            printf("=====================================\n");
            printf("Sender IP  : ");
            printIP(recvArp->sender_ip);
            printf("\nSender MAC : ");
            printMAC(recvArp->sender_mac);
            printf("\n\nMeaning: ");
            printIP(recvArp->sender_ip);
            printf(" is at ");
            printMAC(recvArp->sender_mac);
            printf("\n");
            break;
        }
    }

    close(sockfd);
    return 0;
}