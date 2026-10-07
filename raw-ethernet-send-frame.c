/*
Program Name: raw-ethernet-send-frame.c
Purpose:
Send a real Ethernet frame using Linux raw socket.

Compile:
gcc raw-ethernet-send-frame.c -o raw-ethernet-send-frame

Run:
sudo ./raw-ethernet-send-frame <interface> <destination-mac> <payload>

Example:
sudo ./raw-ethernet-send-frame eth0 ff:ff:ff:ff:ff:ff "Hello Network"

Frames sent with custom EtherType 0x88B5 may not be processed by normal protocol handlers and are intended only for controlled observation using another raw-socket receiver or Wireshark.
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

#define CUSTOM_ETHERTYPE 0x88B5
#define MAX_PAYLOAD_SIZE 1500

/*Ethernet FCS is normally added by the NIC hardware and is therefore not included in the user-created frame buffer.*/

void printMAC(unsigned char *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", mac[i]);
        if (i < 5) printf(":");
    }
}

int parseMAC(const char *macStr, unsigned char *mac) {
    return sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2],
                  &mac[3], &mac[4], &mac[5]) == 6;
}

int getInterfaceMAC(int sockfd, const char *interfaceName, unsigned char *mac) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Unable to get interface MAC address");
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
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
    if (argc != 4) {
        printf("Usage: sudo %s <interface> <destination-mac> <payload>\n", argv[0]);
        printf("Example: sudo %s eth0 ff:ff:ff:ff:ff:ff \"Hello Network\"\n", argv[0]);
        return 1;
    }

    char *interfaceName = argv[1];
    char *dstMacStr = argv[2];
    char *payload = argv[3];
    unsigned char dstMAC[6];
    unsigned char srcMAC[6];

    if (!parseMAC(dstMacStr, dstMAC)) {
        printf("Invalid destination MAC format.\n");
        return 1;
    }

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(CUSTOM_ETHERTYPE));
    if (sockfd < 0) {
        perror("Raw socket creation failed");
        printf("Run using sudo.\n");
        return 1;
    }

    if (getInterfaceMAC(sockfd, interfaceName, srcMAC) < 0) {
        close(sockfd);
        return 1;
    }

    int ifIndex = getInterfaceIndex(sockfd, interfaceName);
    if (ifIndex < 0) {
        close(sockfd);
        return 1;
    }

    unsigned char frame[ETH_FRAME_LEN];
    memset(frame, 0, ETH_FRAME_LEN);

    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_dest, dstMAC, 6);
    memcpy(eth->h_source, srcMAC, 6);
    eth->h_proto = htons(CUSTOM_ETHERTYPE);

    int payloadLen = strlen(payload);
    if (payloadLen > MAX_PAYLOAD_SIZE) {
        printf("Payload too large.\n");
        close(sockfd);
        return 1;
    }

    memcpy(frame + sizeof(struct ethhdr), payload, payloadLen);
    int frameLen = sizeof(struct ethhdr) + payloadLen;

    if (frameLen < 60) {
        frameLen = 60;   // Minimum Ethernet frame size without FCS
    }

    struct sockaddr_ll socketAddress;
    memset(&socketAddress, 0, sizeof(socketAddress));
    socketAddress.sll_family = AF_PACKET;
    socketAddress.sll_ifindex = ifIndex;
    socketAddress.sll_halen = ETH_ALEN;
    memcpy(socketAddress.sll_addr, dstMAC, 6);

    printf("\n--- Ethernet Frame to Send ---\n");
    printf("Interface       : %s\n", interfaceName);
    printf("Source MAC      : ");
    printMAC(srcMAC);
    printf("\nDestination MAC : ");
    printMAC(dstMAC);
    printf("\nEtherType       : 0x%04X", CUSTOM_ETHERTYPE);
    printf("\nPayload         : %s\n", payload);

    int sentBytes = sendto(sockfd, frame, frameLen, 0,
                           (struct sockaddr *)&socketAddress,
                           sizeof(socketAddress));

    if (sentBytes < 0) {
        perror("Frame send failed");
        close(sockfd);
        return 1;
    }

    printf("\nFrame sent successfully. Bytes sent: %d\n", sentBytes);
    close(sockfd);
    return 0;
}