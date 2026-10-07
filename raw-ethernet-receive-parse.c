/*
Program Name: raw-ethernet-receive-parse.c
Purpose:
Capture real Ethernet frames using Linux raw socket and parse:
1. Destination MAC address
2. Source MAC address
3. EtherType
4. Frame accept/drop decision based on MAC address
5. Protocol identification: IPv4, ARP, IPv6

Run:
gcc raw-ethernet-receive-parse.c -o raw-ethernet-receive-parse
sudo ./raw-ethernet-receive-parse <interface-name>

Example:
sudo ./raw-ethernet-receive-parse eth0
sudo ./raw-ethernet-receive-parse ens33
sudo ./raw-ethernet-receive-parse enp0s3
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

#define MAX_FRAME_SIZE 65536
#define CAPTURE_COUNT 10

// Print MAC Address
void printMAC(unsigned char *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", mac[i]);
        if (i < 5) {
            printf(":");
        }
    }
}

// Compare MAC addresses
int isEqualMAC(unsigned char *a, unsigned char *b) {
    return memcmp(a, b, 6) == 0;
}

// Check Broadcast MAC: FF:FF:FF:FF:FF:FF
int isBroadcast(unsigned char *mac) {
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0xFF) {
            return 0;
        }
    }
    return 1;
}

// Check Multicast MAC
// In Ethernet, if least significant bit of first byte is 1, it is multicast
int isMulticast(unsigned char *mac) {
    return (mac[0] & 0x01);
}

// Get MAC address of selected network interface
int getInterfaceMAC(int sockfd, char *interfaceName, unsigned char *deviceMAC) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Unable to get interface MAC address");
        return -1;
    }
    memcpy(deviceMAC, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

// Get interface index
int getInterfaceIndex(int sockfd, char *interfaceName) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Unable to get interface index");
        return -1;
    }
    return ifr.ifr_ifindex;
}

// Protocol identification based on EtherType
void identifyProtocol(unsigned short etherType) {
    printf("\n--- Protocol Identification ---\n");
    if (etherType == ETH_P_IP) {
        printf("Protocol: IPv4  --> Forward to IP Layer\n");
    }
    else if (etherType == ETH_P_ARP) {
        printf("Protocol: ARP   --> Forward to ARP Module\n");
    }
    else if (etherType == ETH_P_IPV6) {
        printf("Protocol: IPv6  --> Forward to IPv6 Layer\n");
    }
    else {
        printf("Protocol: Other / Unknown\n");
    }
}

// Main function
int main(int argc, char *argv[]) {
    int sockfd;
    unsigned char buffer[MAX_FRAME_SIZE];
    unsigned char deviceMAC[6];
    char *interfaceName;

    if (argc != 2) {
        printf("Usage: sudo %s <interface-name>\n", argv[0]);
        printf("Example: sudo %s eth0\n", argv[0]);
        printf("Use 'ip link' command to find interface name.\n");
        return 1;
    }
    interfaceName = argv[1];

    // Create raw socket to capture all Ethernet frames
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Raw socket creation failed");
        printf("Run this program using sudo.\n");
        return 1;
    }

    // Get MAC address of selected interface
    if (getInterfaceMAC(sockfd, interfaceName, deviceMAC) < 0) {
        close(sockfd);
        return 1;
    }

    // Get interface index
    int interfaceIndex = getInterfaceIndex(sockfd, interfaceName);
    if (interfaceIndex < 0) {
        close(sockfd);
        return 1;
    }

    // Bind raw socket to selected interface
    struct sockaddr_ll socketAddress;
    memset(&socketAddress, 0, sizeof(socketAddress));
    socketAddress.sll_family = AF_PACKET;
    socketAddress.sll_protocol = htons(ETH_P_ALL);
    socketAddress.sll_ifindex = interfaceIndex;

    if (bind(sockfd, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return 1;
    }

    printf("\n========================================\n");
    printf(" Real Ethernet Frame Receiver and Parser\n");
    printf("========================================\n");
    printf("Interface Name : %s\n", interfaceName);
    printf("Device MAC     : ");
    printMAC(deviceMAC);
    printf("\n");
    printf("\nCapturing %d Ethernet frames...\n", CAPTURE_COUNT);
    printf("Generate traffic using ping in another terminal if needed.\n");

    for (int frameNo = 1; frameNo <= CAPTURE_COUNT; frameNo++) {
        ssize_t frameLength;
        frameLength = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);

        if (frameLength < 0) {
            perror("Packet receive failed");
            close(sockfd);
            return 1;
        }

        // Ethernet header is present at the start of the frame
        struct ethhdr *eth = (struct ethhdr *)buffer;
        unsigned char *dstMAC = eth->h_dest;
        unsigned char *srcMAC = eth->h_source;
        unsigned short etherType = ntohs(eth->h_proto);

        printf("\n\n========================================\n");
        printf("Frame No. %d\n", frameNo);
        printf("========================================\n");
        printf("Frame Length    : %ld bytes\n", frameLength);
        printf("Destination MAC : ");
        printMAC(dstMAC);
        printf("\nSource MAC      : ");
        printMAC(srcMAC);
        printf("\nEtherType       : 0x%04X\n", etherType);

        // Step 1: MAC Address Check
        printf("\n--- MAC Address Decision ---\n");
        if (isEqualMAC(dstMAC, deviceMAC)) {
            printf("MAC Match        --> Frame Accepted\n");
        }
        else if (isBroadcast(dstMAC)) {
            printf("Broadcast Frame  --> Frame Accepted\n");
        }
        else if (isMulticast(dstMAC)) {
            printf("Multicast Frame  --> Accepted if subscribed\n");
        }
        else {
            printf("MAC Mismatch     --> Frame not intended for this device\n");
            printf("Note: In a normal NIC, such frames are usually filtered before reaching the OS.\n");
        }

        // Step 2: CRC / FCS note
        printf("\n--- CRC / FCS Check ---\n");
        printf("FCS is normally checked by NIC hardware and removed before packet reaches this program.\n");
        printf("Therefore, this program cannot directly verify Ethernet FCS.\n");

        // Step 3: EtherType Handling
        identifyProtocol(etherType);
        printf("\nEthernet Header Parsed --> Payload can be passed to upper layer conceptually.\n");
    }

    close(sockfd);
    return 0;
}