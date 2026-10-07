/*
Program Name: raw_ip_send_process.c
Purpose: Construct and send an IPv4 packet containing an ICMP Echo Request.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

#define PAYLOAD_TEXT "ITUC201 Raw IPv4 Packet"

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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: sudo %s <source-ip> <destination-ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *source_ip_string = argv[1];
    const char *destination_ip_string = argv[2];

    unsigned char packet[1500];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip_header = (struct iphdr *)packet;
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct iphdr));
    unsigned char *payload = packet + sizeof(struct iphdr) + sizeof(struct icmphdr);

    size_t payload_length = strlen(PAYLOAD_TEXT);
    memcpy(payload, PAYLOAD_TEXT, payload_length);

    size_t icmp_length = sizeof(struct icmphdr) + payload_length;
    size_t packet_length = sizeof(struct iphdr) + icmp_length;

    struct in_addr source_address;
    struct in_addr destination_address;

    if (inet_pton(AF_INET, source_ip_string, &source_address) != 1) {
        fprintf(stderr, "Invalid source IPv4 address.\n");
        return EXIT_FAILURE;
    }

    if (inet_pton(AF_INET, destination_ip_string, &destination_address) != 1) {
        fprintf(stderr, "Invalid destination IPv4 address.\n");
        return EXIT_FAILURE;
    }

    /* Prepare ICMP Echo Request. */
    icmp_header->type = ICMP_ECHO;
    icmp_header->code = 0;
    icmp_header->un.echo.id = htons((unsigned short)getpid());
    icmp_header->un.echo.sequence = htons(1);
    icmp_header->checksum = 0;
    icmp_header->checksum = calculate_checksum(icmp_header, icmp_length);

    /* Prepare IPv4 header. */
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = htons((unsigned short)packet_length);
    ip_header->id = htons((unsigned short)getpid());
    ip_header->frag_off = htons(0);
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_ICMP;
    ip_header->saddr = source_address.s_addr;
    ip_header->daddr = destination_address.s_addr;
    ip_header->check = 0;
    ip_header->check = calculate_checksum(ip_header, sizeof(struct iphdr));

    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket_fd < 0) {
        perror("Raw IP socket creation failed");
        fprintf(stderr, "Run the program using sudo.\n");
        return EXIT_FAILURE;
    }

    int header_included = 1;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &header_included, sizeof(header_included)) < 0) {
        perror("IP_HDRINCL configuration failed");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    struct sockaddr_in destination_socket;
    memset(&destination_socket, 0, sizeof(destination_socket));
    destination_socket.sin_family = AF_INET;
    destination_socket.sin_addr = destination_address;

    printf("========================================\n");
    printf("IPv4 Packet Preparation\n");
    printf("========================================\n");
    printf("Source IP       : %s\n", source_ip_string);
    printf("Destination IP  : %s\n", destination_ip_string);
    printf("Version         : %u\n", ip_header->version);
    printf("Header length   : %u bytes\n", ip_header->ihl * 4U);
    printf("Total length    : %u bytes\n", ntohs(ip_header->tot_len));
    printf("TTL             : %u\n", ip_header->ttl);
    printf("Protocol        : ICMP (%u)\n", ip_header->protocol);
    printf("Payload         : %s\n", PAYLOAD_TEXT);
    printf("IPv4 checksum   : 0x%04X\n", ntohs(ip_header->check));
    printf("ICMP checksum   : 0x%04X\n", ntohs(icmp_header->checksum));

    ssize_t sent_length = sendto(socket_fd, packet, packet_length, 0, (struct sockaddr *)&destination_socket, sizeof(destination_socket));

    if (sent_length < 0) {
        perror("Packet transmission failed");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    printf("Packet sent successfully: %zd bytes\n", sent_length);
    close(socket_fd);
    return EXIT_SUCCESS;
}