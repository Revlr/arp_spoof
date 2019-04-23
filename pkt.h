#pragma once
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LIBNET_LIL_ENDIAN   1

#pragma pack(push, 1)
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>

struct arp_hdr{
    struct libnet_arp_hdr lah;
    uint8_t  ar_sha[6];
    uint32_t ar_sip;
    uint8_t  ar_tha[6];
    uint32_t ar_tip;
};
#pragma pack(pop)

#define TCP_PORT_HTTP 80
#define IP_ADDR_LEN   4 //byte

class Pkt {
public:
    u_char* pkt;
    char* dev;

    uint8_t my_mac[6];
    uint32_t my_ip;

    struct libnet_ethernet_hdr *ethhdr;
    struct libnet_ipv4_hdr *iphdr;
    struct libnet_tcp_hdr *tcphdr;
    struct arp_hdr * arphdr;

public:
    Pkt();
    Pkt(const u_char* _pkt);
    ~Pkt();

    bool isIp();
    bool isArp();
    bool isTcp();
    bool isHttp();

    void printMac(uint8_t* mac);
    void printIp(struct in_addr *ip);
    void printTcp(uint16_t tcp);
    void printTcpData();

    void getMyMac(char* dev);
    void getMyIp(char* dev);

    void setMac(uint8_t* dst, uint8_t* src);
    void setMac(uint8_t* dst, uint8_t  src);
    void setArp(uint16_t op);
};
