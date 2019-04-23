#include "pkt.h"

Pkt::Pkt(){

}

Pkt::Pkt(const u_char *_pkt){
    this->pkt = const_cast<u_char *>(_pkt);
    this->ethhdr = reinterpret_cast<struct libnet_ethernet_hdr*>(pkt);
}

Pkt::~Pkt(){

}

bool Pkt::isIp(){
    if(ntohs(ethhdr->ether_type) == ETHERTYPE_IP) {
        this->iphdr = reinterpret_cast<struct libnet_ipv4_hdr*>(pkt + LIBNET_ETH_H);
        return true;
    }
    return false;
}

bool Pkt::isArp(){
    if(ntohs(ethhdr->ether_type) == ETHERTYPE_ARP) {
        this->arphdr = reinterpret_cast<struct arp_hdr *>(pkt + LIBNET_ETH_H);
        return true;
    }
    return false;
}

bool Pkt::isTcp(){
    if(isIp()){
        if(iphdr->ip_p == IPPROTO_TCP){
            this->tcphdr = reinterpret_cast<struct libnet_tcp_hdr *>(reinterpret_cast<uint64_t>(iphdr) + 4*(iphdr->ip_hl));
            return true;
        }
    }
    return false;
}

bool Pkt::isHttp(){
    if(isTcp()){
        if(ntohs(tcphdr->th_dport) == TCP_PORT_HTTP || ntohs(tcphdr->th_sport) == TCP_PORT_HTTP){
            return true;
        }
    }
    return false;
}

void Pkt::printMac(uint8_t* mac) {
    int i;
    for (i=0;i<6;i++){
        printf("%02x", mac[i]);
        if (i != 5) printf(":");
        if (i == 5) printf("\n");
    }
}

void Pkt::printIp(struct in_addr *ip){
    char buf[16]={0,};
    inet_ntop(AF_INET, ip, buf, sizeof(buf));
    printf("%s\n", buf);
}

void Pkt::printTcp(uint16_t tcp){
    printf("%d\n", ntohs(tcp));
}

void Pkt::printTcpData(){
    int len = ntohs(iphdr->ip_len)-(iphdr->ip_hl*4)-(tcphdr->th_off*4);
    u_char* data = reinterpret_cast<u_char*>(reinterpret_cast<uint64_t>(tcphdr)+(tcphdr->th_off)*4);
    printf("http data: ");
    if(len < 16) printf("%.*s\n", len, data);
    else printf("%.*s\n", 16, data);
}

void Pkt::getMyMac(char* dev){
    int fd;
    struct ifreq ifr;
    uint8_t* mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);
    if(ioctl(fd, SIOCGIFHWADDR, &ifr)< 0) close(fd);
    mac = reinterpret_cast<uint8_t *>(ifr.ifr_hwaddr.sa_data);
    setMac(my_mac, mac);
    close(fd);
}

void Pkt::getMyIp(char* dev){
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *ip;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFADDR, &ifr)< 0) close(fd);

    ip = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    my_ip = reinterpret_cast<uint32_t>(ip->sin_addr.s_addr);

    close(fd);
}


void Pkt::setMac(uint8_t* dst, uint8_t* src){
    for(int i = 0; i < ETHER_ADDR_LEN; i++)
        dst[i] = src[i];
}

void Pkt::setMac(uint8_t* dst, uint8_t  src){
    for(int i = 0; i < ETHER_ADDR_LEN; i++)
        dst[i] = src;
}

void Pkt::setArp(uint16_t op){
    ethhdr->ether_type = htons(ETHERTYPE_ARP);
    this->arphdr = reinterpret_cast<struct arp_hdr *>(pkt+LIBNET_ETH_H);
    arphdr->lah.ar_hrd = htons(ARPHRD_ETHER);
    arphdr->lah.ar_pro = htons(ETHERTYPE_IP);
    arphdr->lah.ar_hln = ETHER_ADDR_LEN;
    arphdr->lah.ar_pln = IP_ADDR_LEN;
    arphdr->lah.ar_op  = htons(op);
}
