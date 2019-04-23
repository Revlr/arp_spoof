#include "pkt.h"
#include <map>
#include <set>
#include <thread>

using namespace std;

class Arp: public Pkt{
private:
    uint8_t brd_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
public:
    set <uint32_t> ipSet;               //To prevent getting Mac many times
    map <uint32_t, uint8_t*> ipMac;     //To store mac via ip
    pair<uint32_t, uint8_t*> p;
    set <pair<uint32_t, uint32_t>> session; // To prevent duplicate sessions

    Arp(char* _dev);

    uint8_t* getMac(uint32_t ip);
    uint8_t* findMac(uint32_t ip);

    bool isSame(uint8_t* mac1, uint8_t* mac2);

    void sendArp(uint32_t sip, uint32_t tip);
    void arpSpoof(uint32_t sip, uint32_t tip);

    thread spoofingThread(uint32_t sip, uint32_t tip);
};
