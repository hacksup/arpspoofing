#include <stdio.h>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <pcap.h>

#include "getInfo.h"


struct in_addr getGatewayIP(void)
{
	struct in_addr gatewayIP;

	FILE * fp;
		
	char cmd[500];
	char gatewayIPbuf[20];

	sprintf(cmd, "netstat -r | grep 'default' | awk '{print $2}'"); //grep gateway ip

	fp = popen(cmd, "r"); //pipe open

	fgets(gatewayIPbuf, sizeof(gatewayIPbuf), fp);
	pclose(fp);

	inet_aton(gatewayIPbuf, &gatewayIP);

	return gatewayIP;
	
}

struct myInfo getMyInfo(void)
{
	struct myInfo myInfoTest;

	FILE * fp;

	char * dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	char cmd[500];
	char myIpbuf[20];
	char myMacbuf[20];

	dev = pcap_lookupdev(errbuf);


	sprintf(cmd, "ifconfig | grep '%s' | awk '{print $5}'", dev); //grep mac
	fp = popen(cmd, "r"); //pipe open

	fgets(myMacbuf, sizeof(myMacbuf), fp);
	pclose(fp);

	ether_aton_r(myMacbuf, &(myInfoTest.MAC));

	sprintf(cmd, "ifconfig | grep -A 1 '%s' | grep 'inet addr' | awk '{print $2}' | awk -F ':' '{print $2}'", dev); //grep ip
	fp = popen(cmd, "r"); //pipe open

	fgets(myIpbuf, sizeof(myIpbuf), fp);
	pclose(fp);

	inet_aton(myIpbuf, &(myInfoTest.IP));
	


	return myInfoTest;
}

