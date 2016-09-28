#pragma once

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>


struct myInfo {
	struct in_addr IP;
	struct ether_addr MAC;
};

struct in_addr getGatewayIP(void);
struct myInfo getMyInfo(void);