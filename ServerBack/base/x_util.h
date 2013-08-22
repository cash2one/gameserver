#pragma once

#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

inline const char* getIPByIfName(const char* ifName)
{
	int s;
	struct ifreq ifr;
	const char* none_ip = "0.0.0.0";

	if(NULL == ifName)
		return none_ip;
	s = ::socket(AF_INET,SOCK_DGRAM,0);
	if( -1 == s)
		return none_ip;

	bzero(ifr.ifr_name,sizeof(ifr.ifr_name));
	strncpy(ifr.ifr_name,ifName,sizeof(ifr.ifr_name)-1);
	if(-1 == ioctl(s,SIOCGIFADDR,&ifr))
	{
		TEMP_FAILURE_RETRY(::close(s));
		return none_ip;
	}
	TEMP_FAILURE_RETRY(::close(s));
	return inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
}

