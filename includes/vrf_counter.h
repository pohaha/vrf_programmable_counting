#ifndef VRF_COUNTER
#define VRF_COUNTER

#include <vector>
#include <linux/netlink.h>
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <asm/types.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <libnetlink.h>
extern "C" {
	#include <rt_names.h>
	#include <utils.h>
}
#include <linux/rtnetlink.h>

//vector of such structures is extracted from the vrf table
struct Routing_Table
{
	std::string rta_dst;
	int rtm_dst_len;
	std::string psrc;
};

std::vector<Routing_Table> tables;
int preferred_family = AF_INET;
rtnl_handle socket_handle = {.fd = -1};


struct Request
{
    struct nlmsghdr n;
    struct ifinfomsg i;
    char buf[1024];
    Request()
    {
        n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
        n.nlmsg_flags = NLM_F_REQUEST;
        n.nlmsg_type = RTM_GETLINK;
        i.ifi_family = AF_UNSPEC;
    }
};

static struct
{
	unsigned int tb;
	int cloned;
	int flushed;
	char *flushb;
	int flushp;
	int flushe;
	int protocol, protocolmask;
	int scope, scopemask;
	__u64 typemask;
	int tos, tosmask;
	int iif, iifmask;
	int oif, oifmask;
	int mark, markmask;
	int realm, realmmask;
	__u32 metric, metricmask;
	inet_prefix rprefsrc;
	inet_prefix rvia;
	inet_prefix rdst;
	inet_prefix mdst;
	inet_prefix rsrc;
	inet_prefix msrc;
} filter;


//this is a function you are looking for
std::vector<Routing_Table> get_vrf_by_name(const char* vrf_name);

#endif //VRF_COUNTER