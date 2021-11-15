#include <vrf_counter.h>


int inet_addr_match(const inet_prefix *a, const inet_prefix *b, int bits)
{
	const __u32 *a1 = a->data;
	const __u32 *a2 = b->data;
	int words = bits >> 0x05;

	bits &= 0x1f;

	if (words)
		if (memcmp(a1, a2, words << 2))
			return -1;

	if (bits) {
		__u32 w1, w2;
		__u32 mask;

		w1 = a1[words];
		w2 = a2[words];

		mask = htonl((0xffffffff) << (0x20 - bits));

		if ((w1 ^ w2) & mask)
			return 1;
	}

	return 0;
}

/* This is a necessary workaround for multicast route dumps */
int get_real_family(int rtm_type, int rtm_family)
{
	if (rtm_type != RTN_MULTICAST)
		return rtm_family;

	if (rtm_family == RTNL_FAMILY_IPMR)
		return AF_INET;

	if (rtm_family == RTNL_FAMILY_IP6MR)
		return AF_INET6;

	return rtm_family;
}

int af_bit_len(int af)
{
	switch (af) {
	case AF_INET6:
		return 128;
	case AF_INET:
		return 32;
	case AF_DECnet:
		return 16;
	case AF_IPX:
		return 80;
	case AF_MPLS:
		return 20;
	}

	return 0;
}

const char *rt_addr_n2a(int af, int len, const void *addr)
{
	static char buf[256];

	return rt_addr_n2a_r(af, len, addr, buf, 256);
}

const char *rt_addr_n2a_r(int af, int len,
			  const void *addr, char *buf, int buflen)
{
	switch (af) {
	case AF_INET:
	case AF_INET6:
		return inet_ntop(af, addr, buf, buflen);
	default:
		return "???";
	}
}

int prepare_NL_sock(rtnl_handle  *rth)
{
	socklen_t addr_len;
	int sndbuf = 32768;
	int one = 1;

	memset(rth, 0, sizeof(*rth));

	rth->proto = NETLINK_ROUTE;
	rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (rth->fd < 0) {
		perror("Cannot open netlink socket");
		return -1;
	}

	if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF,
		       &sndbuf, sizeof(sndbuf)) < 0) {
		perror("SO_SNDBUF");
		return -1;
	}

	if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF,
		       &rcvbuf, sizeof(rcvbuf)) < 0) {
		perror("SO_RCVBUF");
		return -1;
	}

	/* Older kernels may no support extended ACK reporting */
	setsockopt(rth->fd, SOL_NETLINK, NETLINK_EXT_ACK,
		   &one, sizeof(one));

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = 0;

	if (bind(rth->fd, (struct sockaddr *)&rth->local,
		 sizeof(rth->local)) < 0) {
		perror("Cannot bind netlink socket");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr *)&rth->local,
			&addr_len) < 0) {
		perror("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		fprintf(stderr, "Wrong address length %d\n", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		fprintf(stderr, "Wrong address family %d\n",
			rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);

    //set the strict check to check only interesting vrf

	if (setsockopt(rth->fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
		       &one, sizeof(one)) < 0)
		return 0;

	rth->flags |= 0x04; //RTNL_HANDLE_F_STRICT_CHK
	return 0;
}

static int iproute_dump_filter(struct nlmsghdr *nlh, int reqlen)
{
	struct rtmsg *rtm = reinterpret_cast<rtmsg*>(NLMSG_DATA(nlh));
	int err;

	rtm->rtm_protocol = filter.protocol;
	if (filter.cloned)
		rtm->rtm_flags |= RTM_F_CLONED;

	if (filter.tb) 
	{
		err = addattr32(nlh, reqlen, RTA_TABLE, filter.tb);
		if (err)
			return err;
	}

	if (filter.oif) {
		err = addattr32(nlh, reqlen, RTA_OIF, filter.oif);
		if (err)
			return err;
	}

	return 0;
}


void iproute_reset_filter(int ifindex)
{
	memset(&filter, 0, sizeof(filter));
	filter.mdst.bitlen = -1;
	filter.msrc.bitlen = -1;
	filter.oif = ifindex;
	if (filter.oif > 0)
		filter.oifmask = -1;
}

__u32 ipvrf_get_table_id(const char *name)
{
	struct {
		struct nlmsghdr		n;
		struct ifinfomsg	i;
		char			buf[1024];
	} req = {
		.n = {
			.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type  = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.i = {
			.ifi_family  = preferred_family,
		},
	};
	struct nlmsghdr *answer;
	struct rtattr *tb[IFLA_MAX+1];
	struct rtattr *li[IFLA_INFO_MAX+1];
	struct rtattr *vrf_attr[IFLA_VRF_MAX + 1];
	struct ifinfomsg *ifi;
	__u32 tb_id = 0;
	int len;

	addattr_l(&req.n, sizeof(req), IFLA_IFNAME, name, strlen(name) + 1);

	if (rtnl_talk_suppress_rtnl_errmsg(&socket_handle, &req.n, &answer) < 0) {
		/* special case "default" vrf to be the main table */
		if (errno == ENODEV && !strcmp(name, "default"))
			if (rtnl_rttable_a2n(&tb_id, "main"))
				fprintf(stderr,
					"BUG: RTTable \"main\" not found.\n");

		return tb_id;
	}

	ifi = reinterpret_cast<ifinfomsg*>(NLMSG_DATA(answer));
	len = answer->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0) {
		fprintf(stderr, "BUG: Invalid response to link query.\n");
		goto out;
	}

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	if (!tb[IFLA_LINKINFO])
		goto out;

	parse_rtattr_nested(li, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);

	if (!li[IFLA_INFO_KIND] || !li[IFLA_INFO_DATA])
		goto out;

	if (strcmp(reinterpret_cast<const char*>(RTA_DATA(li[IFLA_INFO_KIND])), "vrf"))
		goto out;

	parse_rtattr_nested(vrf_attr, IFLA_VRF_MAX, li[IFLA_INFO_DATA]);
	if (vrf_attr[IFLA_VRF_TABLE])
		tb_id = rta_getattr_u32(vrf_attr[IFLA_VRF_TABLE]);

	if (!tb_id)
		fprintf(stderr, "BUG: VRF %s is missing table id\n", name);

out:
	free(answer);
	return tb_id;
}

static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
	__u32 table = r->rtm_table;

	if (tb[RTA_TABLE])
		table = rta_getattr_u32(tb[RTA_TABLE]);
	return table;
}

static int filter_nlmsg(struct nlmsghdr *n, struct rtattr **tb, int host_len)
{
	struct rtmsg *r = reinterpret_cast<rtmsg*>(NLMSG_DATA(n));
	inet_prefix dst = { .family = r->rtm_family };
	inet_prefix src = { .family = r->rtm_family };
	inet_prefix via = { .family = r->rtm_family };
	inet_prefix prefsrc = { .family = r->rtm_family };
	__u32 table;
	static int ip6_multiple_tables;

	table = rtm_get_table(r, tb);

	if (preferred_family != AF_UNSPEC && r->rtm_family != preferred_family)
		return 0;

	if (r->rtm_family == AF_INET6 && table != RT_TABLE_MAIN)
		ip6_multiple_tables = 1;

	if (filter.cloned == !(r->rtm_flags & RTM_F_CLONED))
		return 0;

	if (r->rtm_family == AF_INET6 && !ip6_multiple_tables) {
		if (filter.tb) {
			if (filter.tb == RT_TABLE_LOCAL) {
				if (r->rtm_type != RTN_LOCAL)
					return 0;
			} else if (filter.tb == RT_TABLE_MAIN) {
				if (r->rtm_type == RTN_LOCAL)
					return 0;
			} else {
				return 0;
			}
		}
	} else {
		if (filter.tb > 0 && filter.tb != table)
			return 0;
	}
	if ((filter.protocol^r->rtm_protocol)&filter.protocolmask)
		return 0;
	if ((filter.scope^r->rtm_scope)&filter.scopemask)
		return 0;

	if (filter.typemask && !(filter.typemask & (1 << r->rtm_type)))
		return 0;
	if ((filter.tos^r->rtm_tos)&filter.tosmask)
		return 0;
	if (filter.rdst.family) {
		if (r->rtm_family != filter.rdst.family ||
		    filter.rdst.bitlen > r->rtm_dst_len)
			return 0;
	} else if (filter.rdst.flags & PREFIXLEN_SPECIFIED) {
		if (filter.rdst.bitlen > r->rtm_dst_len)
			return 0;
	}
	if (filter.mdst.family) {
		if (r->rtm_family != filter.mdst.family ||
		    (filter.mdst.bitlen >= 0 &&
		     filter.mdst.bitlen < r->rtm_dst_len))
			return 0;
	} else if (filter.mdst.flags & PREFIXLEN_SPECIFIED) {
		if (filter.mdst.bitlen >= 0 &&
		    filter.mdst.bitlen < r->rtm_dst_len)
			return 0;
	}
	if (filter.rsrc.family) {
		if (r->rtm_family != filter.rsrc.family ||
		    filter.rsrc.bitlen > r->rtm_src_len)
			return 0;
	} else if (filter.rsrc.flags & PREFIXLEN_SPECIFIED) {
		if (filter.rsrc.bitlen > r->rtm_src_len)
			return 0;
	}
	if (filter.msrc.family) {
		if (r->rtm_family != filter.msrc.family ||
		    (filter.msrc.bitlen >= 0 &&
		     filter.msrc.bitlen < r->rtm_src_len))
			return 0;
	} else if (filter.msrc.flags & PREFIXLEN_SPECIFIED) {
		if (filter.msrc.bitlen >= 0 &&
		    filter.msrc.bitlen < r->rtm_src_len)
			return 0;
	}
	if (filter.rvia.family) {
		int family = r->rtm_family;

		if (tb[RTA_VIA]) {
			struct rtvia *via = reinterpret_cast<rtvia*>(RTA_DATA(tb[RTA_VIA]));

			family = via->rtvia_family;
		}
		if (family != filter.rvia.family)
			return 0;
	}
	if (filter.rprefsrc.family && r->rtm_family != filter.rprefsrc.family)
		return 0;

	if (tb[RTA_DST])
		memcpy(&dst.data, RTA_DATA(tb[RTA_DST]), (r->rtm_dst_len+7)/8);
	if (filter.rsrc.family || filter.msrc.family ||
	    filter.rsrc.flags & PREFIXLEN_SPECIFIED ||
	    filter.msrc.flags & PREFIXLEN_SPECIFIED) {
		if (tb[RTA_SRC])
			memcpy(&src.data, RTA_DATA(tb[RTA_SRC]), (r->rtm_src_len+7)/8);
	}
	if (filter.rvia.bitlen > 0) {
		if (tb[RTA_GATEWAY])
			memcpy(&via.data, RTA_DATA(tb[RTA_GATEWAY]), host_len/8);
		if (tb[RTA_VIA]) {
			size_t len = RTA_PAYLOAD(tb[RTA_VIA]) - 2;
			struct rtvia *ret_via = reinterpret_cast<rtvia*>(RTA_DATA(tb[RTA_VIA]));

			via.family = ret_via->rtvia_family;
			memcpy(&via.data, ret_via->rtvia_addr, len);
		}
	}
	if (filter.rprefsrc.bitlen > 0) {
		if (tb[RTA_PREFSRC])
			memcpy(&prefsrc.data, RTA_DATA(tb[RTA_PREFSRC]), host_len/8);
	}

	if ((filter.rdst.family || filter.rdst.flags & PREFIXLEN_SPECIFIED) &&
	    inet_addr_match(&dst, &filter.rdst, filter.rdst.bitlen))
		return 0;
	if ((filter.mdst.family || filter.mdst.flags & PREFIXLEN_SPECIFIED) &&
	    inet_addr_match(&dst, &filter.mdst, r->rtm_dst_len))
		return 0;

	if ((filter.rsrc.family || filter.rsrc.flags & PREFIXLEN_SPECIFIED) &&
	    inet_addr_match(&src, &filter.rsrc, filter.rsrc.bitlen))
		return 0;
	if ((filter.msrc.family || filter.msrc.flags & PREFIXLEN_SPECIFIED) &&
	    filter.msrc.bitlen >= 0 &&
	    inet_addr_match(&src, &filter.msrc, r->rtm_src_len))
		return 0;

	if (filter.rvia.family && inet_addr_match(&via, &filter.rvia, filter.rvia.bitlen))
		return 0;
	if (filter.rprefsrc.family && inet_addr_match(&prefsrc, &filter.rprefsrc, filter.rprefsrc.bitlen))
		return 0;
	if (filter.realmmask) {
		__u32 realms = 0;

		if (tb[RTA_FLOW])
			realms = rta_getattr_u32(tb[RTA_FLOW]);
		if ((realms^filter.realm)&filter.realmmask)
			return 0;
	}
	if (filter.iifmask) {
		int iif = 0;

		if (tb[RTA_IIF])
			iif = rta_getattr_u32(tb[RTA_IIF]);
		if ((iif^filter.iif)&filter.iifmask)
			return 0;
	}
	if (filter.oifmask) {
		int oif = 0;

		if (tb[RTA_OIF])
			oif = rta_getattr_u32(tb[RTA_OIF]);
		if ((oif^filter.oif)&filter.oifmask)
			return 0;
	}
	if (filter.markmask) {
		int mark = 0;

		if (tb[RTA_MARK])
			mark = rta_getattr_u32(tb[RTA_MARK]);
		if ((mark ^ filter.mark) & filter.markmask)
			return 0;
	}
	if (filter.metricmask) {
		__u32 metric = 0;

		if (tb[RTA_PRIORITY])
			metric = rta_getattr_u32(tb[RTA_PRIORITY]);
		if ((metric ^ filter.metric) & filter.metricmask)
			return 0;
	}
	if (filter.flushb &&
	    r->rtm_family == AF_INET6 &&
	    r->rtm_dst_len == 0 &&
	    r->rtm_type == RTN_UNREACHABLE &&
	    tb[RTA_PRIORITY] &&
	    rta_getattr_u32(tb[RTA_PRIORITY]) == -1)
		return 0;

	return 1;
}


int print_route(struct nlmsghdr *n, void *arg)
{
	Routing_Table new_table;
	struct rtmsg *r = reinterpret_cast<rtmsg*>(NLMSG_DATA(n));
	int len = n->nlmsg_len;
	struct rtattr *tb[RTA_MAX+1];
	int family, color, host_len;
	__u32 table;
	int ret;

	if (n->nlmsg_type != RTM_NEWROUTE && n->nlmsg_type != RTM_DELROUTE) {
		fprintf(stderr, "Not a route: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return -1;
	}
	if (filter.flushb && n->nlmsg_type != RTM_NEWROUTE)
		return 0;
	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	host_len = af_bit_len(r->rtm_family);

	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
	table = rtm_get_table(r, tb);

	if (!filter_nlmsg(n, tb, host_len))
		return 0;

	if (tb[RTA_DST]) 
	{
		family = get_real_family(r->rtm_type, r->rtm_family);

		if (r->rtm_dst_len != host_len) 
		{
			new_table.rta_dst = rt_addr_n2a_rta(family, tb[RTA_DST]);
			new_table.rtm_dst_len = r->rtm_dst_len;
		} 
	}
	if (tb[RTA_PREFSRC] && filter.rprefsrc.bitlen != host_len) 
	{
		new_table.psrc = rt_addr_n2a_rta(r->rtm_family, tb[RTA_PREFSRC]);

	}
	tables.push_back(new_table);
	return 0;
}


std::vector<Routing_Table> get_vrf_by_name(const char* vrf_name)
{
	rtnl_filter_t filter_fn;
	filter_fn = print_route;

	iproute_reset_filter(0);
	filter.tb = RT_TABLE_MAIN;

    prepare_NL_sock(&socket_handle);
	__u32 tid;
	tid = ipvrf_get_table_id(vrf_name);
	if (tid == 0)
		std::cout<<"invalid arg "<<vrf_name;
	iproute_reset_filter(0);
	filter.tb = tid;
	filter.typemask = ~(1 << RTN_LOCAL | 1<<RTN_BROADCAST);
	if (rtnl_routedump_req(&socket_handle, AF_INET, iproute_dump_filter) < 0) {
		perror("Cannot send dump request");
	}
	if (rtnl_dump_filter(&socket_handle, filter_fn, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
	}
	rtnl_close(&socket_handle);
	return tables;
}