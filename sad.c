// SPDX-License-Identifier: GPL-3.0-or-later

/*
 *	SAD - Source Address Daemon
 *
 *	Copyright 2023 Ian Pilcher <arequipeno@gmail.com>
 */

#define _GNU_SOURCE	/* for asprintf() */

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

#define SAD_DEF_BUF_SIZE	8192
#define SAD_MIN_BUF_SIZE	SAD_DEF_BUF_SIZE
#define SAD_MAX_BUF_SIZE	(1024 * 1024)  /* 1 MiB */

#define SAD_DEF_INTERVAL	30
#define SAD_MIN_INTERVAL	5
#define SAD_MAX_INTERVAL	3600  /* 1 hour */

#define SAD_MCAST_SPORT		42
#define SAD_MCAST_DADDR		0xefff2a2a  /* 239.255.42.42 */
#define SAD_MCAST_DPORT		4242

/* Avoid awkward line breaks in function declarations with unused arguments */
#define SAD_UNUSED(decl)	decl __attribute__((unused))

/* Free a simple linked list (pointer to next node must be named 'next') */
#define SAD_FREE_LIST(list)						\
		do {							\
			typeof (list) next;				\
									\
			while (list != NULL) {				\
				next = list->next;			\
				free(list);				\
				list = next;				\
			}						\
		}							\
		while (0)

/* Macro versions of byte swapping functions for static initializers */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define SAD_HTONS(x)	(x)
#define SAD_HTONL(x)	(x)
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define SAD_HTONS(x)	__builtin_bswap16(x)
#define SAD_HTONL(x)	__builtin_bswap32(x)
#else
#error "__BYTE_ORDER__ is not __ORDER_BIG_ENDIAN__ or __ORDER_LITTLE_ENDIAN__"
#endif

/* Information about a command line option */
struct sad_opt {
	const char	*help;
	const char	*lname;
	void		(*parse_fn)(const struct sad_opt *, const char *);
	const void	*data;
	void		*out;
	const char	*argname;
	char		sname;
	_Bool		arg;
};

/* Information about an unsigned integer command line option */
struct sad_uint_opt {
	const char	*name;
	void		(*set_fn)(const unsigned long, const struct sad_opt *);
	unsigned long	min;
	unsigned long	max;
};

/* Used for a list of network interfaces from which advertisements are sent */
struct sad_netif {
	struct sad_netif	*next;
	struct ifreq		ifr;
};

/* Used for a list of default and local routes */
struct sad_route {
	struct sad_route	*next;
	uint32_t		priority;
	struct in_addr		src_addr;
	uint32_t		src_ifindex;
	struct in_addr		dst_addr;
	struct in_addr		gateway;
	uint8_t			dst_len;
	uint8_t			scope;
};

/* Command line options */
static size_t sad_buf_size = SAD_DEF_BUF_SIZE;
static unsigned int sad_interval = SAD_DEF_INTERVAL;
static struct in_addr sad_mcast_daddr = { SAD_HTONL(SAD_MCAST_DADDR) };
static uint16_t sad_mcast_dport = SAD_HTONS(SAD_MCAST_DPORT);
static uint16_t sad_mcast_sport = SAD_HTONS(SAD_MCAST_SPORT);
static _Bool sad_debug;
static _Bool sad_syslog;
static _Bool sad_stderr;

/* Set in sad_parse_opts(), based on environment and command line options */
static _Bool sad_use_syslog;
static struct sockaddr_in sad_mcast_sockaddr;

/* Set when SIGINT/SIGTERM is received to trigger clean exit */
static volatile sig_atomic_t sad_exit_flag;

/*
 *	Logging
 */

__attribute__((format(printf, 2, 3)))
static void sad_log(const int level, const char *const format, ...)
{
	va_list ap;
	size_t fmt_len;

	va_start(ap, format);

	if (sad_use_syslog) {
		vsyslog(level, format, ap);
	}
	else {
		vfprintf(stderr, format, ap);
		fmt_len = strlen(format);
		if (fmt_len > 0 && format[fmt_len - 1] != '\n')
			fputc('\n', stderr);
	}

	va_end(ap);
}

/* Preprocessor dance to "stringify" an expanded macro value (e.g. __LINE__) */
#define SAD_STR_RAW(x)	#x
#define	SAD_STR(x)		SAD_STR_RAW(x)

/* Expands to a message preamble which specifies file & line */
#define SAD_LOCATION		__FILE__ ":" SAD_STR(__LINE__) ": "

/* Expands to syslog priority & full message preamble */
#define SAD_LOG_HDR(lvl)	LOG_ ## lvl, #lvl ": " SAD_LOCATION

/* Log debug messages (when enabled) at INFO priority to avoid filtering */
#define SAD_DEBUG(fmt, ...)						\
		do {							\
			if (!sad_debug)					\
				break;					\
			sad_log(LOG_INFO, "DEBUG: " SAD_LOCATION fmt,	\
				##__VA_ARGS__);				\
		}							\
		while (0)

/* Logging macros for other priorities */
#define SAD_INFO(fmt, ...)	\
		sad_log(SAD_LOG_HDR(INFO) fmt, ##__VA_ARGS__)
#define SAD_NOTICE(fmt, ...)	\
		sad_log(SAD_LOG_HDR(NOTICE) fmt, ##__VA_ARGS__)
#define SAD_WARNING(fmt, ...)	\
		sad_log(SAD_LOG_HDR(WARNING) fmt, ##__VA_ARGS__)
#define SAD_ERR(fmt, ...) \
		sad_log(SAD_LOG_HDR(ERR) fmt, ##__VA_ARGS__)
#define SAD_CRIT(fmt, ...) \
		sad_log(SAD_LOG_HDR(CRIT) fmt, ##__VA_ARGS__)
#define SAD_ALERT(fmt, ...) \
		sad_log(SAD_LOG_HDR(ALERT) fmt, ##__VA_ARGS__)
#define SAD_EMERG(fmt, ...) \
		sad_log(SAD_LOG_HDR(EMERG) fmt, ##__VA_ARGS__)

/* Log an unexpected internal error and abort */
#define SAD_ABORT(...) \
		do { SAD_CRIT(__VA_ARGS__); abort(); } while (0)

/* Assertion with logging */
#define SAD_ASSERT(expr)						\
		do {							\
			if (expr)					\
				break;					\
			SAD_ABORT("Assertion failed: " #expr);		\
		}							\
		while (0)

/* Log a fatal error and exit immediately */
#define SAD_FATAL(...) \
		do { SAD_CRIT(__VA_ARGS__); exit(EXIT_FAILURE); } while (0)

/* Log an error with errno information */
#define SAD_PERROR(fmt, ...)	SAD_ERR(fmt ": %m", ##__VA_ARGS__)

/* Log a fatal error with errno information */
#define SAD_PFATAL(fmt, ...)	SAD_FATAL(fmt ": %m", ##__VA_ARGS__)

static const char *sad_ntop(const struct in_addr *const addr,
			    char dst[const static INET_ADDRSTRLEN])
{
	SAD_ASSERT(inet_ntop(AF_INET, addr, dst, INET_ADDRSTRLEN) == dst);
	return dst;
}

static const char *sad_indextoname(const unsigned int index,
				   char dst[const static IF_NAMESIZE])
{
	static const char none[] = "[none]";

	if (if_indextoname(index, dst) == NULL) {
		SAD_WARNING("No interface name for index %u", index);
		return none;
	}

	return dst;
}

static _Bool sad_is_default(const struct sad_route *const route)
{
	return route->scope == RT_SCOPE_UNIVERSE
		&& route->dst_addr.s_addr == INADDR_ANY
		&& route->dst_len == 0
		&& route->gateway.s_addr != INADDR_ANY;
}

static _Bool sad_is_local(const struct sad_route *const route)
{
	return route->scope == RT_SCOPE_LINK
		&& route->dst_addr.s_addr != INADDR_ANY
		&& route->dst_len > 0
		&& route->dst_len < 32
		&& route->src_addr.s_addr != INADDR_ANY;
}

static char *sad_fmt_route(const struct sad_route *const route)
{
	char addr1[INET_ADDRSTRLEN];
	char addr2[INET_ADDRSTRLEN];
	char ifname[IF_NAMESIZE];
	char *output;
	int result;

	if (sad_is_default(route)) {
		sad_ntop(&route->gateway, addr1);
		sad_indextoname(route->src_ifindex, ifname);
		result = asprintf(&output, "default via %s on %s metric %u",
				  addr1, ifname, route->priority);
	}
	else {
		SAD_ASSERT(sad_is_local(route));
		sad_ntop(&route->dst_addr, addr1);
		sad_ntop(&route->src_addr, addr2);
		sad_indextoname(route->src_ifindex, ifname);
		result = asprintf(&output, "%s/%hhu from %s on %s metric %u",
				  addr1, route->dst_len, addr2, ifname,
				  route->priority);
	}

	if (result < 0)
		SAD_FATAL("Memory allocation failure");

	return output;
}

/*
 *	Memory allocation
 */

static void *sad_zalloc(const size_t size, const char *const file,
			  const unsigned int line)
{
	void *result;

	if ((result = calloc(1, size)) == NULL) {
		sad_log(LOG_CRIT, "CRIT: %s:%u: Memory allocation failure",
			file, line);
		exit(EXIT_FAILURE);
	}

	return result;
}

#define SAD_ZALLOC(size)	sad_zalloc(size, __FILE__, __LINE__)

/*
 *	Command line parsing
 */

static void sad_parse_flag(const struct sad_opt *const opt,
			   SAD_UNUSED(const char *const arg))
{
	*(_Bool *)(opt->out) = 1;
}

static void sad_parse_uint(const struct sad_opt *const opt,
			   const char *const arg)
{
	const struct sad_uint_opt *uopt;
	unsigned long value;
	char *endptr;

	uopt = opt->data;

	errno = 0;
	value = strtoul(arg, &endptr, 10);
	if (errno != 0 || value < uopt->min || value > uopt->max) {
		SAD_FATAL("Invalid %s value: %s (not in range %lu - %lu)",
			  uopt->name, arg, uopt->min, uopt->max);
	}

	uopt->set_fn(value, opt);
}

static void sad_set_port(const unsigned long value,
			 const struct sad_opt *const opt)
{
	*(uint16_t *)(opt->out) = htons(value);
}

static void sad_set_uint(const unsigned long value,
			 const struct sad_opt *const opt)
{
	*(unsigned int *)(opt->out) = value;
}

static void sad_set_sizet(const unsigned long value,
			  const struct sad_opt *const opt)
{
	*(size_t *)(opt->out) = value;
}

static void sad_parse_daddr(SAD_UNUSED(const struct sad_opt *const opt),
			    const char *const arg)
{
	/* IPv4 multicast local scope address & mask - 239.255.0.0/16 */
	static const uint32_t local_scope_addr = SAD_HTONL(0xefff0000);
	static const uint32_t local_scope_mask = SAD_HTONL(0xffff0000);

	if (inet_aton(arg, &sad_mcast_daddr) != 1)
		SAD_FATAL("Invalid destination address: %s", arg);

	if ((sad_mcast_daddr.s_addr & local_scope_mask) != local_scope_addr) {
		SAD_FATAL("Invalid destination address: %s "
				"(not in 239.255.0.0/16)",
			  arg);
	}
}

static void sad_help(const struct sad_opt *, const char *);

static const struct sad_uint_opt sad_bufsz_uopt = {
	.name		= "buffer size",
	.set_fn		= sad_set_sizet,
	.min		= SAD_MIN_BUF_SIZE,
	.max		= SAD_MAX_BUF_SIZE
};

static const struct sad_uint_opt sad_interval_uopt = {
	.name		= "announcement interval",
	.set_fn		= sad_set_uint,
	.min		= SAD_MIN_INTERVAL,
	.max		= SAD_MAX_INTERVAL
};

static const struct sad_uint_opt sad_dport_uopt = {
	.name		= "destination port",
	.set_fn		= sad_set_port,
	.min		= 1,
	.max		= UINT16_MAX
};

static const struct sad_uint_opt sad_sport_uopt = {
	.name		= "source port",
	.set_fn		= sad_set_port,
	.min		= 1,
	.max		= UINT16_MAX
};

static const struct sad_opt sad_opts[] = {
	{
		.sname		= 'a',
		.lname		= "dest-address",
		.parse_fn	= sad_parse_daddr,
		.arg		= 1,
		.argname	= "ADDRESS",
		.help		= "announcement destination address "
					"(default 239.255.42.42)"
	},
	{
		.sname		= 'b',
		.lname		= "buffer-size",
		.parse_fn	= sad_parse_uint,
		.data		= &sad_bufsz_uopt,
		.out		= &sad_buf_size,
		.arg		= 1,
		.argname	= "BYTES",
		.help		= "netlink buffer size (default "
					SAD_STR(SAD_DEF_BUF_SIZE) ")"
	},
	{
		.sname		= 'i',
		.lname		= "interval",
		.parse_fn	= sad_parse_uint,
		.data		= &sad_interval_uopt,
		.out		= &sad_interval,
		.arg		= 1,
		.argname	= "SECONDS",
		.help		= "interval between announcements (default "
					SAD_STR(SAD_DEF_INTERVAL) ")"
	},
	{
		.sname		= 'p',
		.lname		= "dest-port",
		.parse_fn	= sad_parse_uint,
		.data		= &sad_dport_uopt,
		.out		= &sad_mcast_dport,
		.arg		= 1,
		.argname	= "PORT",
		.help		= "announcement destination port (default "
					SAD_STR(SAD_MCAST_DPORT) ")"
	},
	{
		.sname		= 'P',
		.lname		= "source-port",
		.parse_fn	= sad_parse_uint,
		.data		= &sad_sport_uopt,
		.out		= &sad_mcast_sport,
		.arg		= 1,
		.argname	= "PORT",
		.help		= "announcement source port (default "
					SAD_STR(SAD_MCAST_SPORT) ")"
	},
	{
		.sname		= 'd',
		.lname		= "debug",
		.parse_fn	= sad_parse_flag,
		.out		= &sad_debug,
		.help		= "enable debugging messages"
	},
	{
		.sname		= 'l',
		.lname		= "syslog",
		.parse_fn	= sad_parse_flag,
		.out		= &sad_syslog,
		.help		= "log to system log (conflicts with -e)"
	},
	{
		.sname		= 'e',
		.lname		= "stderr",
		.parse_fn	= sad_parse_flag,
		.out		= &sad_stderr,
		.help		= "log to terminal (conflicts with -l)"
	},
	{
		.sname		= 'h',
		.lname		= "help",
		.parse_fn	= sad_help,
		.help		= "show this message"
	},
	{ 0 }
};

static void sad_help(SAD_UNUSED(const struct sad_opt *const opt),
		     SAD_UNUSED(const char *const arg))
{
	const struct sad_opt *o;
	int len;

	puts("Usage: sad OPTION... INTERFACES...\nOptions:");

	for (o = sad_opts; o->sname != 0; ++o) {

		len = printf("  -%c, --%s", o->sname, o->lname);

		if (o->arg)
			len += printf(" %s", o->argname);

		SAD_ASSERT(len <= 32);

		printf("%*s%s\n", 32 - len, "", o->help);
	}

	exit(EXIT_SUCCESS);
}

static _Bool sad_do_opt(char **const argp, const struct sad_opt *const opt,
			const _Bool present)
{
	const char *optstr, *optarg;
	size_t len;

	optstr = *argp;
	len = strlen(optstr);

	if (len < 2 || optstr[0] != '-') {
		return 0;
	}
	else if (len == 2) {
		if (optstr[1] != opt->sname)
			return 0;
	}
	else if (optstr[1] != '-' || strcmp(optstr + 2, opt->lname) != 0) {
		return 0;
	}

	if (present) {
		SAD_FATAL("Duplicate command line options: %c/%s",
			  opt->sname, opt->lname);
	}

	if ((optarg = *(argp + 1)) == NULL && opt->arg) {
		SAD_FATAL("Missing argument for command line option: %s",
			  optstr);
	}

	opt->parse_fn(opt, optarg);
	return 1;
}

static char **sad_parse_opts(char **const argv)
{
	_Bool present[sizeof sad_opts / sizeof sad_opts[0] - 1];
	const struct sad_opt *opt;
	char **argp, **pargp;
	_Bool match, *p;

	sad_use_syslog = !isatty(STDERR_FILENO);  /* make best initial guess */
	setlinebuf(stderr);

	bzero(present, sizeof present);

	for (argp = argv + 1; *argp != NULL; ++argp) {

		match = 0;

		for (opt = sad_opts, p = present; opt->sname != 0; ++opt, ++p) {

			if (sad_do_opt(argp, opt, *p)) {
				match = 1;
				*p = 1;
				argp += opt->arg;
				break;
			}
		}

		if (!match) {
			if (**argp == '-') {
				SAD_FATAL("Invalid command line option: %s",
					  *argp);
			}
			break;
		}
	}

	if (sad_syslog && sad_stderr) {
		SAD_FATAL("Conflicting command line options: "
				"-e/--stderr and -l/--syslog");
	}

	if (sad_syslog)
		sad_use_syslog = 1;
	if (sad_stderr)
		sad_use_syslog = 0;

	sad_mcast_sockaddr.sin_family = AF_INET;
	sad_mcast_sockaddr.sin_port = sad_mcast_dport;
	sad_mcast_sockaddr.sin_addr = sad_mcast_daddr;

	for (pargp = argp; *pargp != NULL; ++pargp) {
		if (**pargp != '-')
			continue;
		SAD_FATAL("Command line option after positional argument: %s",
			  *pargp);
	}

	return argp;
}

static struct sad_netif *sad_parse_interfaces(char **const pos_args,
					      const int sockfd)
{
	char **ifname;
	struct sad_netif *netif, *netifs;
	size_t namesz;
	char addrstr[INET_ADDRSTRLEN];

	netifs = NULL;

	for (ifname = pos_args; *ifname != NULL; ++ifname) {

		if ((namesz = strlen(*ifname) + 1) > IFNAMSIZ) {
			SAD_FATAL("Invalid network interface name: %s",
				  *ifname);
		}

		netif = SAD_ZALLOC(sizeof *netif);
		memcpy(&netif->ifr.ifr_name, *ifname, namesz);

		if (ioctl(sockfd, SIOCGIFINDEX, &netif->ifr) < 0)
			SAD_PFATAL("Failed to get interace index: %s", *ifname);

		SAD_DEBUG("Found index %d for %s",
			  netif->ifr.ifr_ifindex, *ifname);

		netif->next = netifs;
		netifs = netif;
	}

	if (netifs == NULL)
		SAD_FATAL("No network interfaces specified");

	SAD_INFO("Sending from port %hu to %s:%hu on these interfaces:",
		 ntohs(sad_mcast_sport), sad_ntop(&sad_mcast_daddr, addrstr),
		 ntohs(sad_mcast_dport));
	for (netif = netifs; netif != NULL; netif = netif->next)
		SAD_INFO("  - %s", netif->ifr.ifr_name);

	return netifs;
}

/*
 *	Socket setup
 */

static struct mnl_socket *sad_mnl_socket(void)
{
	struct mnl_socket *mnlsock;
	unsigned int sockopt;
	int result;

	if ((mnlsock = mnl_socket_open(NETLINK_ROUTE)) == NULL)
		SAD_PFATAL("Failed to create netlink socket");

	if (mnl_socket_bind(mnlsock, 0, MNL_SOCKET_AUTOPID) < 0)
		SAD_PFATAL("Failed to bind netlink socket");

	sockopt = 1;
	result = mnl_socket_setsockopt(mnlsock, NETLINK_GET_STRICT_CHK,
				       &sockopt, sizeof sockopt);
	if (result < 0)
		SAD_PFATAL("Failed to set netlink socket option");

	return mnlsock;
}

static int sad_nl_socket(void)
{
	static const struct sockaddr_nl nladdr = {
		.nl_family	= AF_NETLINK,
		.nl_groups	= RTMGRP_IPV4_ROUTE
	};

	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
	if (fd < 0)
		SAD_PFATAL("Failed to create netlink socket");

	if (bind(fd, (const struct sockaddr *)&nladdr, sizeof nladdr) < 0)
		SAD_PFATAL("Failed to bind netlink socket");

	return fd;
}

static int sad_udp_socket(void)
{
	int sockfd, optval, result;
	struct sockaddr_in sin;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		SAD_PFATAL("Failed to create UDP socket");

	sin.sin_family = AF_INET;
	sin.sin_port = sad_mcast_sport;
	sin.sin_addr.s_addr = INADDR_ANY;

	if (bind(sockfd, (struct sockaddr *)&sin, sizeof sin) < 0)
		SAD_PFATAL("Failed to find UDP socket");

	optval = 0;

	result = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP,
			    &optval, sizeof optval);
	if (result < 0)
		SAD_PFATAL("Failed to disable multicast loopback");

	return sockfd;
}

/*
 *	Netlink message processing
 */

static int sad_attr_cb(const struct nlattr *const attr, void *const data)
{
	struct sad_route *route;
	uint16_t type;

	route = data;
	type = mnl_attr_get_type(attr);

	switch (type) {

		case RTA_GATEWAY:
		case RTA_PREFSRC:
		case RTA_OIF:
		case RTA_DST:
		case RTA_PRIORITY:
			break;

		default:
			return MNL_CB_OK;
	}

	if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
		SAD_PFATAL("Invalid netlink attribute");

	switch (type) {

		case RTA_GATEWAY:
			route->gateway.s_addr = mnl_attr_get_u32(attr);
			break;

		case RTA_PREFSRC:
			route->src_addr.s_addr = mnl_attr_get_u32(attr);
			break;

		case RTA_OIF:
			route->src_ifindex = mnl_attr_get_u32(attr);
			break;

		case RTA_DST:
			route->dst_addr.s_addr = mnl_attr_get_u32(attr);
			break;

		case RTA_PRIORITY:
			route->priority = mnl_attr_get_u32(attr);
			break;
	}

	return MNL_CB_OK;
}

static int sad_msg_cb(const struct nlmsghdr *const nlh, void *const data)
{
	struct rtmsg *rtm;
	struct sad_route *route, **routes;
	char *rtstr;

	if (nlh->nlmsg_type != RTM_NEWROUTE) {
		SAD_WARNING("Unexpected netlink message type (%hu)",
			    nlh->nlmsg_type);
		return MNL_CB_OK;
	}

	rtm = mnl_nlmsg_get_payload(nlh);

	if (rtm->rtm_family != AF_INET) {
		SAD_WARNING("Unexpected route address family (%hhu)",
			    rtm->rtm_family);
		return MNL_CB_OK;
	}

	if (rtm->rtm_table != RT_TABLE_MAIN) {
		SAD_WARNING("Unexpected route table (%hhu)", rtm->rtm_table);
		return MNL_CB_OK;
	}

	if (rtm->rtm_type != RTN_UNICAST) {
		SAD_DEBUG("Ignoring non-unicast route (type %hhu)",
			  rtm->rtm_type);
		return MNL_CB_OK;
	}

	route = SAD_ZALLOC(sizeof *route);

	route->dst_len = rtm->rtm_dst_len;
	route->scope = rtm->rtm_scope;

	mnl_attr_parse(nlh, sizeof *rtm, sad_attr_cb, route);

	if (route->src_ifindex == 0) {
		SAD_WARNING("Route has no output interface");
		return MNL_CB_OK;
	}

	if (sad_is_default(route) || sad_is_local(route)) {
		rtstr = NULL;  /* SAD_DEBUG() may not initialize rtstr */
		SAD_DEBUG("Got route: %s", rtstr = sad_fmt_route(route));
		free(rtstr);
		routes = data;
		route->next = *routes;
		*routes = route;
	}

	return MNL_CB_OK;
}

static _Bool sad_addr_in_subnet(const struct in_addr addr,
				const struct in_addr net_addr,
				const uint8_t prefix_len)
{
	uint32_t netmask;

	/* This only works for prefix lengths between 1 and 32 */
	netmask = htonl(~(uint32_t)0 << (32 - prefix_len));

	return (addr.s_addr & netmask) == (net_addr.s_addr & netmask);
}

static struct sad_route *sad_get_routes(struct mnl_socket *const mnlsock,
					unsigned int *const sequence,
					uint8_t *const buf)
{
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	struct sad_route *routes;
	ssize_t got;
	int result;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = (*sequence)++;

	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof *rtm);
	rtm->rtm_family = AF_INET;

	mnl_attr_put_u32(nlh, RTA_TABLE, RT_TABLE_MAIN);

	if (mnl_socket_sendto(mnlsock, nlh, nlh->nlmsg_len) < 0)
		SAD_PFATAL("Failed to send netlink message");

	routes = NULL;

	do {
		if ((got = mnl_socket_recvfrom(mnlsock, buf, sad_buf_size)) < 0)
			SAD_PFATAL("Failed to receive netlink message");

		result = mnl_cb_run(buf, got, 0, mnl_socket_get_portid(mnlsock),
				    sad_msg_cb, &routes);
		if (result < 0)
			SAD_PFATAL("Netlink request failed");
	}
	while (result > 0);

	return routes;
}

static struct in_addr sad_def_saddr(struct mnl_socket *const mnlsock,
				    unsigned int *const sequence,
				    uint8_t *const buf)
{
	struct sad_route *routes;
	const struct sad_route *route, *defrt, *localrt;
	char *rtstr;

	routes = sad_get_routes(mnlsock, sequence, buf);

	defrt = NULL;
	for (route = routes; route != NULL; route = route->next) {

		if (!sad_is_default(route))
			continue;

		if (defrt == NULL || route->priority < defrt->priority)
			defrt = route;
	}

	if (defrt == NULL) {
		SAD_WARNING("No default route found");
		SAD_FREE_LIST(routes);
		return (struct in_addr){ .s_addr = INADDR_ANY };
	}

	rtstr = NULL;  /* SAD_DEBUG() may not initialize rtstr */
	SAD_DEBUG("Using default route: %s", rtstr = sad_fmt_route(defrt));
	free(rtstr);

	localrt = NULL;
	for (route = routes; route != NULL; route = route->next) {

		if (!sad_is_local(route))
			continue;

		if (route->src_ifindex != defrt->src_ifindex)
			continue;

		if (!sad_addr_in_subnet(defrt->gateway,
					 route->dst_addr, route->dst_len))
			continue;

		/*
		 * If 2 routes are equally specific, use the one that was first
		 * in the kernel list (which will be later in the linked list).
		 */
		if (localrt == NULL || route->dst_len >= localrt->dst_len)
			localrt = route;
	}

	if (localrt == NULL) {
		SAD_WARNING("No local route to default gateway");
		SAD_FREE_LIST(routes);
		return (struct in_addr){ .s_addr = INADDR_ANY };
	}

	rtstr = NULL;  /* SAD_DEBUG() may not re-initialize rtsrt */
	SAD_DEBUG("Using local route: %s", rtstr = sad_fmt_route(localrt));
	free(rtstr);
	SAD_FREE_LIST(routes);

	return localrt->src_addr;
}

/*
 *	Startup & main loop
 */

static void sad_tsdiff(struct timespec *const difference,
		       const struct timespec *const end,
		       const struct timespec *const restrict start)
{
	long diff;

	/*
	 * Calculate difference with millisecond resolution to keep the
	 * numbers reasonable.
	 */

	/* Max value of tv_nsec is 999,999,9999, so this can't overflow */
	diff = end->tv_nsec - start->tv_nsec;

	/* Round -1/2 away from zero */
	diff += (diff >= 0) ? 500000 : -500000;

	/* Convert from nanoseconds to milliseconds */
	diff /= 1000000;

	/*
	 * We're using CLOCK_BOOTTIME, so the tv_sec values should never be
	 * too large.  Additionally, the difference between the two tv_sec
	 * values should never be larger than SAD_MAX_INTERVAL (3600 seconds).
	 */
	diff += (end->tv_sec - start->tv_sec) * 1000;

	/* CLOCK_BOOTTIME should never move backwards */
	SAD_ASSERT(diff >= 0);

	difference->tv_sec = diff / 1000;
	difference->tv_nsec = (diff % 1000) * 1000000;
}

static int sad_poll(struct pollfd *const pfd, struct timespec *const timeout,
		    const sigset_t *const sigmask)
{
	struct timespec before, after, elapsed, new_timeout;
	int result;

	if (clock_gettime(CLOCK_BOOTTIME, &before) < 0)
		SAD_PFATAL("Failed to get current time");

	if ((result = ppoll(pfd, 1, timeout, sigmask)) < 0) {
		if (errno == EINTR)
			return 1;
		SAD_PFATAL("Failed to wait for netlink socket");
	}

	if (result == 0)
		return 0;

	if (clock_gettime(CLOCK_BOOTTIME, &after) < 0)
		SAD_PFATAL("Failed to get current time");

	sad_tsdiff(&elapsed, &after, &before);  /* initializes elapsed */
	sad_tsdiff(&new_timeout, timeout, &elapsed);
	memcpy(timeout, &new_timeout, sizeof timeout);

	return 1;
}

static void sad_announce(const int sockfd, struct in_addr defsrc,
			 const struct sad_netif *const netifs)
{
	uint8_t cmsg[CMSG_SPACE(sizeof(struct in_pktinfo))];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmh;
	const struct sad_netif *netif;
	char addrstr[INET_ADDRSTRLEN];
	void *cmsg_ifi;

	iov.iov_base = &defsrc;
	iov.iov_len = sizeof defsrc;

	msg.msg_name = &sad_mcast_sockaddr;
	msg.msg_namelen = sizeof sad_mcast_sockaddr;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg;
	msg.msg_controllen = sizeof cmsg;

	bzero(cmsg, sizeof cmsg);
	cmh = CMSG_FIRSTHDR(&msg);
	cmh->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	cmh->cmsg_level = SOL_IP;
	cmh->cmsg_type = IP_PKTINFO;

	/*
	 * Instead of repeatedly copying an entire in_pktinfo structure, we'll
	 * just copy the interface index to the correct location in the control
	 * message buffer.
	 */
	cmsg_ifi = CMSG_DATA(cmh) + offsetof(struct in_pktinfo, ipi_ifindex);

	if (sad_debug)
		sad_ntop(&defsrc, addrstr);

	for (netif = netifs; netif != NULL; netif = netif->next) {

		memcpy(cmsg_ifi, &netif->ifr.ifr_ifindex,
		       sizeof netif->ifr.ifr_ifindex);

		if (sendmsg(sockfd, &msg, 0) < 0) {
			SAD_FATAL("Failed to send announcement: %s",
				  netif->ifr.ifr_name);
		}

		SAD_DEBUG("Sent '%s' via %s", addrstr, netif->ifr.ifr_name);
	}
}

static void sad_sighandler(SAD_UNUSED(const int signum))
{
	sad_exit_flag = 1;
}

static void sad_signal_setup(sigset_t *oldmask)
{
	struct sigaction sa;
	sigset_t mask;

	if (sigemptyset(&mask) != 0)
		SAD_PFATAL("sigemptyset");
	if (sigaddset(&mask, SIGTERM) != 0)
		SAD_PFATAL("sigaddset(SIGTERM)");
	if (sigaddset(&mask, SIGINT) != 0)
		SAD_PFATAL("sigaddset(SIGINT)");

	sa.sa_handler = sad_sighandler;
	sa.sa_mask = mask;
	sa.sa_flags = SA_RESETHAND;

	if (sigprocmask(SIG_BLOCK, &mask, oldmask) != 0)
		SAD_PFATAL("sigprocmask");

	if (sigaction(SIGTERM, &sa, NULL) != 0)
		SAD_PFATAL("sigaction(SIGTERM)");
	if (sigaction(SIGINT, &sa, NULL) != 0)
		SAD_PFATAL("sigaction(SIGINT)");
}

int main(SAD_UNUSED(const int argc), char **const argv)
{
	struct mnl_socket *mnlsock;
	unsigned int sequence;
	uint8_t *buf;
	int udpsock;
	struct in_addr defsrc, olddefsrc;
	char **pargv;
	struct sad_netif *netifs;
	struct pollfd pfd;
	_Bool announce;
	struct timespec timeout;
	sigset_t sigmask;
	char addrstr[INET_ADDRSTRLEN];

	pargv = sad_parse_opts(argv);
	udpsock = sad_udp_socket();
	netifs = sad_parse_interfaces(pargv, udpsock);
	buf = SAD_ZALLOC(sad_buf_size);
	sequence = 0;
	mnlsock = sad_mnl_socket();
	pfd.fd = sad_nl_socket();
	pfd.events = POLLIN;
	/* Ensure default source has "changed", so timeout gets initialized */
	defsrc.s_addr = INADDR_NONE;

	sad_signal_setup(&sigmask);

	while (!sad_exit_flag) {

		olddefsrc = defsrc;
		defsrc = sad_def_saddr(mnlsock, &sequence, buf);
		if ((announce = (defsrc.s_addr != olddefsrc.s_addr))) {
			SAD_INFO("Advertising source address: %s",
				 sad_ntop(&defsrc, addrstr));
		}

		while (!sad_exit_flag) {

			if (announce) {
				sad_announce(udpsock, defsrc, netifs);
				/* Announced, so always wait full interval */
				timeout.tv_sec = sad_interval;
				timeout.tv_nsec = 0;
			}

			if (sad_poll(&pfd, &timeout, &sigmask) != 0)
				break;

			/* Timed out, so definitely send announcements */
			announce = 1;
		}

		/*
		 * Routing table has changed, and sad_poll() has updated
		 * timeout (or we caught an exit signal).  Empty the socket
		 * buffer, so next ppoll() call doesn't return immediately.
		 */
		while (recv(pfd.fd, buf, sizeof buf, 0) >= 0);
		if (errno != EAGAIN)
			SAD_PFATAL("Failed to receive netlink message");
	}

	SAD_INFO("Shutting down");

	if (mnl_socket_close(mnlsock) < 0 || close(pfd.fd) < 0)
		SAD_PFATAL("Failed to close netlink socket");

	if (close(udpsock) < 0)
		SAD_PFATAL("Failed to close UDP socket");

	SAD_FREE_LIST(netifs);
	free(buf);

	return EXIT_SUCCESS;
}
