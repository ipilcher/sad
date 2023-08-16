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

#define SAD_DEF_INTERVAL	30
#define SAD_MIN_INTERVAL	5
#define SAD_MAX_INTERVAL	3600  /* 1 hour */

#define SAD_MCAST_SPORT		42
#define SAD_MCAST_DADDR		0xefff2a2a  /* 239.255.42.42 */
#define SAD_MCAST_DPORT		4242

#define SAD_ROUTE_DADDR		0x08080808  /* 8.8.8.8 */
#define SAD_BUF_SIZE		MNL_SOCKET_BUFFER_SIZE

/* Avoid awkward line breaks in function declarations with unused arguments */
#define SAD_UNUSED(decl)	decl __attribute__((unused))

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

/* Information about a route */
struct sad_route {
	struct in_addr		src_addr;
	uint32_t		src_ifindex;
	struct in_addr		dst_addr;
	struct in_addr		gateway;
	uint8_t			dst_len;
};

/* Command line options */
static unsigned int sad_interval = SAD_DEF_INTERVAL;
static struct in_addr sad_mcast_daddr = { SAD_HTONL(SAD_MCAST_DADDR) };
static uint16_t sad_mcast_dport = SAD_HTONS(SAD_MCAST_DPORT);
static uint16_t sad_mcast_sport = SAD_HTONS(SAD_MCAST_SPORT);
static struct in_addr sad_route_daddr = { SAD_HTONL(SAD_ROUTE_DADDR) };
static _Bool sad_debug;
static _Bool sad_syslog;
static _Bool sad_stderr;
static _Bool sad_mcast_loopback;

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

static void sad_free_netifs(struct sad_netif *const netifs)
{
	struct sad_netif *netif, *next;

	netif = netifs;

	while (netif != NULL) {
		next = netif->next;
		free(netif);
		netif = next;
	}
}

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

static void sad_parse_addr(const struct sad_opt *const opt,
			   const char *const arg)
{
	if (inet_aton(arg, opt->out) != 1) {
		SAD_FATAL("Invalid %s address: %s",
			  (const char *)opt->data, arg);
	}
}

static void sad_help(const struct sad_opt *, const char *);

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
		.sname		= 'r',
		.lname		= "route-dest",
		.parse_fn	= sad_parse_addr,
		.data		= "route destination",
		.out		= &sad_route_daddr,
		.arg		= 1,
		.argname	= "ADDRESS",
		.help		= "destination used to check default route "
					"(default 8.8.8.8)"
	},
	{
		.sname		= 'a',
		.lname		= "dest-address",
		.parse_fn	= sad_parse_addr,
		.data		= "announcement multicast",
		.out		= &sad_mcast_daddr,
		.arg		= 1,
		.argname	= "ADDRESS",
		.help		= "announcement destination address "
					"(default 239.255.42.42)"
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
		.sname		= 'L',
		.lname		= "loopback",
		.parse_fn	= sad_parse_flag,
		.out		= &sad_mcast_loopback,
		.help		= "enable multicast loopback (for testing)"
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
		SAD_PFATAL("Failed to bind UDP socket");

	optval = sad_mcast_loopback;

	result = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP,
			    &optval, sizeof optval);
	if (result < 0) {
		SAD_PFATAL("Failed to %s multicast loopback",
			   sad_mcast_loopback ? "enable" : "disable");
	}

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
	}

	return MNL_CB_OK;
}

static int sad_msg_cb(const struct nlmsghdr *const nlh, void *const data)
{
	struct rtmsg *rtm;
	struct sad_route route;
	char addr1[INET_ADDRSTRLEN];
	char addr2[INET_ADDRSTRLEN];
	char addr3[INET_ADDRSTRLEN];
	char ifname[IF_NAMESIZE];

	if (nlh->nlmsg_type != RTM_NEWROUTE) {
		SAD_WARNING("Unexpected netlink message type (%hu)",
			    nlh->nlmsg_type);
		return MNL_CB_OK;
	}

	rtm = mnl_nlmsg_get_payload(nlh);

	if (rtm->rtm_family != AF_INET) {
		SAD_WARNING("Route address family not IPv4: %hhu",
			    rtm->rtm_family);
		return MNL_CB_OK;
	}

	if (rtm->rtm_type != RTN_UNICAST) {
		SAD_WARNING("Route type not unicast: %hhu",
			  rtm->rtm_type);
		return MNL_CB_OK;
	}

	if (rtm->rtm_dst_len != 32) {
		SAD_WARNING("Route destination length not 32: %hhu",
			    rtm->rtm_dst_len);
		return MNL_CB_OK;
	}

	bzero(&route, sizeof route);
	route.dst_len = rtm->rtm_dst_len;

	mnl_attr_parse(nlh, sizeof *rtm, sad_attr_cb, &route);

	if (route.dst_addr.s_addr != sad_route_daddr.s_addr) {
		SAD_WARNING("Route destination incorrect: %s",
			    sad_ntop(&route.dst_addr, addr1));
		return MNL_CB_OK;

	}

	if (route.src_addr.s_addr == INADDR_ANY) {
		SAD_WARNING("Route missing source address");
		return MNL_CB_OK;
	}

	SAD_INFO("Found route to %s via %s from %s on %s",
		 sad_ntop(&route.dst_addr, addr1),
		 sad_ntop(&route.gateway, addr2),
		 sad_ntop(&route.src_addr, addr3),
		 sad_indextoname(route.src_ifindex, ifname));

	*(struct in_addr *)data = route.src_addr;
	return MNL_CB_OK;
}

static struct in_addr sad_def_saddr(struct mnl_socket *const mnlsock,
				    unsigned int *const sequence,
				    uint8_t buf[const static SAD_BUF_SIZE])
{
	static _Bool already_warned;

	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	uint32_t seq;
	ssize_t got;
	int result;
	struct in_addr defsrc;
	char addrstr[INET_ADDRSTRLEN];

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = seq = (*sequence)++;

	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof *rtm);
	rtm->rtm_family = AF_INET;
	rtm->rtm_dst_len = 32;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_flags = RTM_F_LOOKUP_TABLE;

	mnl_attr_put_u32(nlh, RTA_DST, sad_route_daddr.s_addr);

	if (mnl_socket_sendto(mnlsock, nlh, nlh->nlmsg_len) < 0)
		SAD_PFATAL("Failed to send netlink message");

	if ((got = mnl_socket_recvfrom(mnlsock, buf, SAD_BUF_SIZE)) < 0)
		SAD_PFATAL("Failed to receive netlink message");

	defsrc.s_addr = INADDR_ANY;  /* Not INADDR_NONE!  (See main().) */

	result = mnl_cb_run(buf, got, seq, mnl_socket_get_portid(mnlsock),
			    sad_msg_cb, &defsrc);
	if (result < 0 && errno != ENETUNREACH)
		SAD_PFATAL("Netlink request failed");

	if (defsrc.s_addr == INADDR_ANY) {
		if (!already_warned) {
			SAD_WARNING("No route to destination: %s",
				    sad_ntop(&sad_route_daddr, addrstr));
			already_warned = 1;
		}
	}
	else {
		already_warned = 0;
	}

	return defsrc;
}


/*
 *	Startup & main loop
 */

static void sad_tsdiff(struct timespec *const difference,
		       const struct timespec *const end,
		       const struct timespec *const restrict start)
{
	/*
	 * We're using CLOCK_BOOTTIME, so the tv_sec values should always be
	 * reasonable, and their difference should never be greater than
	 * SAD_MAX_INTERVAL (3600).
	 *
	 * clock_gettime() should never return a tv_nsec value greater than
	 * 999,999,999.
	 */

	difference->tv_sec = end->tv_sec - start->tv_sec;
	difference->tv_nsec = end->tv_nsec - start->tv_nsec;

	if (difference->tv_nsec < 0) {
		--(difference->tv_sec);
		difference->tv_nsec += 1000000000;
	}
	else if (difference->tv_nsec >= 1000000000) {
		++(difference->tv_sec);
		difference->tv_nsec -= 1000000000;
	}
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
	*timeout = new_timeout;

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
	buf = SAD_ZALLOC(SAD_BUF_SIZE);
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

		if (sad_exit_flag)
			break;

		/*
		 * sad_ppoll() updated timeout, so next pass will wait remainder
		 * of interval if default route hasn't changed
		 */

		SAD_INFO("Routing table has changed");

		/* Empty socket buffer, so ppoll() doesn't return immediately */
		while (recv(pfd.fd, buf, sizeof buf, 0) >= 0);
		if (errno != EAGAIN)
			SAD_PFATAL("Failed to receive netlink message");
	}

	SAD_INFO("Shutting down");

	if (mnl_socket_close(mnlsock) < 0 || close(pfd.fd) < 0)
		SAD_PFATAL("Failed to close netlink socket");

	if (close(udpsock) < 0)
		SAD_PFATAL("Failed to close UDP socket");

	sad_free_netifs(netifs);
	free(buf);

	return EXIT_SUCCESS;
}
