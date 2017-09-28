/*
 * pcaputil.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: pcaputil.c,v 1.2 2001/03/15 08:33:04 dugsong Exp $
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <pcap.h>
#include <ctype.h>

#include <sys/socket.h>
#include <unistd.h>
#include <sys/utsname.h>
#include "config.h"

#ifdef BSD
#include <pcap-int.h>
#endif

#include "pcaputil.h"
//#include "net-support.h"


static short sVafinit = 0;

//extern struct aftype unspec_aftype;
//extern struct aftype unix_aftype;
//extern struct aftype inet_aftype;
//extern struct aftype inet6_aftype;
//extern struct aftype ax25_aftype;
//extern struct aftype netrom_aftype;
//extern struct aftype ipx_aftype;
//extern struct aftype ddp_aftype;
//extern struct aftype ec_aftype;
//extern struct aftype x25_aftype;
//extern struct aftype rose_aftype;
//extern struct aftype ash_aftype;


//struct aftype *aftypes[] =
//		{
//#if HAVE_AFUNIX
//				&unix_aftype,
//#endif
//#if HAVE_AFINET
//				&inet_aftype,
//#endif
//#if HAVE_AFINET6
//				&inet6_aftype,
//#endif
//#if HAVE_AFAX25
//				&ax25_aftype,
//#endif
//#if HAVE_AFNETROM
//				&netrom_aftype,
//#endif
//#if HAVE_AFROSE
//				&rose_aftype,
//#endif
//#if HAVE_AFIPX
//				&ipx_aftype,
//#endif
//#if HAVE_AFATALK
//				&ddp_aftype,
//#endif
//#if HAVE_AFECONET
//				&ec_aftype,
//#endif
//#if HAVE_AFASH
//				&ash_aftype,
//#endif
//#if HAVE_AFX25
//				&x25_aftype,
//#endif
//				&unspec_aftype,
//				NULL
//		};
#ifdef BSD
static int
bpf_immediate(int fd, int on)
{
	return (ioctl(fd, BIOCIMMEDIATE, &on));
}
#endif



int
pcap_dloff(pcap_t *pd)
{
	int offset = -1;
	
	switch (pcap_datalink(pd)) {
	case DLT_EN10MB:
		offset = 14;
		break;
	case DLT_IEEE802:
		offset = 22;
		break;
	case DLT_FDDI:
		offset = 21;
		break;
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
	case DLT_NULL:
		offset = 4;
		break;
	default:
		warnx("unsupported datalink type");
		break;
	}
	return (offset);
}

pcap_t *
pcap_init(char *intf, char *filter, int snaplen)
{
	pcap_t *pd;
	u_int net, mask;
	struct bpf_program fcode;
	char ebuf[PCAP_ERRBUF_SIZE];

	if (intf == NULL && (intf = pcap_lookupdev(ebuf)) == NULL) {
		warnx("%s", ebuf);
		return (NULL);
	}
	if ((pd = pcap_open_live(intf, snaplen, 1, 512, ebuf)) == NULL) {
		warnx("%s", ebuf);
		return (NULL);
	}
	if (pcap_lookupnet(intf, &net, &mask, ebuf) == -1) {
		warnx("%s", ebuf);
		return (NULL);
	}  
	if (pcap_compile(pd, &fcode, filter, 1, mask) < 0) {
		pcap_perror(pd, "pcap_compile");
		return (NULL);
	}
	if (pcap_setfilter(pd, &fcode) == -1) {
		pcap_perror(pd, "pcap_compile");
		return (NULL);
	}
#ifdef BSD
	if (bpf_immediate(pd->fd, 1) < 0) {
		perror("ioctl");
		return (NULL);
	}
#endif
	return (pd);
}

/* from tcpdump util.c. */
char *
copy_argv(char **argv)
{
	char **p, *buf, *src, *dst;
	u_int len = 0;
	
	p = argv;
	if (*p == 0)
		return (0);
	
	while (*p)
		len += strlen(*p++) + 1;
	
	if ((buf = (char *)malloc(len)) == NULL)
		err(1, "copy_argv: malloc");
	
	p = argv;
	dst = buf;
	
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';
	
	return (buf);
}

/* like strcmp(), but knows about numbers */
int nstrcmp(const char *astr, const char *b)
{
	const char *a = astr;

	while (*a == *b) {
		if (*a == '\0')
			return 0;
		a++;
		b++;
	}
	if (isdigit(*a)) {
		if (!isdigit(*b))
			return -1;
		while (a > astr) {
			a--;
			if (!isdigit(*a)) {
				a++;
				break;
			}
			if (!isdigit(*b))
				return -1;
			b--;
		}
		return atoi(a) > atoi(b) ? 1 : -1;
	}
	return *a - *b;
}

/* Like strncpy but make sure the resulting string is always 0 terminated. */
char *safe_strncpy(char *dst, const char *src, size_t size)
{
	dst[size-1] = '\0';
	return strncpy(dst,src,size-1);
}

static void oom(void)
{
	fprintf(stderr, "out of virtual memory\n");
	exit(2);
}


void *xrealloc(void *oldp, size_t sz)
{
	void *p = realloc(oldp, sz);
	if (!p)
		oom();
	return p;
}

void *xmalloc(unsigned sz)
{
	void *p = calloc(sz,1);
	if (!p) {};
	return p;
}

int kernel_version(void)
{
	struct utsname uts;
	int major, minor, patch;

	if (uname(&uts) < 0)
		return -1;
	if (sscanf(uts.release, "%d.%d.%d", &major, &minor, &patch) != 3)
		return -1;
	return KRELEASE(major, minor, patch);
}

//void afinit()
//{
//	unspec_aftype.title = "UNSPEC";
//#if HAVE_AFUNIX
//	unix_aftype.title = "UNIX Domain";
//#endif
//#if HAVE_AFINET
//	inet_aftype.title = "DARPA Internet";
//#endif
//#if HAVE_AFINET6
//	inet6_aftype.title = "IPv6";
//#endif
//#if HAVE_AFAX25
//	ax25_aftype.title = "AMPR AX.25";
//#endif
//#if HAVE_AFNETROM
//	netrom_aftype.title = "AMPR NET/ROM";
//#endif
//#if HAVE_AFIPX
//	ipx_aftype.title = "Novell IPX";
//#endif
//#if HAVE_AFATALK
//	ddp_aftype.title = "Appletalk DDP";
//#endif
//#if HAVE_AFECONET
//	ec_aftype.title = "Econet";
//#endif
//#if HAVE_AFX25
//	x25_aftype.title = "CCITT X.25";
//#endif
//#if HAVE_AFROSE
//	rose_aftype.title = "AMPR ROSE";
//#endif
//#if HAVE_AFASH
//	ash_aftype.title = "Ash";
//#endif
//	sVafinit = 1;
//}




///* Check our protocol family table for this family and return its socket */
//int get_socket_for_af(int af)
//{
//	struct aftype **afp;
//
//	if (!sVafinit)
//		afinit();
//
//	afp = aftypes;
//	while (*afp != NULL) {
//		if ((*afp)->af == af)
//			return (*afp)->fd;
//		afp++;
//	}
//	return -1;
//}
//
//
//
//int sockets_open(int family)
//{
//	struct aftype **aft;
//	int sfd = -1;
//	static int force = -1;
//
//	if (force < 0) {
//		force = 0;
//		if (kernel_version() < KRELEASE(2, 1, 0))
//			force = 1;
//		if (access("/proc/net", R_OK))
//			force = 1;
//	}
//	for (aft = aftypes; *aft; aft++) {
//		struct aftype *af = *aft;
//		int type = SOCK_DGRAM;
//		if (af->af == AF_UNSPEC)
//			continue;
//		if (family && family != af->af)
//			continue;
//		if (af->fd != -1) {
//			sfd = af->fd;
//			continue;
//		}
//		/* Check some /proc file first to not stress kmod */
//		if (!family && !force && af->flag_file) {
//			if (access(af->flag_file, R_OK))
//				continue;
//		}
//#if HAVE_AFNETROM
//		if (af->af == AF_NETROM)
//            type = SOCK_SEQPACKET;
//#endif
//#if HAVE_AFX25
//		if (af->af == AF_X25)
//           type = SOCK_SEQPACKET;
//#endif
//		af->fd = socket(af->af, type, 0);
//		if (af->fd >= 0)
//			sfd = af->fd;
//	}
//	if (sfd < 0)
//		fprintf(stderr, "No usable address families found.\n");
//	return sfd;
//}

