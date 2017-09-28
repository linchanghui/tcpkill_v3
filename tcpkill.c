/*
 * tcpkill.c
 *
 * Kill TCP connections already in progress.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: tcpkill.c,v 1.17 2001/03/17 08:10:43 dugsong Exp $
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <libnet.h>
#include <arpa/inet.h>

#include "pcaputil.h"
#include "version.h"

#define DEFAULT_SEVERITY    3
#define CMD 'netstat |grep ESTABLISHED|awk -F \' \' \'{print $4}\'|grep %d:%d'

FILE *procinfo;

enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING                 /* now a valid state */
};


static int tcp_do_one(int lnr, const char *line, char *src, char *dst, int sport, int dport) {
    unsigned long rxq, txq, time_len, retr, inode;
    int num, local_port, rem_port, d, state, uid, timer_run, timeout;
    char rem_addr[128], local_addr[128], more[512];
    char local_addr2[15], rem_addr2[15]; //like xxx.xxx.xxx.xxx

#if HAVE_AFINET6
    struct sockaddr_in6 localaddr, remaddr;
    char addr6[INET6_ADDRSTRLEN];
    struct in6_addr in6;
    extern struct aftype inet6_aftype;
#else
    struct sockaddr_in localaddr, remaddr;
#endif

    if (lnr == 0)
        return 0;

    num = sscanf(line,
                 "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %ld %512s\n",
                 &d, local_addr, &local_port, rem_addr, &rem_port, &state,
                 &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);
    if (strlen(local_addr) > 8) {
        //ipv6 no support
    } else if (strlen(local_addr) == 8){
        sscanf(local_addr, "%X",
               &((struct sockaddr_in *) &localaddr)->sin_addr.s_addr);
        sscanf(rem_addr, "%X",
               &((struct sockaddr_in *) &remaddr)->sin_addr.s_addr);
        ((struct sockaddr *) &localaddr)->sa_family = AF_INET;
        ((struct sockaddr *) &remaddr)->sa_family = AF_INET;

    } else {
        //todo log error info
    }


    if (num < 11) {
        fprintf(stderr, "warning, got bogus tcp line.\n");
        return 0;
    }

    if (state != TCP_ESTABLISHED) return 0;
    //not sure the localhost pattern 0.0.0.0/127.0.0.1
    if (strcmp(src, inet_ntoa(((struct sockaddr_in *) &remaddr)->sin_addr)) == 0
            && strcmp(dst, inet_ntoa(((struct sockaddr_in *) &localaddr)->sin_addr)) == 0
            && rem_port == sport
            && local_port == dport) {
        return 1;
    }

    return 0;
}

static int tcp_info(char *src, char *dst, int sport, int dport) {
    char buffer[8192];
    int rc = 0;
    int lnr = 0;
    procinfo = fopen(_PATH_PROCNET_TCP, "r"); //todo why '/proc/net/tcp' why wrong
    if (procinfo == NULL) {
        if (errno != ENOENT) {
            printf("fopen failed, errno = %d\n", errno);
            perror((_PATH_PROCNET_TCP));
            return -1;
        }
    } else {
        do {
            if (fgets(buffer, sizeof(buffer), procinfo))
                if ((tcp_do_one)(lnr++, buffer, src, dst, sport, dport)) return 1;
        } while (!feof(procinfo));
        fclose(procinfo);
    }

}

int Opt_severity = DEFAULT_SEVERITY;
int pcap_off;
pcap_t *pd;
int Opt_max_kill = 0;
int kill_counter = 0;

uint16_t both_side_done = 0;

struct tcp_connection {
    u_short sport;
    u_short dport;
    char *src;
    char *dst;
    libnet_t *l;
};

static void
usage(void) {
    fprintf(stderr, "Version: " VERSION "\n"
            "Usage: tcpkill [-i interface] [-m max kills] [-1..9] expression\n");
    exit(1);
}


int connectionExisted(char *src, char *dst, int sport, int dport) {
    return tcp_info(src, dst, sport, dport);
}

static void
tcp_kill_cb(u_char *user, const struct pcap_pkthdr *pcap, const u_char *pkt) {
    struct libnet_ipv4_hdr *ip;
    struct libnet_tcp_hdr *tcp;
    char ctext[64];
    u_int32_t seq, win;
    int i = 0, len;
    libnet_t *l;

    l = (libnet_t *) user;
    pkt += pcap_off;
    len = pcap->caplen - pcap_off;

    ip = (struct libnet_ipv4_hdr *) pkt;
    if (ip->ip_p != IPPROTO_TCP)
        return;

    tcp = (struct libnet_tcp_hdr *) (pkt + (ip->ip_hl << 2));
    if (tcp->th_flags & (TH_SYN | TH_FIN | TH_RST))
        return;

    seq = ntohl(tcp->th_ack);
    win = ntohs(tcp->th_win);

    snprintf(ctext, sizeof(ctext), "%s:%d > %s:%d:",
             libnet_addr2name4(ip->ip_src.s_addr, LIBNET_DONT_RESOLVE),
             ntohs(tcp->th_sport),
             libnet_addr2name4(ip->ip_dst.s_addr, LIBNET_DONT_RESOLVE),
             ntohs(tcp->th_dport));

    for (i = 0; i < Opt_severity; i++) {
        seq += (i * win);

        libnet_clear_packet(l);
        printf("%d %d\n", tcp->th_dport, tcp->th_sport);
        libnet_build_tcp(ntohs(tcp->th_dport), ntohs(tcp->th_sport),
                         seq, 0, TH_RST, 0, 0, 0, LIBNET_TCP_H,
                         NULL, 0, l, 0);
        libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0,
                          libnet_get_prand(LIBNET_PRu16), 0, 64,
                          IPPROTO_TCP, 0, ip->ip_dst.s_addr,
                          ip->ip_src.s_addr, NULL, 0, l, 0);

        if (libnet_write(l) < 0)
            warn("write");

        fprintf(stderr, "%s R %lu:%lu(0) win 0\n",
                ctext,
                (unsigned long) seq,
                (unsigned long) seq);
    }

    //break loop if send rst to both side
    if (both_side_done == 0) {
        both_side_done = tcp->th_dport;
    } else if (tcp->th_dport != both_side_done) {

        //check whether tcp is broken
        if (!connectionExisted(inet_ntoa(ip->ip_dst),
                              inet_ntoa(ip->ip_src),
                              tcp->th_sport,
                              tcp->th_dport) &&
                !connectionExisted(inet_ntoa(ip->ip_src),
                                   inet_ntoa(ip->ip_dst),
                                   tcp->th_dport,
                                   tcp->th_sport)) {
            pcap_breakloop(pd);
        }
        //Exceptions case ,reset the flag
        both_side_done = 0;
    }
}


int build_syn(u_char *user, u_short sport, u_short dport, char *srchost, char *dsthost) {
    printf("%d %d %s %s\n", sport, dport, srchost, dsthost);
    libnet_t *l;
    l = (libnet_t *) user;
    struct in_addr ip_src, ip_dst;
    ip_src.s_addr = inet_addr(srchost);
    ip_dst.s_addr = inet_addr(dsthost);
    u_int32_t seq = 12345;
    u_int32_t ack = 12345;

    u_char options[12] = {1, 1, 8, 10, 0, 32, 230, 114, 0, 32, 230, 114};
    libnet_clear_packet(l);
    //libnet_seed_prand(l); if seq num bigger than real seq num maybe the packet will be queued wait seq num increase to fake seq num
    //libnet_build_tcp_options(options, 12, l, 0); unnecssary to set tcp options

    libnet_build_tcp(dport, sport,
                     seq, ack, TH_FIN | TH_ACK, 350, 0, 0, LIBNET_TCP_H,
                     NULL, 0, l, 0);

    libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0,
                      libnet_get_prand(LIBNET_PRu16), 0, 64,
                      IPPROTO_TCP, 0, ip_dst.s_addr,
                      ip_src.s_addr, NULL, 0, l, 0);

    if (libnet_write(l) < 0) {
        printf("send failed.\n");
        warn("write");
    } else {
        printf("send succ\n");
    }
    //send to other side to get both side ack
    libnet_clear_packet(l);

    libnet_build_tcp(sport, dport,
                     seq, ack, TH_FIN | TH_ACK, 350, 0, 0, LIBNET_TCP_H,
                     NULL, 0, l, 0);

    libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0,
                      libnet_get_prand(LIBNET_PRu16), 0, 64,
                      IPPROTO_TCP, 0, ip_src.s_addr,
                      ip_dst.s_addr, NULL, 0, l, 0);

    if (libnet_write(l) < 0) {
        printf("send failed.\n");
        warn("write");
    } else {
        printf("send succ\n");
    }
    return 0;
}

void *trigger(void *data) {
    struct tcp_connection *d = (struct tcp_connection *) data;
    int count = 5;
    while (count--) {
        sleep(1);
    }
    build_syn((u_char *) (d->l), d->sport, d->dport, d->src, d->dst);
    return NULL;
}


int
main(int argc, char *argv[]) {
    extern char *optarg;
    extern int optind;
    int c;
    char *p, *intf, *filter, ebuf[PCAP_ERRBUF_SIZE];
    char libnet_ebuf[LIBNET_ERRBUF_SIZE];
    char *src = NULL, *dst = NULL;
    int sport = -1, dport = -1;
    libnet_t *l;
    libnet_t *l2;

    both_side_done = 0;
    intf = NULL;

    while ((c = getopt(argc, argv, "i:t:s:d:k:")) != -1) {
        switch (c) {
            case 'i':
                intf = optarg;
                break;
            case 't':
                sport = atoi(optarg);
                break;
            case 's':
                src = optarg;
                break;
            case 'k':
                dport = atoi(optarg);
                break;
            case 'd':
                dst = optarg;
                break;;
            default:
                usage();
                break;
        }
    }
    if (intf == NULL && (intf = pcap_lookupdev(ebuf)) == NULL) {
        errx(1, "%s", ebuf);
    }

    if (argc == 0) {
        usage();
        return 0;
    }

    //check connection ESTABLISHED
    if (!connectionExisted(src, dst, sport, dport)) {
        //log record not found
        return 0;
    }

    static char f[1024];
    sprintf(f,
            "(src port %d and dst port %d and src host %s and dst host %s) or (src port %d and dst port %d and src host %s and dst host %s)",
            sport, dport, src, dst, dport, sport, dst, src);
    printf("%s\n", f);
    filter = f;

    if ((pd = pcap_init(intf, filter, 64)) == NULL)
        errx(1, "couldn't initialize sniffing");

    if ((pcap_off = pcap_dloff(pd)) < 0)
        errx(1, "couldn't determine link layer offset");

    if ((l = libnet_init(LIBNET_RAW4, NULL, libnet_ebuf)) == NULL)
        errx(1, "couldn't initialize sending");
    if ((l2 = libnet_init(LIBNET_RAW4, NULL, libnet_ebuf)) == NULL)
        errx(1, "couldn't initialize sending");

    libnet_seed_prand(l);
    libnet_seed_prand(l2);

    warnx("listening on %s [%s]", intf, filter);


    struct tcp_connection data;
    data.l = l2;
    data.sport = sport;
    data.dport = dport;
    data.src = src;
    data.dst = dst;
    pthread_t tid;
    //pthread_create(&tid, NULL, trigger, &data);
    build_syn((u_char *) l2, sport, dport, src, dst);
    pcap_loop(pd, -1, tcp_kill_cb, (u_char *) l);

    /* NOTREACHED */
    exit(0);
}
