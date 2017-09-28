#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>



#include "pcaputil.h"

int procnetdev_vsn = 1;

static struct interface *int_list, *int_last;

//
// Created by linchanghui on 9/26/17.
//
static struct interface *add_interface(char *name) {
    struct interface *ife, **nextp, *new;

    for (ife = int_last; ife; ife = ife->prev) {
        int n = nstrcmp(ife->name, name);
        if (n == 0)
            return ife;
        if (n < 0)
            break;
    }
    new(new);
    safe_strncpy(new->name, name, IFNAMSIZ);
    nextp = ife ? &ife->next : &int_list;
    new->prev = ife;
    new->next = *nextp;
    if (new->next)
        new->next->prev = new;
    else
        int_last = new;
    *nextp = new;
    return new;
}


static int procnetdev_version(char *buf) {
    if (strstr(buf, "compressed"))
        return 3;
    if (strstr(buf, "bytes"))
        return 2;
    return 1;
}

static char *get_name(char *name, char *p) {
    while (isspace(*p))
        p++;
    while (*p) {
        if (isspace(*p))
            break;
        if (*p == ':') {        /* could be an alias */
            char *dot = p, *dotname = name;
            *name++ = *p++;
            while (isdigit(*p))
                *name++ = *p++;
            if (*p != ':') {    /* it wasn't, backup */
                p = dot;
                name = dotname;
            }
            if (*p == '\0')
                return NULL;
            p++;
            break;
        }
        *name++ = *p++;
    }
    *name++ = '\0';
    return p;
}

static int get_dev_fields(char *bp, struct interface *ife) {
    switch (procnetdev_vsn) {
        case 3:
            sscanf(bp,
                   "%llu %llu %lu %lu %lu %lu %lu %lu %llu %llu %lu %lu %lu %lu %lu %lu",
                   &ife->stats.rx_bytes,
                   &ife->stats.rx_packets,
                   &ife->stats.rx_errors,
                   &ife->stats.rx_dropped,
                   &ife->stats.rx_fifo_errors,
                   &ife->stats.rx_frame_errors,
                   &ife->stats.rx_compressed,
                   &ife->stats.rx_multicast,

                   &ife->stats.tx_bytes,
                   &ife->stats.tx_packets,
                   &ife->stats.tx_errors,
                   &ife->stats.tx_dropped,
                   &ife->stats.tx_fifo_errors,
                   &ife->stats.collisions,
                   &ife->stats.tx_carrier_errors,
                   &ife->stats.tx_compressed);
            break;
        case 2:
            sscanf(bp, "%llu %llu %lu %lu %lu %lu %llu %llu %lu %lu %lu %lu %lu",
                   &ife->stats.rx_bytes,
                   &ife->stats.rx_packets,
                   &ife->stats.rx_errors,
                   &ife->stats.rx_dropped,
                   &ife->stats.rx_fifo_errors,
                   &ife->stats.rx_frame_errors,

                   &ife->stats.tx_bytes,
                   &ife->stats.tx_packets,
                   &ife->stats.tx_errors,
                   &ife->stats.tx_dropped,
                   &ife->stats.tx_fifo_errors,
                   &ife->stats.collisions,
                   &ife->stats.tx_carrier_errors);
            ife->stats.rx_multicast = 0;
            break;
        case 1:
            sscanf(bp, "%llu %lu %lu %lu %lu %llu %lu %lu %lu %lu %lu",
                   &ife->stats.rx_packets,
                   &ife->stats.rx_errors,
                   &ife->stats.rx_dropped,
                   &ife->stats.rx_fifo_errors,
                   &ife->stats.rx_frame_errors,

                   &ife->stats.tx_packets,
                   &ife->stats.tx_errors,
                   &ife->stats.tx_dropped,
                   &ife->stats.tx_fifo_errors,
                   &ife->stats.collisions,
                   &ife->stats.tx_carrier_errors);
            ife->stats.rx_bytes = 0;
            ife->stats.tx_bytes = 0;
            ife->stats.rx_multicast = 0;
            break;
    }
    return 0;
}





static int if_readlist_proc(char *target) {
    static int proc_read;
    FILE *fh;
    char buf[512];
    struct interface *ife = NULL;
    int err;
    int fd;
    struct ifreq ifr;

    if (proc_read)
        return 0;
    if (!target)
        proc_read = 1;

    fh = fopen(_PATH_PROCNET_DEV, "r");
    if (!fh) {
        fprintf(stderr, "Warning: cannot open %s (%s). Limited output.\n",
                _PATH_PROCNET_DEV, strerror(errno));
        //return if_readconf();
        return -1;
    }
    fgets(buf, sizeof buf, fh); /* eat line */
    fgets(buf, sizeof buf, fh);
    procnetdev_vsn = procnetdev_version(buf);

    err = 0;
    while (fgets(buf, sizeof buf, fh)) {
        char *s, name[IFNAMSIZ];
        s = get_name(name, buf);
        ife = add_interface(name);
        get_dev_fields(s, ife);
        ife->statistics_valid = 1;
        if (target && !strcmp(target, name))
            break;
    }
    //go to head
    for (;NULL != ife && NULL != ife->prev; ife = ife->prev);
    //from head to end
    for ( ;NULL != ife; ife = ife->next) {
        fd = socket(AF_INET, SOCK_DGRAM, 0);

        //Type of address to retrieve - IPv4 IP address
        ifr.ifr_addr.sa_family = AF_INET;

        //Copy the interface name in the ifreq structure
        strncpy(ifr.ifr_name , ife->name , IFNAMSIZ-1);

        //get the ip address
        ioctl(fd, SIOCGIFADDR, &ifr);

        //display ip
        printf("IP address of %s - %s\n" , ife->name , inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );

        //get the netmask ip
        ioctl(fd, SIOCGIFNETMASK, &ifr);

        //display netmask
        printf("Netmask of %s - %s\n" , ife->name , inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );

        close(fd);
    }
    if (ferror(fh)) {
        perror(_PATH_PROCNET_DEV);
        err = -1;
        proc_read = 0;
    }

#if 0
    free(fmt);
#endif


    fclose(fh);
    return err;
}

int
main(int argc, char *argv[]) {
    int rc = -1;
    if_readlist_proc(NULL);
    return rc;
}


