/* netif_posix.c — HOME_NET auto-detect via getifaddrs() (Linux/BSD/macOS). */
#include "netif.h"
#include "nta_net.h"

#include <ifaddrs.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static int prefix_from_mask(uint32_t mask_host) {
    int p = 0; uint32_t m = mask_host;
    while (m & 0x80000000u) { p++; m <<= 1; }
    return p;
}

/* Prefixo IPv6 = número de bits 1 da máscara (de sin6_addr). */
static int prefix_from_mask6(const uint8_t m[16]) {
    int p = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t b = m[i];
        while (b & 0x80) { p++; b <<= 1; }
        if (b) break;               /* máscara não contígua: para na primeira falha */
    }
    return p;
}

int netif_home_cidrs(const char *iface, int (*on_cidr)(const char *cidr)) {
    struct ifaddrs *ifap = NULL, *ifa;
    if (getifaddrs(&ifap) != 0) return 0;
    int n = 0;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        int family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) continue;
        if (!ifa->ifa_netmask) continue;
        if (strcmp(ifa->ifa_name, iface) != 0 &&
            strcmp(ifa->ifa_name, "lo")   != 0) continue;

        if (family == AF_INET6) {
            const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)ifa->ifa_addr;
            const struct sockaddr_in6 *m6 = (const struct sockaddr_in6 *)ifa->ifa_netmask;
            uint8_t net[16];
            for (int i = 0; i < 16; i++)
                net[i] = a6->sin6_addr.s6_addr[i] & m6->sin6_addr.s6_addr[i];
            int prefix = prefix_from_mask6(m6->sin6_addr.s6_addr);

            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, net, ip_str, sizeof(ip_str));
            char cidr[64];
            snprintf(cidr, sizeof(cidr), "%s/%d", ip_str, prefix);
            if (on_cidr(cidr) == 0) n++;
            continue;
        }

        uint32_t addr_be = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
        uint32_t mask_be = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
        uint32_t net_be  = addr_be & mask_be;
        int prefix = prefix_from_mask(ntohl(mask_be));

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &net_be, ip_str, sizeof(ip_str));
        char cidr[32];
        snprintf(cidr, sizeof(cidr), "%s/%d", ip_str, prefix);
        if (on_cidr(cidr) == 0) n++;
    }
    freeifaddrs(ifap);
    return n;
}
