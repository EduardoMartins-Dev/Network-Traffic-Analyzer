/* netif_win32.c — HOME_NET auto-detect via GetAdaptersAddresses() (Windows).
 *
 * O Npcap nomeia a interface como "\Device\NPF_{GUID}" e o IP Helper expõe o
 * mesmo "{GUID}" em AdapterName — é por ele que casamos os dois. */
#include "netif.h"
#include "nta_net.h"

#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int netif_home_cidrs(const char *iface, int (*on_cidr)(const char *cidr)) {
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                  GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size  = 16 * 1024;
    IP_ADAPTER_ADDRESSES *list = NULL;
    ULONG rc;

    /* Buffer pode crescer entre a consulta de tamanho e a leitura — tenta 3x. */
    for (int attempt = 0; attempt < 3; attempt++) {
        list = (IP_ADAPTER_ADDRESSES *)malloc(size);
        if (!list) return 0;
        rc = GetAdaptersAddresses(AF_INET, flags, NULL, list, &size);
        if (rc != ERROR_BUFFER_OVERFLOW) break;
        free(list);
        list = NULL;
    }
    if (!list || rc != NO_ERROR) { free(list); return 0; }

    int n = 0;
    for (IP_ADAPTER_ADDRESSES *a = list; a; a = a->Next) {
        int is_loopback = (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
        if (!is_loopback && !(a->AdapterName && strstr(iface, a->AdapterName)))
            continue;

        for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family != AF_INET) continue;

            int prefix = u->OnLinkPrefixLength;
            if (prefix < 0 || prefix > 32) continue;
            uint32_t mask_be = htonl(prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix));
            uint32_t addr_be = ((struct sockaddr_in *)u->Address.lpSockaddr)->sin_addr.s_addr;
            uint32_t net_be  = addr_be & mask_be;

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &net_be, ip_str, sizeof(ip_str));
            char cidr[32];
            snprintf(cidr, sizeof(cidr), "%s/%d", ip_str, prefix);
            if (on_cidr(cidr) == 0) n++;
        }
    }
    free(list);
    return n;
}
