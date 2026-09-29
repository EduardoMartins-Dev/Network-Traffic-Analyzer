#ifndef NTA_NETIF_H
#define NTA_NETIF_H

/* ========================================================================= *
 * Descoberta das redes IPv4 locais de uma interface (HOME_NET auto-detect). *
 *                                                                           *
 * Implementações por plataforma:                                            *
 *   src/agent/platform/netif_posix.c — getifaddrs() (Linux, FreeBSD, macOS)       *
 *   src/agent/platform/netif_win32.c — GetAdaptersAddresses() (Windows)           *
 *                                                                           *
 * `iface` é o nome usado no pcap_open_live: "eth0" no POSIX,                *
 * "\Device\NPF_{GUID}" no Windows (Npcap). Loopback é sempre incluída.      *
 * Chama `on_cidr("a.b.c.d/nn")` para cada rede e retorna quantas o         *
 * callback aceitou (retorno 0 do callback).                                 *
 * ========================================================================= */

int netif_home_cidrs(const char *iface, int (*on_cidr)(const char *cidr));

#endif /* NTA_NETIF_H */
