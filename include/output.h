#ifndef NETWORK_TRAFFIC_ANALYZER_OUTPUT_H
#define NETWORK_TRAFFIC_ANALYZER_OUTPUT_H

// Protótipo da função (Assinatura)
void export_to_json(const char *src_ip, int src_port, const char *dst_ip, int dst_port, const char *proto, int len);

#endif //NETWORK_TRAFFIC_ANALYZER_OUTPUT_H