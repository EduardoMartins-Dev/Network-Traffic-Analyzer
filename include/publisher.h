#ifndef PUBLISHER_H
#define PUBLISHER_H

void init_queue();
void close_queue();
void publish_packet(const char *src_ip, int port, const char *proto, int bytes,
                    int is_scan, const char *attack_type,
                    const char *kill_chain_stage, int kc_score,
                    const char *mitre_technique);

#endif // PUBLISHER_H
