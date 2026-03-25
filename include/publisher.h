#ifndef PUBLISHER_H
#define PUBLISHER_H

void init_queue();
void close_queue();
void publish_packet(const char *src_ip, int port, const char *proto, int bytes, int is_scan);

#endif // PUBLISHER_H