#ifndef  PUBLISHER_H
#define  PUBLISHER_H

// starta conexao com o rabbit

void init_queue();

//Envia o JSON
static void send_message(const char *message);

// fecha conexao

void close_queue();

void publish_packet(const char* src_ip, int port, const char* proto, int bytes, int is_scan);



#endif //PUBLISHER_H