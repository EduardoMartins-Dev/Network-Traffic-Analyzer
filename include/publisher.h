#ifndef  PUBLISHER_H
#define  PUBLISHER_H

// starta conexao com o rabbit

void init_queue();

//Envia o JSON
void send_message(const char *message);

// fecha conexao

void close_queue();


#endif //PUBLISHER_H