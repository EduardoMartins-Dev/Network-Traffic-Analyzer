#ifndef NTA_COLLECTOR_H
#define NTA_COLLECTOR_H

#include <time.h>

/* ========================================================================= *
 * DETECTION COLLECTOR (v4.1)                                                *
 *                                                                           *
 * Coleta detecções em memória durante o modo replay.                        *
 * Em modo live, g_replay_mode=0 e collector_record() é no-op.              *
 * ========================================================================= */

#define MAX_DETECTIONS 1024

typedef struct {
    char   attack_type[32];  /* ex: "SYN_FLOOD"     */
    char   src_ip[16];       /* ex: "192.168.1.10"  */
    time_t timestamp;        /* timestamp do pacote  */
} DetectedEvent;

/* Flag global: 0 = modo live (RabbitMQ ativo)
 *              1 = modo replay (RabbitMQ bypassado, collector ativo) */
extern int g_replay_mode;

void                 collector_reset(void);
void                 collector_record(const char *attack_type,
                                      const char *src_ip,
                                      time_t ts);
int                  collector_count(void);
const DetectedEvent *collector_get(int index);

#endif /* NTA_COLLECTOR_H */
