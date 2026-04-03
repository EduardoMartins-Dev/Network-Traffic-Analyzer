#include <string.h>
#include "../../include/collector.h"

/* Flag global — define aqui, extern em todos os outros módulos */
int g_replay_mode = 0;

static DetectedEvent g_events[MAX_DETECTIONS];
static int           g_count = 0;

void collector_reset(void) {
    memset(g_events, 0, sizeof(g_events));
    g_count = 0;
}

void collector_record(const char *attack_type, const char *src_ip, time_t ts) {
    if (!g_replay_mode || g_count >= MAX_DETECTIONS) return;

    strncpy(g_events[g_count].attack_type, attack_type,
            sizeof(g_events[g_count].attack_type) - 1);
    strncpy(g_events[g_count].src_ip, src_ip,
            sizeof(g_events[g_count].src_ip) - 1);
    g_events[g_count].timestamp = ts;
    g_count++;
}

int collector_count(void) {
    return g_count;
}

const DetectedEvent *collector_get(int index) {
    if (index < 0 || index >= g_count) return NULL;
    return &g_events[index];
}
