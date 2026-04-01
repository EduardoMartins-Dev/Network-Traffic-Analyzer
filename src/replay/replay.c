#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "../../include/replay.h"
#include "../../include/collector.h"
#include "../../include/capture.h"
#include "../../include/cJSON.h"

/* Suporte multiplataforma para leitura de diretório */
#ifdef _WIN32
    #include <windows.h>
#else
    #include <dirent.h>
#endif

/* ========================================================================= *
 * PARSE DE ARGUMENTOS                                                       *
 * ========================================================================= */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Uso:\n"
        "  %s <interface>                          — captura ao vivo\n"
        "  %s --replay <file.pcap>                 — replay de arquivo\n"
        "        [--expect <gabarito.json>]         — valida detecções\n"
        "  %s --replay-dir <diretório>             — replay de diretório\n"
        "        [--report <relatório.json>]        — salva relatório\n",
        prog, prog, prog);
}

AgentArgs parse_args(int argc, char *argv[]) {
    AgentArgs args;
    memset(&args, 0, sizeof(args));
    args.mode = MODE_LIVE;

    if (argc < 2) {
        print_usage(argv[0]);
        exit(1);
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--replay") == 0 && i + 1 < argc) {
            args.mode      = MODE_REPLAY_FILE;
            args.pcap_file = argv[++i];
        } else if (strcmp(argv[i], "--replay-dir") == 0 && i + 1 < argc) {
            args.mode       = MODE_REPLAY_DIR;
            args.replay_dir = argv[++i];
        } else if (strcmp(argv[i], "--expect") == 0 && i + 1 < argc) {
            args.expect_file = argv[++i];
        } else if (strcmp(argv[i], "--report") == 0 && i + 1 < argc) {
            args.report_file = argv[++i];
        } else if (args.mode == MODE_LIVE && argv[i][0] != '-') {
            args.iface = argv[i];
        } else {
            fprintf(stderr, "Argumento desconhecido: %s\n", argv[i]);
            print_usage(argv[0]);
            exit(1);
        }
    }

    if (args.mode == MODE_LIVE && !args.iface) {
        print_usage(argv[0]);
        exit(1);
    }

    return args;
}

/* ========================================================================= *
 * GABARITO — carga e liberação                                              *
 * ========================================================================= */

Gabarito *gabarito_load(const char *json_path) {
    FILE *f = fopen(json_path, "rb");
    if (!f) {
        fprintf(stderr, "[REPLAY] Não foi possível abrir gabarito: %s\n", json_path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    char *buf = malloc((size_t)size + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t read_bytes = fread(buf, 1, (size_t)size, f);
    buf[read_bytes] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(buf);
    free(buf);

    if (!root) {
        fprintf(stderr, "[REPLAY] JSON inválido em: %s\n", json_path);
        return NULL;
    }

    Gabarito *g = calloc(1, sizeof(Gabarito));
    if (!g) { cJSON_Delete(root); return NULL; }

    cJSON *expected = cJSON_GetObjectItem(root, "expected");
    if (!cJSON_IsArray(expected)) {
        fprintf(stderr, "[REPLAY] Gabarito sem array 'expected': %s\n", json_path);
        cJSON_Delete(root);
        free(g);
        return NULL;
    }

    int n = cJSON_GetArraySize(expected);
    for (int i = 0; i < n && g->count < MAX_EXPECTED; i++) {
        cJSON *item = cJSON_GetArrayItem(expected, i);

        cJSON *at = cJSON_GetObjectItem(item, "attack_type");
        cJSON *ip = cJSON_GetObjectItem(item, "src_ip");

        if (!cJSON_IsString(at) || !cJSON_IsString(ip)) continue;

        ExpectedDetection *e = &g->entries[g->count];
        strncpy(e->attack_type, at->valuestring, sizeof(e->attack_type) - 1);
        strncpy(e->src_ip,      ip->valuestring, sizeof(e->src_ip) - 1);

        cJSON *tw = cJSON_GetObjectItem(item, "time_window");
        if (cJSON_IsObject(tw)) {
            cJSON *ts = cJSON_GetObjectItem(tw, "start_sec");
            cJSON *te = cJSON_GetObjectItem(tw, "end_sec");
            if (cJSON_IsNumber(ts) && cJSON_IsNumber(te)) {
                e->has_time_window = 1;
                e->t_start_sec     = (long)ts->valuedouble;
                e->t_end_sec       = (long)te->valuedouble;
            }
        }

        g->count++;
    }

    cJSON_Delete(root);
    return g;
}

void gabarito_free(Gabarito *g) {
    free(g);
}

/* ========================================================================= *
 * COMPARE RESULTS                                                           *
 * ========================================================================= */

void compare_results(const Gabarito *g, ReplayResult *r) {
    if (!g || g->count == 0) return;

    r->expected_count = g->count;
    r->passed         = 0;
    r->failed         = 0;

    printf("\n%-14s %-15s %s\n", "RESULTADO", "ATTACK_TYPE", "SRC_IP");
    printf("%-14s %-15s %s\n",   "---------", "-----------", "------");

    for (int i = 0; i < g->count; i++) {
        const ExpectedDetection *e = &g->entries[i];
        int found = 0;

        for (int j = 0; j < collector_count(); j++) {
            const DetectedEvent *d = collector_get(j);

            if (strcmp(d->attack_type, e->attack_type) != 0) continue;
            if (strcmp(d->src_ip,      e->src_ip)      != 0) continue;

            if (e->has_time_window && g->pcap_start_ts > 0) {
                long rel = (long)(d->timestamp - g->pcap_start_ts);
                if (rel < e->t_start_sec || rel > e->t_end_sec) continue;
            }

            found = 1;
            break;
        }

        if (found) {
            printf("[PASS]         %-15s %s\n", e->attack_type, e->src_ip);
            r->passed++;
        } else {
            printf("[FAIL]         %-15s %s\n", e->attack_type, e->src_ip);
            r->failed++;
        }
    }

    r->score = (r->expected_count > 0)
               ? ((double)r->passed / r->expected_count) * 100.0
               : 100.0;
}

void print_replay_result(const ReplayResult *r) {
    printf("\n--- Resultado: %s ---\n", r->pcap_file ? r->pcap_file : "N/A");
    if (r->expected_count > 0) {
        printf("Score: %.1f%%  (%d/%d detecções corretas)\n",
               r->score, r->passed, r->expected_count);
    } else {
        printf("Nenhum gabarito fornecido — replay concluído sem validação.\n");
        printf("Detecções capturadas: %d\n", collector_count());
        for (int i = 0; i < collector_count(); i++) {
            const DetectedEvent *d = collector_get(i);
            printf("  %-15s %s\n", d->attack_type, d->src_ip);
        }
    }
}

/* ========================================================================= *
 * REPLAY DE ARQUIVO ÚNICO                                                   *
 * ========================================================================= */

ReplayResult replay_file(const char *pcap_path, const Gabarito *g) {
    ReplayResult r;
    memset(&r, 0, sizeof(r));
    r.pcap_file = pcap_path;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_path, errbuf);
    if (!handle) {
        fprintf(stderr, "[REPLAY] Não foi possível abrir: %s — %s\n", pcap_path, errbuf);
        return r;
    }

    printf("[REPLAY] Processando: %s\n", pcap_path);

    collector_reset();
    g_replay_mode = 1;

    /* Captura o timestamp do primeiro pacote para time_window relativo */
    if (g && g->count > 0) {
        struct pcap_pkthdr *hdr;
        const u_char *pkt;
        int res = pcap_next_ex(handle, &hdr, &pkt);
        if (res == 1) {
            /* Processa o primeiro pacote e guarda o timestamp base */
            ((Gabarito *)g)->pcap_start_ts = (long)hdr->ts.tv_sec;
            packet_handler(NULL, hdr, pkt);
        }
    }

    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);

    g_replay_mode = 0;

    compare_results(g, &r);
    return r;
}

/* ========================================================================= *
 * REPLAY DE DIRETÓRIO                                                       *
 * ========================================================================= */

/* Constrói caminho do gabarito: troca extensão .pcap por .json */
static void derive_gabarito_path(const char *pcap_path, char *out, size_t out_size) {
    strncpy(out, pcap_path, out_size - 1);
    out[out_size - 1] = '\0';
    char *dot = strrchr(out, '.');
    if (dot) strncpy(dot, ".json", out_size - (size_t)(dot - out));
}

static void write_report_json(const char *report_path,
                              ReplayResult *results, int count,
                              double total_score) {
    cJSON *root  = cJSON_CreateObject();
    cJSON *arr   = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "results", arr);
    cJSON_AddNumberToObject(root, "total_score", total_score);

    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "file",     results[i].pcap_file);
        cJSON_AddNumberToObject(item, "score",    results[i].score);
        cJSON_AddNumberToObject(item, "passed",   results[i].passed);
        cJSON_AddNumberToObject(item, "failed",   results[i].failed);
        cJSON_AddNumberToObject(item, "expected", results[i].expected_count);
        cJSON_AddItemToArray(arr, item);
    }

    char *json_str = cJSON_Print(root);
    FILE *f = fopen(report_path, "w");
    if (f) {
        fputs(json_str, f);
        fclose(f);
        printf("[REPLAY] Relatório salvo em: %s\n", report_path);
    } else {
        fprintf(stderr, "[REPLAY] Não foi possível salvar relatório: %s\n", report_path);
    }

    free(json_str);
    cJSON_Delete(root);
}

void replay_dir(const char *dir_path, const char *report_out) {
    ReplayResult results[256];
    int result_count = 0;

    printf("[REPLAY] Processando diretório: %s\n\n", dir_path);

#ifdef _WIN32
    char pattern[512];
    snprintf(pattern, sizeof(pattern), "%s\\*.pcap", dir_path);

    WIN32_FIND_DATA ffd;
    HANDLE hFind = FindFirstFile(pattern, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[REPLAY] Nenhum .pcap encontrado em: %s\n", dir_path);
        return;
    }

    do {
        char pcap_path[512];
        snprintf(pcap_path, sizeof(pcap_path), "%s\\%s", dir_path, ffd.cFileName);

        char gabarito_path[512];
        derive_gabarito_path(pcap_path, gabarito_path, sizeof(gabarito_path));

        Gabarito *g = gabarito_load(gabarito_path);
        ReplayResult r = replay_file(pcap_path, g);
        print_replay_result(&r);
        gabarito_free(g);

        if (result_count < 256)
            results[result_count++] = r;

    } while (FindNextFile(hFind, &ffd));
    FindClose(hFind);

#else
    DIR *d = opendir(dir_path);
    if (!d) {
        fprintf(stderr, "[REPLAY] Não foi possível abrir diretório: %s\n", dir_path);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        /* Filtra apenas arquivos .pcap */
        const char *name = entry->d_name;
        size_t len = strlen(name);
        if (len < 5 || strcmp(name + len - 5, ".pcap") != 0) continue;

        char pcap_path[512];
        snprintf(pcap_path, sizeof(pcap_path), "%s/%s", dir_path, name);

        char gabarito_path[512];
        derive_gabarito_path(pcap_path, gabarito_path, sizeof(gabarito_path));

        Gabarito *g = gabarito_load(gabarito_path);
        ReplayResult r = replay_file(pcap_path, g);
        print_replay_result(&r);
        gabarito_free(g);

        if (result_count < 256)
            results[result_count++] = r;
    }
    closedir(d);
#endif

    if (result_count == 0) {
        fprintf(stderr, "[REPLAY] Nenhum .pcap processado em: %s\n", dir_path);
        return;
    }

    /* Score agregado */
    int total_passed = 0, total_expected = 0;
    for (int i = 0; i < result_count; i++) {
        total_passed   += results[i].passed;
        total_expected += results[i].expected_count;
    }

    double aggregate = (total_expected > 0)
                       ? ((double)total_passed / total_expected) * 100.0
                       : 100.0;

    printf("\n=== Score agregado: %.1f%% (%d/%d) ===\n",
           aggregate, total_passed, total_expected);

    if (report_out)
        write_report_json(report_out, results, result_count, aggregate);

    if (total_expected > 0 && aggregate < 80.0) {
        fprintf(stderr, "[REPLAY] Score abaixo de 80%% — falha no CI.\n");
        exit(1);
    }
}
