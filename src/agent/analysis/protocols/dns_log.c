/* ========================================================================= *
 * Log de protocolo DNS do agente (B16, PR a). Ver include/agent/dns_log.h.  *
 *                                                                           *
 * Parser defensivo: cada leitura é checada contra o tamanho disponível. Nome *
 * com ponteiro de compressão tem limite de saltos (DNS_MAX_PTR_JUMPS) e o    *
 * nome expandido tem limite de 255 octetos (RFC 1035), então um ponteiro em   *
 * laço não trava o analyzer. O texto de saída é só ASCII imprimível.         *
 * ========================================================================= */
#include "dns_log.h"
#include "ringbuf.h"

/* AF_INET/AF_INET6 e inet_ntop: no FreeBSD o cabeçalho exige <sys/socket.h> e
 * <netinet/in.h> explícitos (nta_net.h não os inclui sozinho). */
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include "nta_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int g_dns_log_on = 0;
static int g_dns_hash = 0;

static ringbuf_t g_rb;
static int       g_rb_ready = 0;

#define DNS_HDR_LEN         12
#define DNS_PORT            53
#define DNS_MAX_PTR_JUMPS    8
#define DNS_MAX_WIRE_NAME  255

static const char HEX[] = "0123456789abcdef";

/* ========================================================================= *
 * CONFIGURAÇÃO                                                              *
 * ========================================================================= */

void dns_log_set_options(int on, int hash_names) {
    g_dns_log_on = on ? 1 : 0;
    g_dns_hash   = hash_names ? 1 : 0;
}

int dns_log_config_from_env(char *err, size_t errlen) {
    dns_log_set_options(0, 0);

    int on = 0;
    const char *logs = getenv("AGENT_PROTO_LOGS");
    if (logs && *logs) {
        char buf[128];
        if (strlen(logs) >= sizeof(buf)) {
            snprintf(err, errlen, "AGENT_PROTO_LOGS muito longo");
            return -1;
        }
        for (size_t i = 0; logs[i]; i++) {
            char c = logs[i];
            buf[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
            buf[i + 1] = '\0';
        }
        char *save = NULL;
        for (char *tok = strtok_r(buf, ", \t", &save); tok;
             tok = strtok_r(NULL, ", \t", &save)) {
            if (strcmp(tok, "dns") == 0) {
                on = 1;
            } else {
                /* Erro (rc 1 na subida), não aviso: tls/http ainda não existem
                 * nesta versão e a config não pode parecer ativa sem estar. */
                snprintf(err, errlen,
                         "AGENT_PROTO_LOGS: tipo '%s' nao suportado nesta versao "
                         "(aceito: dns)", tok);
                return -1;
            }
        }
    }

    int hash = 0;
    const char *h = getenv("AGENT_PROTO_HASH_NAMES");
    if (h && *h) {
        if (strcmp(h, "1") == 0) {
            hash = 1;
        } else if (strcmp(h, "0") != 0) {
            snprintf(err, errlen,
                     "AGENT_PROTO_HASH_NAMES deve ser 1 ou 0 (valor '%s')", h);
            return -1;
        }
    }

    dns_log_set_options(on, hash);
    return 0;
}

/* ========================================================================= *
 * PARSER                                                                    *
 * ========================================================================= */

/* Saída de texto com limite: escreve só se o pedaço inteiro couber (sobra
 * espaço para o NUL). Ao estourar, marca truncado e ignora o resto, sem cortar
 * um escape (\DDD) no meio. */
/* Nome próprio: TextOut colide com a macro de wingdi.h no Windows. */
typedef struct {
    char  *buf;
    size_t cap;
    size_t w;
    int    trunc;
} DnsText;

static void to_put(DnsText *t, const char *s, size_t n) {
    if (t->trunc) return;
    if (t->w + n >= t->cap) { t->trunc = 1; return; }
    memcpy(t->buf + t->w, s, n);
    t->w += n;
}

static uint16_t be16(const uint8_t *p) {
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

/* Decodifica o nome de pergunta que começa em msg[off]. Escreve o texto em `t`
 * e devolve em *end o offset logo após o nome na sequência original (depois do
 * byte zero, ou depois do primeiro ponteiro). -1 se o nome é inválido. */
static int decode_name(const uint8_t *msg, size_t len, size_t off,
                       DnsText *t, size_t *end) {
    size_t pos = off, after = 0;
    int    after_set = 0, jumps = 0, labels = 0;
    size_t wire = 1;                      /* byte zero final */

    for (;;) {
        if (pos >= len) return -1;
        uint8_t b = msg[pos];

        if ((b & 0xC0) == 0xC0) {         /* ponteiro de compressão */
            if (pos + 1 >= len) return -1;
            if (++jumps > DNS_MAX_PTR_JUMPS) return -1;
            size_t target = ((size_t)(b & 0x3F) << 8) | msg[pos + 1];
            if (!after_set) { after = pos + 2; after_set = 1; }
            if (target >= len) return -1;
            pos = target;
            continue;
        }
        if ((b & 0xC0) != 0) return -1;  /* 0x40/0x80: rótulo reservado */

        if (b == 0) {                    /* fim do nome */
            if (!after_set) { after = pos + 1; after_set = 1; }
            break;
        }

        size_t n = b;                    /* 1..63 */
        if (pos + 1 + n > len) return -1;
        wire += 1 + n;
        if (wire > DNS_MAX_WIRE_NAME) return -1;

        if (labels > 0) to_put(t, ".", 1);
        for (size_t i = 0; i < n; i++) {
            unsigned c = msg[pos + 1 + i];
            if (c == '.' || c == '\\') {
                char e[2] = { '\\', (char)c };
                to_put(t, e, 2);
            } else if (c >= 0x21 && c <= 0x7E) {
                char ch = (char)c;
                to_put(t, &ch, 1);
            } else {
                char e[4] = { '\\', (char)('0' + c / 100),
                              (char)('0' + (c / 10) % 10), (char)('0' + c % 10) };
                to_put(t, e, 4);
            }
        }
        labels++;
        pos += 1 + n;
    }

    if (labels == 0) to_put(t, ".", 1);  /* nome da raiz */
    t->buf[t->w] = '\0';                 /* w < cap garantido por to_put */
    *end = after;
    return 0;
}

int dns_log_parse(uint8_t ip_proto, const uint8_t *l4, int l4_len, DnsEvent *out) {
    if (!l4 || !out || l4_len <= 0) return -1;
    size_t avail = (size_t)l4_len;

    const uint8_t *msg;
    size_t         msg_len;      /* bytes que existem de fato no quadro */
    uint32_t       declared;     /* tamanho da mensagem DNS declarado */

    if (ip_proto == DNS_PROTO_UDP) {
        if (avail < 8) return -1;
        if (be16(l4) != DNS_PORT && be16(l4 + 2) != DNS_PORT) return -1;
        uint16_t ulen = be16(l4 + 4);
        if (ulen < 8) return -1;
        /* Fragmento inicial de resposta grande: o cabeçalho UDP diz o tamanho
         * total, mas só parte está no quadro. Lê o que há; `bytes` mantém o
         * tamanho declarado. */
        declared = (uint32_t)(ulen - 8);
        msg      = l4 + 8;
        msg_len  = (avail - 8 < declared) ? (avail - 8) : declared;
    } else if (ip_proto == DNS_PROTO_TCP) {
        if (avail < 20) return -1;
        if (be16(l4) != DNS_PORT && be16(l4 + 2) != DNS_PORT) return -1;
        size_t hlen = (size_t)(l4[12] >> 4) * 4;   /* data offset */
        if (hlen < 20 || hlen > avail) return -1;
        size_t seg = avail - hlen;
        if (seg < 2) return -1;
        /* Sem remontagem: a mensagem tem de estar inteira neste segmento e o
         * prefixo de 2 bytes tem de bater com ele. Senão, não há registro. */
        declared = be16(l4 + hlen);
        if (declared < DNS_HDR_LEN || declared > seg - 2) return -1;
        msg     = l4 + hlen + 2;
        msg_len = declared;
    } else {
        return -1;
    }

    if (msg_len < DNS_HDR_LEN) return -1;
    if (be16(msg + 4) == 0) return -1;             /* QDCOUNT 0: sem pergunta */

    DnsText t = { out->qname, sizeof(out->qname), 0, 0 };
    size_t  after = 0;
    if (decode_name(msg, msg_len, DNS_HDR_LEN, &t, &after) != 0) return -1;
    if (after + 4 > msg_len) return -1;            /* QTYPE + QCLASS */

    out->qtype  = be16(msg + after);
    out->rcode  = (uint8_t)(msg[3] & 0x0F);
    out->resp   = (msg[2] & 0x80) ? 1 : 0;
    out->proto  = ip_proto;
    out->bytes  = declared;
    return 0;
}

/* ========================================================================= *
 * HASH (FNV-1a 64, não criptográfico)                                       *
 * ========================================================================= */

void dns_log_hash_hex(const char *s, char out[17]) {
    uint64_t h = 14695981039346656037ULL;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned c = *p;
        if (c >= 'A' && c <= 'Z') c += 32;   /* DNS não diferencia caixa */
        h ^= c;
        h *= 1099511628211ULL;
    }
    for (int i = 15; i >= 0; i--) {
        out[i] = HEX[h & 0xF];
        h >>= 4;
    }
    out[16] = '\0';
}

/* ========================================================================= *
 * EMISSÃO E RING                                                            *
 * ========================================================================= */

/* Texto do IP (inet_ntop, buffer do chamador de 46 bytes). Só na thread de logs
 * ou no replay: nunca no caminho quente da análise. */
static void fmt_ip(const DnsEvent *e, const uint8_t *addr, char out[46]) {
    if (!inet_ntop(e->is_v6 ? AF_INET6 : AF_INET, addr, out, 46)) out[0] = '\0';
}

/* qname de saída: o texto, ou o hash quando AGENT_PROTO_HASH_NAMES=1. */
static void fmt_qname(const DnsEvent *e, char out[DNS_LOG_QNAME_MAX]) {
    if (g_dns_hash) {
        char h[17];
        dns_log_hash_hex(e->qname, h);
        memcpy(out, h, sizeof(h));
    } else {
        memcpy(out, e->qname, sizeof(e->qname));
    }
}

void dns_log_submit(const DnsEvent *e, int replay) {
    if (replay) {
        char src[46], dst[46], qn[DNS_LOG_QNAME_MAX];
        fmt_ip(e, e->src, src);
        fmt_ip(e, e->dst, dst);
        fmt_qname(e, qn);
        printf("[PROTO] dns ts=%lld proto=%s src=%s dst=%s qname=%s qtype=%u "
               "rcode=%u resp=%u bytes=%u\n",
               (long long)e->ts_ms, e->proto == DNS_PROTO_TCP ? "TCP" : "UDP",
               src, dst, qn, (unsigned)e->qtype,
               (unsigned)e->rcode, (unsigned)e->resp, (unsigned)e->bytes);
        return;
    }

    if (!g_rb_ready) return;
    (void)rb_push(&g_rb, e);   /* cópia de bytes; rb_push conta o descarte */
}

int dns_log_start(size_t capacity) {
    if (g_rb_ready) return 0;
    if (rb_init(&g_rb, capacity, sizeof(DnsEvent)) != 0) return -1;
    g_rb_ready = 1;
    return 0;
}

void dns_log_stop(void) {
    if (!g_rb_ready) return;
    rb_destroy(&g_rb);
    g_rb_ready = 0;
}

int dns_log_pop(DnsEvent *out) {
    return g_rb_ready ? rb_pop(&g_rb, out) : -1;
}

size_t dns_log_depth(void) {
    return g_rb_ready ? rb_size(&g_rb) : 0;
}

uint64_t dns_log_overflow(void) {
    return g_rb_ready ? rb_overflow(&g_rb) : 0;
}

/* ========================================================================= *
 * SERIALIZAÇÃO JSON                                                          *
 * ========================================================================= */

/* Escapa para dentro de uma string JSON (aspas, barra e controles). Retorna o
 * tamanho ou -1 se não couber em `cap` (com o NUL). */
static int json_escape(const char *in, char *dst, size_t cap) {
    size_t w = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        char tmp[6];
        size_t n;
        if (*p == '"' || *p == '\\') {
            tmp[0] = '\\'; tmp[1] = (char)*p; n = 2;
        } else if (*p < 0x20 || *p == 0x7F) {
            tmp[0] = '\\'; tmp[1] = 'u'; tmp[2] = '0'; tmp[3] = '0';
            tmp[4] = HEX[*p >> 4]; tmp[5] = HEX[*p & 0xF]; n = 6;
        } else {
            tmp[0] = (char)*p; n = 1;
        }
        if (w + n + 1 > cap) return -1;
        memcpy(dst + w, tmp, n);
        w += n;
    }
    dst[w] = '\0';
    return (int)w;
}

int dns_log_render_json(const DnsEvent *ev, int n, char *out, size_t cap) {
    if (!ev || !out || n < 0 || cap < 3) return -1;

    char qr[DNS_LOG_QNAME_MAX], qn[2 * DNS_LOG_QNAME_MAX];
    char sip[46], dip[46], sip_e[2 * 46], dip_e[2 * 46];
    size_t w = 0;
    out[w++] = '[';

    for (int i = 0; i < n; i++) {
        fmt_ip(&ev[i], ev[i].src, sip);
        fmt_ip(&ev[i], ev[i].dst, dip);
        fmt_qname(&ev[i], qr);
        if (json_escape(qr, qn, sizeof(qn)) < 0) return -1;
        if (json_escape(sip, sip_e, sizeof(sip_e)) < 0) return -1;
        if (json_escape(dip, dip_e, sizeof(dip_e)) < 0) return -1;

        int k = snprintf(out + w, cap - w,
            "%s{\"event_type\":\"dns\",\"schema_version\":1,\"ts\":%lld,"
            "\"proto\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
            "\"qname\":\"%s\",\"qtype\":%u,\"rcode\":%u,\"resp\":%u,"
            "\"bytes\":%u,\"qname_hashed\":%u}",
            i ? "," : "", (long long)ev[i].ts_ms,
            ev[i].proto == DNS_PROTO_TCP ? "TCP" : "UDP", sip_e, dip_e, qn,
            (unsigned)ev[i].qtype, (unsigned)ev[i].rcode, (unsigned)ev[i].resp,
            (unsigned)ev[i].bytes, (unsigned)(g_dns_hash ? 1 : 0));
        if (k < 0 || (size_t)k >= cap - w) return -1;
        w += (size_t)k;
    }

    if (w + 2 > cap) return -1;
    out[w++] = ']';
    out[w] = '\0';
    return (int)w;
}
