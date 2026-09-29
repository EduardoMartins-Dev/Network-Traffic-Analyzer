#ifndef NTA_SERVICE_H
#define NTA_SERVICE_H

/* ========================================================================= *
 * Windows Service do agente (src/agent/platform/service_win32.c). Só existe no    *
 * Windows — no Linux o agente roda via systemd (deploy/agent.service).      *
 *                                                                           *
 * Serviço "NTAAgent": SERVICE_AUTO_START, conta LocalSystem, reinício       *
 * automático em falha. O stop do SCM dispara pipeline_request_stop() — o    *
 * mesmo shutdown gracioso do Ctrl+C (drena buffers, fecha AMQP).            *
 * ========================================================================= */

#ifdef _WIN32

#define NTA_SERVICE_NAME    "NTAAgent"
#define NTA_SERVICE_DISPLAY "Network Traffic Analyzer Agent"
#define NTA_DEFAULT_LOG     "C:\\ProgramData\\NTA\\agent.log"

/* Chamado pelo SCM (ImagePath contém --service). Bloqueia até o stop.
 * stdout/stderr vão para AGENT_LOG_FILE (default NTA_DEFAULT_LOG).
 * Retorna 0 em sucesso; != 0 se não foi iniciado pelo SCM. */
int service_run(const char *iface);

/* Registra o serviço apontando para este executável com
 * `--service --config <config_path> [iface]`. config_path é convertido para
 * absoluto (o SCM inicia o processo em System32). Exige Administrador. */
int service_install(const char *config_path, const char *iface);

/* Para (se estiver rodando) e remove o serviço. Exige Administrador. */
int service_uninstall(void);

#endif /* _WIN32 */
#endif /* NTA_SERVICE_H */
