# IoC do nta-server (`deploy/ioc/`)

`blocklist.json` é a lista de IPs maliciosos que o nta-server usa para marcar
eventos com `ioc_hit=1` e `ioc_source=<lista>`. O schema está em
`include/server/nta_ioc.h`; o modelo versionado é `blocklist.json.example`.

- `blocklist.json` é **gerado** e está no `.gitignore`. Não versione listas baixadas.
- O compose monta este **diretório** em `/app/deploy/ioc` (somente leitura).
  Por isso o script troca o arquivo por rename dentro do diretório, sem reiniciar o container.

## Atualizar

```sh
scripts/ioc_update.sh            # baixa, valida, troca e envia SIGHUP ao container nta-server
scripts/ioc_update.sh --no-reload  # só atualiza o arquivo
```

O script baixa o feed Feodo Tracker (abuse.ch, `ipblocklist.json`), valida cada
IP (IPv4), gera o JSON no schema atual e troca o arquivo atomicamente. Se o
download falhar, o feed estiver truncado, tiver IP inválido ou vier sem IPs, o
script sai com erro e **o `blocklist.json` atual permanece como está**.

Variáveis opcionais: `NTA_IOC_FEODO_URL`, `NTA_IOC_OUT`, `NTA_IOC_CONTAINER`
(default `nta-server`). Nenhuma chave de API é usada.

## Recarga (SIGHUP)

```sh
docker kill -s HUP nta-server
docker logs nta-server 2>&1 | grep '\[IOC\]'
```

- Sucesso: `[IOC] lista recarregada: N IPs`.
- Rejeitada: `[IOC] reload rejeitado (...) — lista anterior continua ativa`.
- A troca não toca em AMQP nem em InfluxDB; os workers leem a tabela ativa a
  cada mensagem, sem mutex. A tabela antiga é liberada quando os leitores que a
  usavam terminam.
- Se o IoC estava desabilitado na carga inicial (arquivo ausente ou inválido),
  um reload válido o habilita.

## Agendamento

Cron (uma vez por hora, a partir da raiz do repositório):

```cron
17 * * * * cd /opt/nta && scripts/ioc_update.sh >> /var/log/nta-ioc.log 2>&1
```

Ou systemd timer:

```ini
# /etc/systemd/system/nta-ioc-update.service
[Unit]
Description=Atualiza a blocklist IoC do nta-server

[Service]
Type=oneshot
WorkingDirectory=/opt/nta
ExecStart=/opt/nta/scripts/ioc_update.sh

# /etc/systemd/system/nta-ioc-update.timer
[Unit]
Description=Atualização horária da blocklist IoC

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
```

O usuário que roda o script precisa de acesso ao socket do Docker (ou Podman) para o SIGHUP.

## Feeds e limites de uso

| Feed | URL | Estado verificado (2026-11-19) |
|---|---|---|
| Feodo Tracker (abuse.ch) | `https://feodotracker.abuse.ch/downloads/ipblocklist.json` | HTTP 200, sem chave. Cache-Control observado: `max-age=300`. |
| URLhaus (abuse.ch) | `https://urlhaus.abuse.ch/downloads/text_online/` | **HTTP 410 Gone**. Não incluído: a API atual exige chave, que este projeto não gerencia. |

- Baixe no máximo uma vez por hora; o cache do próprio feed é de 5 minutos.
- Antes de uso comercial, confira os termos de uso atuais do abuse.ch (não foram verificados aqui).
- O feed baixado vai para um diretório temporário e é apagado ao fim do script.
