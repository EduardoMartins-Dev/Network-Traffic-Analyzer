# GeoLite2-City.mmdb — instruções de download

O `nta-server` usa o banco **GeoLite2 City** da MaxMind para enriquecer eventos
com `lat`/`lon` de forma **offline** (~1 µs por lookup, sem rate limit de rede).

O arquivo `.mmdb` **não é distribuído junto ao repositório** — a licença exige
cadastro e aceitação de termos. O servidor roda normalmente sem ele: apenas
emite um `WARN` no startup e omite os campos `lat`/`lon` dos eventos.

## Quando baixar

Só se você quiser ver o mapa de origem dos ataques no Grafana. Todo o resto da
pipeline (detecção, kill chain, narrativa IA, métricas) funciona sem GeoIP.

## Passo a passo

1. **Criar conta grátis** em <https://www.maxmind.com/en/geolite2/signup>
2. Após login, ir em **Download Databases** → **GeoLite2 City**
3. Baixar o formato **GeoIP2 Binary (.tar.gz)** — arquivo tipo
   `GeoLite2-City_YYYYMMDD.tar.gz` (~70 MB)
4. Extrair e copiar o `.mmdb` para este diretório:

   ```bash
   tar -xzf GeoLite2-City_*.tar.gz
   cp GeoLite2-City_*/GeoLite2-City.mmdb data/GeoLite2-City.mmdb
   ```

5. Confirmar que `nta-server` encontrou o banco:

   ```bash
   ./build/nta-server 2>&1 | head
   # Deve imprimir: "▶ GeoIP: banco carregado de ./GeoLite2-City.mmdb"
   ```

## Atualização

A MaxMind atualiza o GeoLite2 toda terça e sexta. Para manter atualizado, dá
pra automatizar com a ferramenta oficial `geoipupdate`
(<https://github.com/maxmind/geoipupdate>), mas isso é opcional — em dev
qualquer snapshot funciona.

## Por que não MaxMind License Key / geoipupdate aqui

O fluxo simples (download manual) basta para uso local. Quando a v10.0 entrar
em produção na VPS, aí sim vale adicionar `geoipupdate` como container no
`docker-compose` pra atualização automática.
