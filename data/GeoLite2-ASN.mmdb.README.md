# GeoLite2-ASN.mmdb — instruções de download

O `nta-server` (v8.0 M1) usa o banco **GeoLite2 ASN** da MaxMind para
enriquecer eventos com **número de sistema autônomo** (`asn`) e
**organização** (`asn_org`) — lookup offline, ~1 µs por IP.

Tags resultantes no measurement `traffic`:

| Tag       | Exemplo            | Uso típico no Grafana                       |
|-----------|--------------------|---------------------------------------------|
| `asn`     | `AS15169`          | groupBy → quais ASs mais atacam             |
| `asn_org` | `GOOGLE`           | nome legível na legenda                     |

O arquivo `.mmdb` **não é distribuído junto ao repositório** — a licença
MaxMind exige cadastro. O servidor roda normalmente sem ele: emite um
`WARN` no startup e omite as tags `asn`/`asn_org`.

## Quando baixar

Só se quiser ver atribuição de ataques por AS (útil pra notar volume vindo
de provedores cloud específicos: AWS, OVH, Hetzner, etc).

## Passo a passo

1. **Criar conta grátis** em <https://www.maxmind.com/en/geolite2/signup>
   (mesma conta do banco City — pode pular se já tem)
2. **Download Databases** → **GeoLite2 ASN**
3. Formato **GeoIP2 Binary (.tar.gz)** — arquivo `GeoLite2-ASN_YYYYMMDD.tar.gz`
   (~10 MB, bem menor que o City)
4. Extrair e copiar o `.mmdb`:

   ```bash
   tar -xzf GeoLite2-ASN_*.tar.gz
   cp GeoLite2-ASN_*/GeoLite2-ASN.mmdb data/GeoLite2-ASN.mmdb
   ```

5. Confirmar carregamento:

   ```bash
   ./build/nta-server 2>&1 | grep GEOIP
   # Deve imprimir:
   # [GEOIP] city carregado: ./GeoLite2-City.mmdb (GeoLite2-City)
   # [GEOIP] asn  carregado: ./GeoLite2-ASN.mmdb  (GeoLite2-ASN)
   ```

## Override de path

```bash
export GEOIP_ASN_DB_PATH=/etc/nta/GeoLite2-ASN.mmdb
./build/nta-server
```

Default: `./GeoLite2-ASN.mmdb` (cwd).

## Atualização

Mesma cadência do banco City (terça/sexta). Em prod, usar `geoipupdate`
oficial pra ambos os bancos no mesmo cron.
