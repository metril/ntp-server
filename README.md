# ntp-server — chrony + Alloy on an Orange Pi

A public `pool.ntp.org` NTP server. `chrony` syncs over NTP unicast from a local time
grandmaster (with fallback sources so a bad grandmaster gets outvoted), serves clients on
UDP 123, and optionally serves NTS on TCP 4460. A Grafana Alloy sidecar scrapes chrony +
host metrics to VictoriaMetrics and tails container logs to VictoriaLogs.

```
                    ┌─────────────────────────────────────┐
NTP clients ──UDP 123──▶ chrony (network_mode: host) ──────┤ /var/lib/chrony (drift, NTS dump)
NTS clients ──TCP 4460──▶  │                               │
                 /run/chrony/chronyd.sock (unix, shared vol) │
                            │                                │
                    chrony-exporter ──127.0.0.1:9123──▶ Alloy ──remote_write──▶ VictoriaMetrics
                                                          │  └─loki push───────▶ VictoriaLogs
                                                docker.sock (container logs)
```

All three containers run `network_mode: host`. `chrony`'s control socket
(`bindcmdaddress /run/chrony/chronyd.sock`, `cmdport 0`) is a unix socket on a
named volume shared only with `chrony-exporter` (needed for `serverstats`/`clients`,
which chronyd refuses over the UDP control protocol); `chrony-exporter`/Alloy's
listeners are loopback-only — only UDP 123 (and TCP 4460 for NTS) are reachable
from outside the host.

## Host prep (Orange Pi)

Two time daemons fighting over the clock is the main failure mode — the host's own daemon
must be off and masked before the container starts:

```sh
sudo systemctl disable --now systemd-timesyncd.service
sudo systemctl mask systemd-timesyncd.service
sudo systemctl disable --now chronyd.service ntpd.service ntp.service 2>/dev/null
sudo systemctl mask chronyd.service ntpd.service ntp.service 2>/dev/null
```

Then run the checker, which verifies all of the above plus UDP 123 is free, the Docker
logging driver, and prints values you'll need for `.env`:

```sh
scripts/check-host.sh
```

It reports:
- `DOCKER_GID` — the `docker` group's gid, needed so Alloy's `group_add` can read
  `/var/run/docker.sock` as an unprivileged user.
- Docker's `LoggingDriver` must be `json-file` or `local` — Alloy's `discovery.docker` /
  `loki.source.docker` tail container stdout via the Docker API, which needs one of these.
- `/sys/class/hwmon/*/name` entries — the Orange Pi's temperature sensor label varies by
  board/kernel; pin the dashboard's Temperature panel query to whatever name is printed
  here after import.

It also creates `./data` and `./chrony-data` next to the compose file if missing, and
chowns `./data` to `1000:1000` (Alloy's container uid) when run as root.

## Firewall / port-forward

- Forward **UDP 123** to the Pi's static/reserved LAN IP. This is the only port pool
  clients need.
- If NTS is enabled, also forward **TCP 4460**.
- If your router does hairpin NAT, note that a LAN client querying the public IP/hostname
  may not reach the Pi unless hairpin NAT (NAT loopback) is supported — test from outside
  the LAN (or from a client that bypasses the router's NAT, e.g. a phone on cellular) to
  confirm the forward actually works end to end.

## Configure

Copy `.env.example` to `.env` and fill in:

| Var | Required | Notes |
|---|---|---|
| `GRANDMASTER_HOST` | yes | Local time grandmaster, synced via NTP unicast (`prefer`). |
| `ALLOY_INSTANCE` | yes | `host` label on metrics/logs; set to this host's name. |
| `VM_URL` | yes | VictoriaMetrics remote_write endpoint. |
| `VM_USER` / `VM_PASSWORD` | yes | Basic auth for `VM_URL`. |
| `VL_URL` | yes | VictoriaLogs Loki-push endpoint. |
| `VL_USER` / `VL_PASSWORD` | yes | Basic auth for `VL_URL`. |
| `DOCKER_GID` | yes | From `scripts/check-host.sh`; lets Alloy read `docker.sock`. |
| `POOL_SERVERS` | no | Extra space-separated fallback NTP servers (added on top of the built-in `time.cloudflare.com`, `time.nist.gov`, `pool 2.pool.ntp.org`). |
| `RATELIMIT_INTERVAL` / `RATELIMIT_BURST` | no | `ratelimit` line defaults (`3` / `8`). |
| `CLIENTLOGLIMIT` | no | Bytes of per-client log memory (default `4194304`); never set `noclientlog`, it disables `ratelimit` and the `clients` metrics. |
| `NTS_ENABLED` | no | `true` to enable NTS (see below); default `false`. |
| `NTS_CERT_DIR` | if NTS | Host directory containing an externally-renewed cert/key, mounted read-only at `/certs` (mount the directory, not the files, so renewal isn't orphaned by inode pinning — see `.env.example` for the Let's Encrypt symlink caveat). |
| `NTS_CERT_NAME` / `NTS_KEY_NAME` | no | Cert/key paths relative to `NTS_CERT_DIR` (default `fullchain.pem` / `privkey.pem`). |

## Deploy

```sh
docker compose build
docker compose up -d
```

With NTS enabled, layer the overlay that mounts the cert/key (also requires
`NTS_ENABLED=true` in `.env`):

```sh
docker compose -f compose.yaml -f compose.nts.yaml up -d
```

## Verify

On the Pi:

```sh
scripts/test-ntp.sh
```

This runs `docker compose exec chrony chronyc tracking|sources -v|sourcestats|serverstats`, checks
`chrony_tracking_stratum` on `curl 127.0.0.1:9123/metrics`, and hits Alloy's
`/-/ready`. Expect the grandmaster to show as the selected source (`^*`) at
stratum grandmaster+1.

From another host (the control port is loopback-only, so `chronyc -h <pi>` will fail —
that's expected):

```sh
ntpdate -q <pi-ip-or-hostname>
# or
sntp <pi-ip-or-hostname>
```

In VictoriaMetrics/VictoriaLogs:

```
chrony_tracking_stratum{host="<ALLOY_INSTANCE>"}
{job="ntp-server"}
```

## Grafana import

Import `dashboards/ntp-server.json` and `dashboards/ntp-server-logs.json`. Each has its
own datasource variable — bind `datasource` (Prometheus, ntp-server.json) and
`logs_datasource` (Loki-compatible, ntp-server-logs.json) to your VictoriaMetrics /
VictoriaLogs datasources on import, and set the `host` variable to `ALLOY_INSTANCE`.

## pool.ntp.org registration

1. The Pi needs a static LAN IP and a stable public IP (or DNS record) with UDP 123
   forwarded, as above.
2. Register at [manage.ntp.org](https://manage.ntp.org).
3. Start with a **low "net speed"** setting — pool.ntp.org ramps up traffic to new servers
   gradually as their score proves stable, so expect query volume to grow over days/weeks,
   not instantly.
4. The server needs a monitoring score of **+10** before the pool routes real client
   traffic to it; watch the score climb in manage.ntp.org and don't raise net speed until
   it's stable there.

## Rate limit & clientloglimit tuning

`ratelimit interval ${RATELIMIT_INTERVAL} burst ${RATELIMIT_BURST} leak 2` in
`chrony.conf.template` throttles abusive clients; `clientloglimit` bounds the memory used
to track per-client state for it. Watch:

```
chrony_serverstats_client_log_records_dropped_total
```

If this counter is climbing, the client log is full and `ratelimit` can no longer track
new clients accurately — raise `CLIENTLOGLIMIT` in `.env` and redeploy. Don't disable
tracking (`noclientlog`) to fix it — that kills both `ratelimit` and the `chrony_clients_*`
metrics.

## NTS notes

- Cert/key renewal is **external** — nothing in this stack issues or renews certificates.
  Point `NTS_CERT_DIR` at the directory your renewal process (e.g. certbot) writes into
  (not the individual files — see `.env.example`).
- chrony 4.5 cannot hot-reload `ntsservercert`/`ntsserverkey`. The entrypoint watches the
  mounted cert/key directories with `inotifywait` (watching directories, not the files
  themselves, since certbot's renewal replaces files in `archive/` and repoints the
  `live/` symlinks rather than editing them in place) and re-hashes the cert+key on any
  event; on a change it exits, and `restart: unless-stopped` brings the container back up
  with the new files. NTS-KE cookies survive the restart via `ntsdumpdir`. This requires
  `NTS_CERT_DIR` to be a local-filesystem bind mount — inotify events don't propagate over
  network filesystems (NFS, etc.).
- The cert's CN/SAN **must match the DNS name clients use** to connect over NTS (the name
  they put in `server ... nts`), not the Pi's internal hostname.
- The key is copied into the container at `/tmp/nts-server.key`, owned `root:chrony`, mode
  `0640`, on every start and every detected change — this is what lets the dropped-privilege
  `chrony` user read a key whose host-mounted original isn't group-readable by it.

## Troubleshooting

- **`chrony_up` is `0`**: `chrony-exporter` talks to chrony over
  `unix:///run/chrony/chronyd.sock`, a socket on the shared `chrony-run` volume. Check
  `bindcmdaddress`/`cmdport` in the rendered `/tmp/chrony.conf` inside the `chrony`
  container (should be the socket path / `0`), that both containers mount `chrony-run`,
  that `chrony-exporter`'s `user:` in compose.yaml matches the `chrony` uid:gid baked into
  the image, and that the `chrony` container's healthcheck (`chronyc tracking`) is passing.
- **No logs in VictoriaLogs**: confirm Docker's logging driver is `json-file` or `local`
  (`scripts/check-host.sh` checks this) — Alloy's `loki.source.docker` can't tail
  `journald` or other drivers.
- **Offset/stratum look wrong or clock is stepping unexpectedly**: check for a second time
  daemon still running on the host (`systemd-timesyncd`, `chronyd`, `ntpd`) — two steppers
  fighting is the most common cause; re-run `scripts/check-host.sh`.
- **Temperature panel is empty**: the Orange Pi's hwmon label varies by board/kernel; run
  `scripts/check-host.sh` (or `cat /sys/class/hwmon/*/name`) and edit the panel's query to
  match the printed name.
