```
 ██████╗███████╗    ███████╗██╗  ██╗██████╗  ██████╗ ██████╗ ████████╗███████╗██████╗
██╔════╝██╔════╝    ██╔════╝╚██╗██╔╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔══██╗
██║     █████╗      █████╗   ╚███╔╝ ██████╔╝██║   ██║██████╔╝   ██║   █████╗  ██████╔╝
██║     ██╔══╝      ██╔══╝   ██╔██╗ ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══╝  ██╔══██╗
╚██████╗██║         ███████╗██╔╝ ██╗██║     ╚██████╔╝██║  ██║   ██║   ███████╗██║  ██║
 ╚═════╝╚═╝         ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

# cloudflare-exporter

**A Prometheus exporter for Cloudflare analytics that works with zones on the Free plan.**

[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8?style=for-the-badge&logo=go)](https://go.dev/)
[![Docker Pulls](https://img.shields.io/docker/pulls/luisra51/cloudflare-exporter?style=for-the-badge&logo=docker)](https://hub.docker.com/r/luisra51/cloudflare-exporter)
[![CI](https://img.shields.io/github/actions/workflow/status/luisra51/cloudflare-exporter/ci.yml?branch=main&style=for-the-badge&logo=githubactions&label=ci)](https://github.com/luisra51/cloudflare-exporter/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge)](LICENSE)
[![Multi-arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-555555?style=for-the-badge&logo=linux)](https://hub.docker.com/r/luisra51/cloudflare-exporter/tags)

> 📈 **Traffic, status codes and security events for every zone your token can see, Free plan included.**

## 🤔 Why another Cloudflare exporter?

Popular Cloudflare exporters, such as
[lablabs/cloudflare-exporter](https://github.com/lablabs/cloudflare-exporter)
and Cloudflare's own exporter, skip zones on the Free plan. They rely on
GraphQL datasets (for example `httpRequests1mGroups` or
`firewallEventsAdaptiveGroups`) that Free zones cannot query. Both are good
tools for paid plans. This exporter covers the case they leave out: it reads
the datasets that Free zones *can* query, and switches to the richer ones when
a zone's plan allows it.

| On a **Free-plan** zone | cloudflare-exporter | Exporters that skip Free zones |
|---|:---:|:---:|
| HTTP traffic (requests, bytes, cache, page views, visitors) | ✅ | ❌ zone skipped |
| Requests by HTTP status code | ✅ | ❌ zone skipped |
| Security (firewall) events by action and source | ✅ | ❌ zone skipped |
| Multi-arch image (amd64 + arm64) | ✅ | varies |
| Background collection (scrapes never call the API) | ✅ | varies |

## ✨ Features

- **🆓 Free plan first**: HTTP traffic from `httpRequests1hGroups` and security events from `firewallEventsAdaptive`, both readable by Free zones
- **🔍 Plan-aware**: reads Cloudflare's GraphQL `settings` node per zone and uses `firewallEventsAdaptiveGroups` automatically when the plan allows it
- **🌐 Auto-discovery**: collects every zone the token can see, or an allowlist (`CF_ZONES`), minus exclusions (`CF_EXCLUDE_ZONES`)
- **🏢 Account metrics**: account-wide traffic from `httpRequestsOverviewAdaptiveGroups`
- **⚡ Background collection**: Cloudflare is queried every `SCRAPE_INTERVAL`; `/metrics` serves the cache, so scrapes are instant and never spend API quota
- **🧮 Bounded cardinality**: countries capped to a top N plus `other`; status, HTTP version, action and source are small enumerations
- **✂️ Exact counts on busy zones**: raw security events are split into smaller windows when a page fills up, with a query budget and a `truncated` flag when that is not enough
- **🩺 Self-monitoring**: per-dataset `up` and last-success timestamps, API error counters, collection duration
- **🔐 Safe by default**: read-only token, never logged and never printed by `--help`
- **🐳 Small image**: static, distroless, non-root, linux/amd64 and linux/arm64
- **🛑 Graceful shutdown** and a `/healthz` endpoint

## ☕ Support

If you like this project, consider [buying me a coffee](https://buymeacoffee.com/luisra51) ☕💛
<a href="https://www.buymeacoffee.com/luisra51" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" width="200"/>
</a>

## 🚀 Quick start

### Docker

```bash
docker run -d --name cloudflare-exporter \
  -p 8080:8080 \
  -e CF_API_TOKEN=your-read-only-token \
  luisra51/cloudflare-exporter:latest

curl -s http://localhost:8080/metrics | grep '^cloudflare_'
```

### Docker Compose

```yaml
services:
  cloudflare-exporter:
    image: luisra51/cloudflare-exporter:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      CF_API_TOKEN: ${CF_API_TOKEN}
      # CF_ZONES: "<zone-id-1>,<zone-id-2>"   # optional allowlist
      SCRAPE_INTERVAL: 5m
      LOG_FORMAT: json
```

### Go

```bash
go install github.com/luisra51/cloudflare-exporter/cmd/cloudflare-exporter@latest
CF_API_TOKEN=your-read-only-token cloudflare-exporter
```

Or from source:

```bash
git clone https://github.com/luisra51/cloudflare-exporter.git
cd cloudflare-exporter
task build && CF_API_TOKEN=your-read-only-token ./bin/cloudflare-exporter
```

### Try it without a Cloudflare account

A fake Cloudflare API with synthetic data is bundled:

```bash
task run:fake
# then open http://localhost:8080/metrics
```

## 🔑 API token

The exporter only needs **read** access.

1. In the Cloudflare dashboard go to **My Profile → API Tokens → Create Token**.
2. Choose **Create Custom Token**.
3. Add these permissions, all set to **Read**:

   | Scope | Permission | Used for |
   |---|---|---|
   | Zone | **Zone** | zone discovery and plan (`/zones`) |
   | Zone | **Analytics** | HTTP traffic (`httpRequests1hGroups`) |
   | Zone | **Firewall Services** | security events |
   | Account | **Account Analytics** | account-wide traffic |
   | Account | **Account Settings** | account name |

4. Under **Zone Resources** and **Account Resources**, include only what you want to monitor.
5. Create the token and pass it as `CF_API_TOKEN`.

Without the account permissions, set `CF_ACCOUNT_METRICS=false`.

## ⚙️ Configuration

Every setting is an environment variable and a flag; flags win. Prefer the
environment variable for the token, since flags are visible in the process list.

| Env var | Flag | Default | Description |
|---|---|---|---|
| `CF_API_TOKEN` | `--api-token` | — (required) | Cloudflare API token |
| `CF_ZONES` | `--zones` | all zones the token sees | Comma-separated zone IDs to collect |
| `CF_EXCLUDE_ZONES` | `--exclude-zones` | — | Comma-separated zone IDs to skip |
| `CF_ACCOUNTS` | `--accounts` | accounts of the discovered zones | Comma-separated account IDs; restricts zone discovery and selects accounts for account metrics |
| `LISTEN` | `--listen` | `:8080` | HTTP listen address |
| `METRICS_PATH` | `--metrics-path` | `/metrics` | Metrics endpoint path |
| `SCRAPE_INTERVAL` | `--scrape-interval` | `5m` | How often to query Cloudflare in the background |
| `CF_HOURLY_DELAY` | `--hourly-delay` | `10m` | Wait this long after an hour ends before reporting it |
| `CF_TOP_COUNTRIES` | `--top-countries` | `20` | Countries per zone; the rest are summed as `country="other"`; `0` disables country metrics |
| `CF_FIREWALL_EVENTS` | `--firewall-events` | `true` | Collect security events |
| `CF_ACCOUNT_METRICS` | `--account-metrics` | `true` | Collect account-level metrics |
| `CF_CONCURRENCY` | `--concurrency` | `4` | Maximum concurrent Cloudflare API requests |
| `CF_HTTP_TIMEOUT` | `--http-timeout` | `30s` | Timeout per API request |
| `CF_API_URL` | `--api-url` | `https://api.cloudflare.com/client/v4` | API base URL (for testing) |
| `LOG_LEVEL` | `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `--log-format` | `text` | `text` or `json` |
| — | `--version` | | Print version and exit |

### Endpoints

| Path | Description |
|---|---|
| `/metrics` | Prometheus metrics (configurable with `METRICS_PATH`) |
| `/healthz` | Liveness: always `200` with `{"status":"ok","zone_discovery_succeeded":...,"last_collection":...}` |
| `/` | Small landing page |

## ⏱️ How hourly data works

- Metrics describe the **last complete hour**, as gauges ("requests in that hour"), not counters.
- The exporter waits `CF_HOURLY_DELAY` (default `10m`) after an hour ends so
  Cloudflare can finish aggregating it. At 12:05 you see 10:00–11:00; from
  12:10 you see 11:00–12:00.
- The hour is re-read every `SCRAPE_INTERVAL`, so late data is picked up.
- Each group of metrics has a `*_window_start_timestamp_seconds` gauge with
  the start of the hour it describes.
- If a query fails, the last good values are kept and
  `cloudflare_exporter_up{dataset="..."}` drops to `0`. Zones that disappear
  from discovery are removed.
- Free zones get security events as raw rows (up to 10,000 per query) that the
  exporter counts. A full page makes it split the window in halves, down to one
  minute, with a budget of 32 queries per zone and cycle. If that is still not
  enough, `cloudflare_zone_hourly_firewall_events_truncated` is `1` and the
  count is a lower bound.
- Requests go through a concurrency limit and are retried on HTTP 429/5xx.
  Cloudflare allows 300 GraphQL queries per 5 minutes per user; with defaults
  the exporter uses about 2–3 queries per zone per cycle, plus one per account.

## 📊 Metrics

`zone` is the zone name and `account` the account name.

### Zone HTTP traffic (last complete hour)

All with labels `zone` and `account`.

| Metric | Extra labels | Description |
|---|---|---|
| `cloudflare_zone_hourly_window_start_timestamp_seconds` | | Start of the hour the HTTP metrics describe |
| `cloudflare_zone_hourly_requests` | | Requests |
| `cloudflare_zone_hourly_cached_requests` | | Requests served from cache |
| `cloudflare_zone_hourly_encrypted_requests` | | HTTPS requests |
| `cloudflare_zone_hourly_bytes` | | Bytes sent to clients |
| `cloudflare_zone_hourly_cached_bytes` | | Bytes served from cache |
| `cloudflare_zone_hourly_encrypted_bytes` | | Bytes sent over HTTPS |
| `cloudflare_zone_hourly_page_views` | | Page views |
| `cloudflare_zone_hourly_threats` | | Requests classified as threats |
| `cloudflare_zone_hourly_unique_visitors` | | Unique visitor IPs |
| `cloudflare_zone_hourly_requests_by_status` | `status` | Requests by edge response status |
| `cloudflare_zone_hourly_requests_by_http_version` | `http_version` | Requests by client HTTP protocol |
| `cloudflare_zone_hourly_requests_by_country` | `country` | Requests by client country (top N + `other`) |
| `cloudflare_zone_hourly_threats_by_country` | `country` | Threats by client country |
| `cloudflare_zone_hourly_bytes_by_country` | `country` | Bytes by client country |

### Zone security events (last complete hour)

All with labels `zone` and `account`.

| Metric | Extra labels | Description |
|---|---|---|
| `cloudflare_zone_hourly_firewall_window_start_timestamp_seconds` | | Start of the hour the security metrics describe |
| `cloudflare_zone_hourly_firewall_events` | `action`, `source` | Events by action (`block`, `managed_challenge`, `log`, ...) and source (`firewallCustom`, `waf`, `securitylevel`, ...) |
| `cloudflare_zone_hourly_firewall_events_truncated` | `dataset` | `1` if the count hit the API row limit and is a lower bound |

### Account HTTP traffic (last complete hour)

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_account_hourly_window_start_timestamp_seconds` | `account`, `account_id` | Start of the hour |
| `cloudflare_account_hourly_requests` | `account`, `account_id` | Requests across all zones |
| `cloudflare_account_hourly_cached_requests` | `account`, `account_id` | Cached requests |
| `cloudflare_account_hourly_bytes` | `account`, `account_id` | Bytes |
| `cloudflare_account_hourly_cached_bytes` | `account`, `account_id` | Cached bytes |

### Metadata and exporter health

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_zone_info` | `zone`, `zone_id`, `account`, `account_id`, `plan`, `status` | Always `1`; `plan` is `free`, `pro`, `business`, `enterprise`, ... |
| `cloudflare_exporter_up` | `scope`, `target`, `dataset` | `1` if the last attempt succeeded; `scope` is `zone`, `account` or `exporter` |
| `cloudflare_exporter_last_success_timestamp_seconds` | `scope`, `target`, `dataset` | Time of the last success |
| `cloudflare_exporter_api_errors_total` | `api`, `operation` | Failed API calls (`api` = `rest` or `graphql`) |
| `cloudflare_exporter_collections_total` | `result` | Collection cycles: `success`, `partial`, `failure` |
| `cloudflare_exporter_collection_duration_seconds` | | Duration of the last cycle |
| `cloudflare_exporter_last_collection_timestamp_seconds` | | When the last cycle finished |
| `cloudflare_exporter_zones` | | Zones being collected |
| `cloudflare_exporter_build_info` | `version`, `revision`, `goversion` | Always `1` |

Standard `go_*` and `process_*` metrics are exported too.

Sample output:

```
cloudflare_zone_info{account="Example Account",account_id="...",plan="free",status="active",zone="example.com",zone_id="..."} 1
cloudflare_zone_hourly_requests{account="Example Account",zone="example.com"} 1000
cloudflare_zone_hourly_requests_by_status{account="Example Account",status="404",zone="example.com"} 80
cloudflare_zone_hourly_firewall_events{account="Example Account",action="block",source="firewallCustom",zone="example.com"} 40
```

## 🔎 Example queries

```promql
# Share of 5xx responses per zone (last complete hour)
sum by (zone) (cloudflare_zone_hourly_requests_by_status{status=~"5.."})
  / sum by (zone) (cloudflare_zone_hourly_requests)

# Cache hit ratio per zone
cloudflare_zone_hourly_cached_requests / cloudflare_zone_hourly_requests

# Blocked requests by source
sum by (zone, source) (cloudflare_zone_hourly_firewall_events{action="block"})

# Top 5 countries by requests for one zone
topk(5, cloudflare_zone_hourly_requests_by_country{zone="example.com", country!="other"})

# Requests over the last 24 hours (one sample per hour)
sum_over_time(cloudflare_zone_hourly_requests{zone="example.com"}[24h:1h])
```

Example alerts:

```yaml
groups:
  - name: cloudflare
    rules:
      - alert: CloudflareExporterStale
        expr: time() - cloudflare_exporter_last_success_timestamp_seconds > 3 * 3600
      - alert: CloudflareHigh5xxRatio
        expr: |
          sum by (zone) (cloudflare_zone_hourly_requests_by_status{status=~"5.."})
            / sum by (zone) (cloudflare_zone_hourly_requests) > 0.05
```

## 📡 Scraping

Any scrape interval works, since `/metrics` is served from cache.

### Prometheus

```yaml
scrape_configs:
  - job_name: cloudflare
    scrape_interval: 1m
    static_configs:
      - targets: ["cloudflare-exporter:8080"]
```

### Grafana Alloy

```alloy
prometheus.scrape "cloudflare" {
  targets         = [{"__address__" = "cloudflare-exporter:8080"}]
  scrape_interval = "1m"
  forward_to      = [prometheus.remote_write.default.receiver]
}

prometheus.remote_write "default" {
  endpoint {
    url = "http://prometheus.example.com:9090/api/v1/write"
  }
}
```

## 🛠️ Contributing

Issues and pull requests are welcome. The dev environment uses [Task](https://taskfile.dev):

```bash
task                # list tasks
task build          # ./bin/cloudflare-exporter
task test           # go test -race
task lint           # golangci-lint (local binary or Docker image)
task check          # vet + lint + test
task run:fake       # run against the bundled fake Cloudflare API
task docker:build   # image for the local architecture
task docker:buildx  # linux/amd64 + linux/arm64
task dev:up         # containerised Go toolchain (docker-compose-dev.yml)
```

Tests use only synthetic fixtures served by `httptest` (`internal/cftest`).
For the dev container, copy `cloudflare-exporter-dev.env.example` to
`cloudflare-exporter-dev.env` (git-ignored).

Releases: pushing a tag `vX.Y.Z` builds and pushes
`luisra51/cloudflare-exporter:X.Y.Z` and `:latest` to Docker Hub for
linux/amd64 and linux/arm64. Every push to `main` runs vet, tests, lint and a
multi-arch build.

## 🙏 Credits

Inspired by [transferwise/cloudflare-prometheus-exporter](https://github.com/transferwise/cloudflare-prometheus-exporter)
(Apache License 2.0), which showed that `httpRequests1hGroups` works on the Free
plan. This project is an independent Go implementation and shares no code with it.

## 📄 License

[Apache License 2.0](LICENSE)
