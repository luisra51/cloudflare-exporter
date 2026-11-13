# cloudflare-exporter

Prometheus exporter for Cloudflare analytics that **works with zones on the Free plan**.

Popular Cloudflare exporters skip Free-plan zones or fail on them, because they
rely on datasets such as `httpRequests1mGroups` or `firewallEventsAdaptiveGroups`
that Free zones cannot query. This exporter treats Free as the first-class
case. It reads:

| Data | GraphQL dataset | Plans |
|---|---|---|
| HTTP traffic per zone | `httpRequests1hGroups` | all, including Free |
| Security (firewall) events per zone | `firewallEventsAdaptive` (raw events, counted by the exporter) | all, including Free |
| Security events, aggregated server-side | `firewallEventsAdaptiveGroups` | used automatically when the zone's plan allows it |
| HTTP traffic per account | `httpRequestsOverviewAdaptiveGroups` | all |

The exporter asks Cloudflare's GraphQL [`settings`](https://developers.cloudflare.com/analytics/graphql-api/features/discovery/settings/)
node which datasets each zone may query (and with what row and time-range
limits), so it never needs a "free tier" switch. The zone plan from the REST
`/zones` API is exported as a label of `cloudflare_zone_info`.

## How it works

- Collection runs **in the background** every `SCRAPE_INTERVAL` (default `5m`).
  `/metrics` only serves the cached result: a Prometheus scrape never triggers
  a Cloudflare API call, so you can scrape as often as you like.
- HTTP and security metrics describe the **last complete hour**. The exporter
  waits `CF_HOURLY_DELAY` (default `10m`) after an hour ends before reporting it,
  so Cloudflare has time to finish aggregating it. At 12:05 you see 10:00–11:00;
  from 12:10 you see 11:00–12:00. The hour is re-read on every cycle, so late
  data is picked up. Each family carries a `*_window_start_timestamp_seconds`
  gauge with the start of the hour it describes.
- Values are **gauges** ("requests in that hour"), not counters. To chart
  traffic, plot the gauge directly; to get a daily total use
  `sum_over_time(cloudflare_zone_hourly_requests[24h:1h])`.
- If a query fails, the previous values are kept and
  `cloudflare_exporter_up{dataset=...}` drops to `0`. Zones that disappear from
  discovery are removed.
- Free-plan security events are fetched raw (max 10,000 rows per query) and
  counted by the exporter. If an hour returns a full page, the window is split
  in halves and queried again, down to one minute, with a budget of 32 queries
  per zone and cycle. If that is not enough the count is a lower bound and
  `cloudflare_zone_hourly_firewall_events_truncated` is `1`.
- All requests go through a concurrency limit (`CF_CONCURRENCY`) and retry on
  HTTP 429/5xx. Cloudflare allows 300 GraphQL queries per 5 minutes per user;
  with defaults the exporter uses about 2–3 queries per zone per cycle, plus
  one per account.

## Quick start

```bash
docker run --rm -p 8080:8080 -e CF_API_TOKEN=... luisra51/cloudflare-exporter:latest
curl -s localhost:8080/metrics | grep cloudflare_
```

Images are published for `linux/amd64` and `linux/arm64`. They are static,
distroless and run as a non-root user.

Prometheus:

```yaml
scrape_configs:
  - job_name: cloudflare
    scrape_interval: 1m
    static_configs:
      - targets: ["cloudflare-exporter:8080"]
```

### Try it without a Cloudflare account

A fake Cloudflare API with synthetic data is included:

```bash
task run:fake
# or
go run ./hack/fake-cloudflare -listen 127.0.0.1:8787 &
CF_API_TOKEN=test-token CF_API_URL=http://127.0.0.1:8787 go run ./cmd/cloudflare-exporter
```

## API token permissions

Create a custom API token (My Profile → API Tokens, or an account-owned token)
with **read-only** permissions:

| Scope | Permission | Used for |
|---|---|---|
| Zone | Zone → Read | zone discovery (`/zones`) |
| Zone | Analytics → Read | `httpRequests1hGroups` |
| Zone | Firewall Services → Read | security events |
| Account | Account Analytics → Read | account metrics |
| Account | Account Settings → Read | account name |

Restrict the zone and account resources to what you want to monitor. Without
the account permissions, set `CF_ACCOUNT_METRICS=false`. The token is never
logged and never printed by `--help`.

## Configuration

Every setting can be given as an environment variable or as a flag; flags win.
Prefer the environment variable for the token, since flags are visible in the
process list.

| Env var | Flag | Default | Description |
|---|---|---|---|
| `CF_API_TOKEN` | `--api-token` | — (required) | Cloudflare API token |
| `CF_ZONES` | `--zones` | all zones the token sees | Comma-separated zone IDs to collect |
| `CF_EXCLUDE_ZONES` | `--exclude-zones` | — | Comma-separated zone IDs to skip |
| `CF_ACCOUNTS` | `--accounts` | accounts of the discovered zones | Comma-separated account IDs. Restricts zone discovery to these accounts and selects the accounts for account metrics |
| `LISTEN` | `--listen` | `:8080` | HTTP listen address |
| `METRICS_PATH` | `--metrics-path` | `/metrics` | Metrics endpoint path |
| `SCRAPE_INTERVAL` | `--scrape-interval` | `5m` | How often to query Cloudflare in the background |
| `CF_HOURLY_DELAY` | `--hourly-delay` | `10m` | Wait this long after an hour ends before reporting it |
| `CF_TOP_COUNTRIES` | `--top-countries` | `20` | Countries exported per zone; the rest are summed as `country="other"`. `0` disables country metrics |
| `CF_FIREWALL_EVENTS` | `--firewall-events` | `true` | Collect security events |
| `CF_ACCOUNT_METRICS` | `--account-metrics` | `true` | Collect account-level metrics |
| `CF_CONCURRENCY` | `--concurrency` | `4` | Maximum concurrent Cloudflare API requests |
| `CF_HTTP_TIMEOUT` | `--http-timeout` | `30s` | Timeout per API request |
| `CF_API_URL` | `--api-url` | `https://api.cloudflare.com/client/v4` | API base URL (for testing) |
| `LOG_LEVEL` | `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `--log-format` | `text` | `text` or `json` |
| — | `--version` | | Print version and exit |

## Endpoints

| Path | Description |
|---|---|
| `/metrics` | Prometheus metrics (configurable with `METRICS_PATH`) |
| `/healthz` | Liveness: always `200` with a JSON body `{"status":"ok","zone_discovery_succeeded":..., "last_collection":...}` |
| `/` | Small landing page |

## Metrics

Labels: `zone` is the zone name, `account` the account name. Label
cardinality is bounded: `status` (HTTP status codes), `http_version`,
`action` and `source` are small enumerations defined by Cloudflare, and
`country` is capped by `CF_TOP_COUNTRIES`.

### Zone HTTP traffic (last complete hour, `httpRequests1hGroups`)

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_zone_hourly_window_start_timestamp_seconds` | zone, account | Start of the hour the HTTP metrics describe |
| `cloudflare_zone_hourly_requests` | zone, account | Requests |
| `cloudflare_zone_hourly_cached_requests` | zone, account | Requests served from cache |
| `cloudflare_zone_hourly_encrypted_requests` | zone, account | HTTPS requests |
| `cloudflare_zone_hourly_bytes` | zone, account | Bytes sent to clients |
| `cloudflare_zone_hourly_cached_bytes` | zone, account | Bytes served from cache |
| `cloudflare_zone_hourly_encrypted_bytes` | zone, account | Bytes sent over HTTPS |
| `cloudflare_zone_hourly_page_views` | zone, account | Page views |
| `cloudflare_zone_hourly_threats` | zone, account | Requests classified as threats |
| `cloudflare_zone_hourly_unique_visitors` | zone, account | Unique visitor IPs |
| `cloudflare_zone_hourly_requests_by_status` | zone, account, status | Requests by edge response status |
| `cloudflare_zone_hourly_requests_by_http_version` | zone, account, http_version | Requests by client HTTP protocol |
| `cloudflare_zone_hourly_requests_by_country` | zone, account, country | Requests by client country (top N + `other`) |
| `cloudflare_zone_hourly_threats_by_country` | zone, account, country | Threats by client country |
| `cloudflare_zone_hourly_bytes_by_country` | zone, account, country | Bytes by client country |

### Zone security events (last complete hour)

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_zone_hourly_firewall_window_start_timestamp_seconds` | zone, account | Start of the hour the security metrics describe |
| `cloudflare_zone_hourly_firewall_events` | zone, account, action, source | Events by action (`block`, `managed_challenge`, `log`, ...) and source (`firewallCustom`, `waf`, `securitylevel`, ...) |
| `cloudflare_zone_hourly_firewall_events_truncated` | zone, account, dataset | `1` if the count hit the API row limit and is a lower bound; `dataset` says whether raw events or server-side groups were used |

### Account HTTP traffic (last complete hour, `httpRequestsOverviewAdaptiveGroups`)

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_account_hourly_window_start_timestamp_seconds` | account, account_id | Start of the hour |
| `cloudflare_account_hourly_requests` | account, account_id | Requests across all zones |
| `cloudflare_account_hourly_cached_requests` | account, account_id | Cached requests |
| `cloudflare_account_hourly_bytes` | account, account_id | Bytes |
| `cloudflare_account_hourly_cached_bytes` | account, account_id | Cached bytes |

### Metadata and exporter health

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_zone_info` | zone, zone_id, account, account_id, plan, status | Always `1`; `plan` is `free`, `pro`, `business`, `enterprise`, ... |
| `cloudflare_exporter_up` | scope, target, dataset | `1` if the last attempt for this dataset and target succeeded. `scope` is `zone`, `account` or `exporter` (zone discovery) |
| `cloudflare_exporter_last_success_timestamp_seconds` | scope, target, dataset | Time of the last success |
| `cloudflare_exporter_api_errors_total` | api, operation | Failed API calls (`api` = `rest` or `graphql`) |
| `cloudflare_exporter_collections_total` | result | Collection cycles: `success`, `partial`, `failure` |
| `cloudflare_exporter_collection_duration_seconds` | | Duration of the last cycle |
| `cloudflare_exporter_last_collection_timestamp_seconds` | | When the last cycle finished |
| `cloudflare_exporter_zones` | | Zones being collected |
| `cloudflare_exporter_build_info` | version, revision, goversion | Always `1` |

Standard `go_*` and `process_*` metrics are also exported.

### Example alerts

```yaml
- alert: CloudflareExporterStale
  expr: time() - cloudflare_exporter_last_success_timestamp_seconds > 3 * 3600
- alert: CloudflareHigh5xxRatio
  expr: |
    sum by (zone) (cloudflare_zone_hourly_requests_by_status{status=~"5.."})
      / sum by (zone) (cloudflare_zone_hourly_requests) > 0.05
```

## Development

The dev environment follows a [Task](https://taskfile.dev) layout:

```bash
task            # list tasks
task build      # ./bin/cloudflare-exporter
task test       # go test -race
task lint       # golangci-lint (local or Docker)
task check      # vet + lint + test
task run:fake   # run against the bundled fake API
task docker:build
task docker:buildx   # linux/amd64 + linux/arm64
task dev:up     # containerised Go toolchain (docker-compose-dev.yml)
```

Copy `cloudflare-exporter-dev.env.example` to `cloudflare-exporter-dev.env`
(git-ignored) for the dev container.

Tests use only synthetic fixtures served by `httptest` (`internal/cftest`).

## Releases

Pushing a tag `vX.Y.Z` builds and pushes `luisra51/cloudflare-exporter:X.Y.Z`
and `:latest` to Docker Hub for `linux/amd64` and `linux/arm64`. Every push to
`main` runs tests, lint and a multi-arch build without pushing.

## Credits

Inspired by [transferwise/cloudflare-prometheus-exporter](https://github.com/transferwise/cloudflare-prometheus-exporter)
(Apache License 2.0), which showed that `httpRequests1hGroups` works on the Free
plan. This project is an independent Go implementation and shares no code with it.

## License

[Apache License 2.0](LICENSE)
