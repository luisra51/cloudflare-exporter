# Changelog

## 1.2.0

### Added

- Per-host traffic from `httpRequestsAdaptiveGroups` (works on the Free
  plan) over a rolling window (`CF_ADAPTIVE_WINDOW`, default 5m, ending
  `CF_ADAPTIVE_DELAY`, default 3m, ago): `cloudflare_zone_host_requests`
  by status class, optional `cloudflare_zone_host_requests_by_status`
  (`CF_HOST_EXACT_STATUS`), and, when the zone's `settings` list them,
  `cloudflare_zone_host_bytes`, `cloudflare_zone_host_origin_5xx_requests`
  and `cloudflare_zone_host_origin_response_time_seconds`. Hosts are capped
  by `CF_TOP_HOSTS` (default 50). Flag: `CF_HOST_METRICS`.
- Edge certificate packs: `cloudflare_zone_certificate_packs`,
  `cloudflare_zone_certificate_pack_info`,
  `cloudflare_zone_certificate_pack_active` and
  `cloudflare_zone_certificate_pack_expiry_timestamp_seconds`. Flag:
  `CF_CERT_METRICS`.
- Zero Trust: Access service token expiry and last use, WARP device counts
  by last-seen bucket and OS (read every `CF_DEVICES_INTERVAL`, default 1h),
  Gateway DNS queries by resolver decision and Access logins by result.
  Flag: `CF_ZEROTRUST_METRICS`.
- A missing permission for any of these groups produces one warning naming
  it and `cloudflare_exporter_up{dataset=...} 0`; everything else keeps
  working.

## 1.1.0

### Added

- Cloudflare Tunnel health metrics for Cloudflare Tunnels (`cfd_tunnel`) and
  WARP Connectors (`warp_connector`): `cloudflare_tunnel_info`,
  `cloudflare_tunnel_status`, `cloudflare_tunnel_up`,
  `cloudflare_tunnel_connections`, `cloudflare_tunnel_connections_pending_reconnect`,
  `cloudflare_tunnel_connections_by_colo`, `cloudflare_tunnel_connectors`,
  `cloudflare_tunnel_connector_info`,
  `cloudflare_tunnel_active_since_timestamp_seconds` and
  `cloudflare_tunnel_inactive_since_timestamp_seconds`.
- `CF_TUNNEL_METRICS` / `--tunnel-metrics` (default `true`).
- `cloudflare_exporter_up` datasets `tunnels` and `tunnel_connectors`.

### Changed

- A missing Cloudflare Tunnel permission is reported with a single warning
  and `cloudflare_exporter_up{dataset="tunnels"} 0`; all other metrics keep
  working.
- Duplicate series (for example two tunnels with the same name) are dropped
  instead of failing the scrape.
- REST error responses keep Cloudflare's error codes.

## 0.1.0

- First release: zone HTTP traffic (`httpRequests1hGroups`), security events
  (`firewallEventsAdaptive`, or `firewallEventsAdaptiveGroups` when the plan
  allows it) and account traffic (`httpRequestsOverviewAdaptiveGroups`), with
  Free-plan zones supported.
