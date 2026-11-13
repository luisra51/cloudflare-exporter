# Changelog

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
