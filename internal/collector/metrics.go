package collector

import (
	"sort"
	"strings"

	"github.com/luisra51/cloudflare-exporter/internal/cloudflare"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	zoneLabels = []string{"zone", "account"}

	descZoneInfo = prometheus.NewDesc("cloudflare_zone_info",
		"Zone metadata. Always 1.", []string{"zone", "zone_id", "account", "account_id", "plan", "status"}, nil)

	descWindow = prometheus.NewDesc("cloudflare_zone_hourly_window_start_timestamp_seconds",
		"Start (Unix time) of the hour the cloudflare_zone_hourly_* HTTP metrics describe.", zoneLabels, nil)
	descRequests = prometheus.NewDesc("cloudflare_zone_hourly_requests",
		"HTTP requests served by the edge during the last complete hour.", zoneLabels, nil)
	descCachedRequests = prometheus.NewDesc("cloudflare_zone_hourly_cached_requests",
		"HTTP requests served from cache during the last complete hour.", zoneLabels, nil)
	descEncryptedRequests = prometheus.NewDesc("cloudflare_zone_hourly_encrypted_requests",
		"HTTPS requests during the last complete hour.", zoneLabels, nil)
	descBytes = prometheus.NewDesc("cloudflare_zone_hourly_bytes",
		"Bytes sent by the edge to clients during the last complete hour.", zoneLabels, nil)
	descCachedBytes = prometheus.NewDesc("cloudflare_zone_hourly_cached_bytes",
		"Bytes served from cache during the last complete hour.", zoneLabels, nil)
	descEncryptedBytes = prometheus.NewDesc("cloudflare_zone_hourly_encrypted_bytes",
		"Bytes sent over HTTPS during the last complete hour.", zoneLabels, nil)
	descPageViews = prometheus.NewDesc("cloudflare_zone_hourly_page_views",
		"Page views during the last complete hour.", zoneLabels, nil)
	descThreats = prometheus.NewDesc("cloudflare_zone_hourly_threats",
		"Requests classified as threats during the last complete hour.", zoneLabels, nil)
	descUniques = prometheus.NewDesc("cloudflare_zone_hourly_unique_visitors",
		"Unique visitor IPs during the last complete hour.", zoneLabels, nil)
	descByStatus = prometheus.NewDesc("cloudflare_zone_hourly_requests_by_status",
		"HTTP requests by edge response status code during the last complete hour.", append(zoneLabels, "status"), nil)
	descByHTTPVersion = prometheus.NewDesc("cloudflare_zone_hourly_requests_by_http_version",
		"HTTP requests by client HTTP protocol during the last complete hour.", append(zoneLabels, "http_version"), nil)
	descCountryRequests = prometheus.NewDesc("cloudflare_zone_hourly_requests_by_country",
		"HTTP requests by client country during the last complete hour (top N countries, the rest as country=\"other\").", append(zoneLabels, "country"), nil)
	descCountryThreats = prometheus.NewDesc("cloudflare_zone_hourly_threats_by_country",
		"Threats by client country during the last complete hour (same countries as requests_by_country).", append(zoneLabels, "country"), nil)
	descCountryBytes = prometheus.NewDesc("cloudflare_zone_hourly_bytes_by_country",
		"Bytes by client country during the last complete hour (same countries as requests_by_country).", append(zoneLabels, "country"), nil)

	descFWWindow = prometheus.NewDesc("cloudflare_zone_hourly_firewall_window_start_timestamp_seconds",
		"Start (Unix time) of the hour the firewall event metrics describe.", zoneLabels, nil)
	descFWEvents = prometheus.NewDesc("cloudflare_zone_hourly_firewall_events",
		"Firewall (security) events by action and source during the last complete hour.", append(zoneLabels, "action", "source"), nil)
	descFWTruncated = prometheus.NewDesc("cloudflare_zone_hourly_firewall_events_truncated",
		"1 if the firewall event count hit the API row limit and is a lower bound.", append(zoneLabels, "dataset"), nil)

	descAccWindow = prometheus.NewDesc("cloudflare_account_hourly_window_start_timestamp_seconds",
		"Start (Unix time) of the hour the cloudflare_account_hourly_* metrics describe.", []string{"account", "account_id"}, nil)
	descAccRequests = prometheus.NewDesc("cloudflare_account_hourly_requests",
		"HTTP requests across all zones of the account during the last complete hour.", []string{"account", "account_id"}, nil)
	descAccCachedRequests = prometheus.NewDesc("cloudflare_account_hourly_cached_requests",
		"Cached HTTP requests across all zones of the account during the last complete hour.", []string{"account", "account_id"}, nil)
	descAccBytes = prometheus.NewDesc("cloudflare_account_hourly_bytes",
		"Bytes across all zones of the account during the last complete hour.", []string{"account", "account_id"}, nil)
	descAccCachedBytes = prometheus.NewDesc("cloudflare_account_hourly_cached_bytes",
		"Cached bytes across all zones of the account during the last complete hour.", []string{"account", "account_id"}, nil)

	tunnelLabels = []string{"account", "tunnel"}

	descTunnelInfo = prometheus.NewDesc("cloudflare_tunnel_info",
		"Tunnel metadata. Always 1.", []string{"account", "account_id", "tunnel", "tunnel_id", "type", "config_src"}, nil)
	descTunnelStatus = prometheus.NewDesc("cloudflare_tunnel_status",
		"Tunnel status as a state set: 1 for the current status, 0 for the others.", append(tunnelLabels, "status"), nil)
	descTunnelUp = prometheus.NewDesc("cloudflare_tunnel_up",
		"1 if the tunnel status is healthy or degraded, 0 otherwise.", tunnelLabels, nil)
	descTunnelConns = prometheus.NewDesc("cloudflare_tunnel_connections",
		"Edge connections of the tunnel.", tunnelLabels, nil)
	descTunnelPending = prometheus.NewDesc("cloudflare_tunnel_connections_pending_reconnect",
		"Edge connections flagged as pending reconnect (Cloudflare has deprecated this flag and may always report 0).", tunnelLabels, nil)
	descTunnelByColo = prometheus.NewDesc("cloudflare_tunnel_connections_by_colo",
		"Edge connections of the tunnel by Cloudflare data center.", append(tunnelLabels, "colo"), nil)
	descTunnelConnectors = prometheus.NewDesc("cloudflare_tunnel_connectors",
		"Distinct connectors (cloudflared or WARP Connector instances) reported for the tunnel.", tunnelLabels, nil)
	descConnectorInfo = prometheus.NewDesc("cloudflare_tunnel_connector_info",
		"Connector metadata. Always 1.", append(tunnelLabels, "connector_id", "version", "arch"), nil)
	descTunnelActive = prometheus.NewDesc("cloudflare_tunnel_active_since_timestamp_seconds",
		"Unix time the tunnel last became active (conns_active_at).", tunnelLabels, nil)
	descTunnelInactive = prometheus.NewDesc("cloudflare_tunnel_inactive_since_timestamp_seconds",
		"Unix time the tunnel last became inactive (conns_inactive_at). Absent when Cloudflare reports none.", tunnelLabels, nil)

	tunnelStatuses = []string{"healthy", "degraded", "down", "inactive"}

	descUp = prometheus.NewDesc("cloudflare_exporter_up",
		"1 if the last attempt to collect this dataset for this target succeeded.", []string{"scope", "target", "dataset"}, nil)
	descLastSuccess = prometheus.NewDesc("cloudflare_exporter_last_success_timestamp_seconds",
		"Unix time of the last successful collection of this dataset for this target.", []string{"scope", "target", "dataset"}, nil)
	descZones = prometheus.NewDesc("cloudflare_exporter_zones",
		"Number of zones being collected.", nil, nil)
	descLastRun = prometheus.NewDesc("cloudflare_exporter_last_collection_timestamp_seconds",
		"Unix time the last background collection cycle finished.", nil, nil)
)

// publish rebuilds the metric snapshot from the current state.
func (c *Collector) publish() {
	c.mu.Lock()
	defer c.mu.Unlock()

	var ms []prometheus.Metric
	// seen drops duplicate series (for example two tunnels with the same
	// name in one account): a duplicate would make the whole scrape fail.
	seen := map[string]bool{}
	g := func(d *prometheus.Desc, v float64, labels ...string) {
		key := d.String() + "\x00" + strings.Join(labels, "\x00")
		if seen[key] {
			return
		}
		seen[key] = true
		ms = append(ms, prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...))
	}

	zoneNames := map[string]string{}
	for id, zs := range c.zones {
		z := zs.zone
		zoneNames[id] = z.Name
		acc := c.accountLabel(z.Account)
		g(descZoneInfo, 1, z.Name, z.ID, acc, z.Account.ID, z.PlanCode(), z.Status)

		if st := zs.http; st != nil {
			g(descWindow, float64(zs.httpWindow.Unix()), z.Name, acc)
			g(descRequests, st.Requests, z.Name, acc)
			g(descCachedRequests, st.CachedRequests, z.Name, acc)
			g(descEncryptedRequests, st.EncryptedRequests, z.Name, acc)
			g(descBytes, st.Bytes, z.Name, acc)
			g(descCachedBytes, st.CachedBytes, z.Name, acc)
			g(descEncryptedBytes, st.EncryptedBytes, z.Name, acc)
			g(descPageViews, st.PageViews, z.Name, acc)
			g(descThreats, st.Threats, z.Name, acc)
			g(descUniques, st.Uniques, z.Name, acc)
			for k, v := range st.ByStatus {
				g(descByStatus, v, z.Name, acc, k)
			}
			for k, v := range st.ByHTTPVersion {
				g(descByHTTPVersion, v, z.Name, acc, k)
			}
			if c.opts.TopCountries > 0 {
				for _, cc := range topCountries(st.Countries, c.opts.TopCountries) {
					g(descCountryRequests, cc.stats.Requests, z.Name, acc, cc.name)
					g(descCountryThreats, cc.stats.Threats, z.Name, acc, cc.name)
					g(descCountryBytes, cc.stats.Bytes, z.Name, acc, cc.name)
				}
			}
		}

		if fw := zs.fw; fw != nil {
			g(descFWWindow, float64(zs.fwWindow.Unix()), z.Name, acc)
			for k, v := range fw.Counts {
				g(descFWEvents, v, z.Name, acc, k.Action, k.Source)
			}
			t := 0.0
			if fw.Truncated {
				t = 1
			}
			g(descFWTruncated, t, z.Name, acc, fw.Dataset)
		}
	}

	for _, as := range c.accounts {
		if as.stats == nil {
			continue
		}
		name := as.name
		if name == "" {
			name = as.id
		}
		g(descAccWindow, float64(as.window.Unix()), name, as.id)
		g(descAccRequests, as.stats.Requests, name, as.id)
		g(descAccCachedRequests, as.stats.CachedRequests, name, as.id)
		g(descAccBytes, as.stats.Bytes, name, as.id)
		g(descAccCachedBytes, as.stats.CachedBytes, name, as.id)
	}

	for accID, states := range c.tunnels {
		acc := c.accountNames[accID]
		if acc == "" {
			acc = accID
		}
		for _, ts := range states {
			publishTunnel(g, acc, accID, ts)
		}
	}

	for k, s := range c.statuses {
		target := k.target
		switch k.scope {
		case "zone":
			if n := zoneNames[k.target]; n != "" {
				target = n
			}
		case "account":
			if n := c.accountNames[k.target]; n != "" {
				target = n
			}
		}
		up := 0.0
		if s.up {
			up = 1
		}
		g(descUp, up, k.scope, target, k.dataset)
		if !s.lastSuccess.IsZero() {
			g(descLastSuccess, float64(s.lastSuccess.Unix()), k.scope, target, k.dataset)
		}
	}

	g(descZones, float64(len(c.zones)))
	if !c.lastRun.IsZero() {
		g(descLastRun, float64(c.lastRun.Unix()))
	}
	c.snapshot.Store(&ms)
}

// accountLabel must be called with c.mu held.
func (c *Collector) accountLabel(a cloudflare.Ref) string {
	if a.Name != "" {
		return a.Name
	}
	if n := c.accountNames[a.ID]; n != "" {
		return n
	}
	return a.ID
}

type countryEntry struct {
	name  string
	stats cloudflare.CountryStats
}

// topCountries keeps the n countries with most requests and folds the rest
// into a single "other" entry, bounding label cardinality.
func topCountries(m map[string]cloudflare.CountryStats, n int) []countryEntry {
	all := make([]countryEntry, 0, len(m))
	for k, v := range m {
		all = append(all, countryEntry{name: k, stats: v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].stats.Requests != all[j].stats.Requests {
			return all[i].stats.Requests > all[j].stats.Requests
		}
		return all[i].name < all[j].name
	})
	if len(all) <= n {
		return all
	}
	other := countryEntry{name: "other"}
	for _, e := range all[n:] {
		other.stats.Requests += e.stats.Requests
		other.stats.Threats += e.stats.Threats
		other.stats.Bytes += e.stats.Bytes
	}
	return append(all[:n], other)
}

func publishTunnel(g func(*prometheus.Desc, float64, ...string), acc, accID string, ts tunnelState) {
	t := ts.tunnel
	name := t.Name
	if name == "" {
		name = t.ID
	}
	configSrc := t.ConfigSrc
	if configSrc == "" {
		configSrc = "unknown"
	}
	g(descTunnelInfo, 1, acc, accID, name, t.ID, t.Type, configSrc)

	known := false
	for _, st := range tunnelStatuses {
		v := 0.0
		if st == t.Status {
			v, known = 1, true
		}
		g(descTunnelStatus, v, acc, name, st)
	}
	if !known && t.Status != "" {
		g(descTunnelStatus, 1, acc, name, t.Status)
	}
	up := 0.0
	if t.Status == "healthy" || t.Status == "degraded" {
		up = 1
	}
	g(descTunnelUp, up, acc, name)

	var conns, pending float64
	byColo := map[string]float64{}
	for _, cn := range ts.connectors {
		for _, conn := range cn.Conns {
			conns++
			if conn.IsPendingReconnect {
				pending++
			}
			colo := conn.ColoName
			if colo == "" {
				colo = "unknown"
			}
			byColo[colo]++
		}
		version, arch := cn.Version, cn.Arch
		if version == "" {
			version = "unknown"
		}
		if arch == "" {
			arch = "unknown"
		}
		g(descConnectorInfo, 1, acc, name, cn.ID, version, arch)
	}
	g(descTunnelConns, conns, acc, name)
	g(descTunnelPending, pending, acc, name)
	for colo, v := range byColo {
		g(descTunnelByColo, v, acc, name, colo)
	}
	ids := map[string]bool{}
	for _, cn := range ts.connectors {
		ids[cn.ID] = true
	}
	g(descTunnelConnectors, float64(len(ids)), acc, name)

	if !t.ConnsActiveAt.IsZero() {
		g(descTunnelActive, float64(t.ConnsActiveAt.Unix()), acc, name)
	}
	if !t.ConnsInactiveAt.IsZero() {
		g(descTunnelInactive, float64(t.ConnsInactiveAt.Unix()), acc, name)
	}
}
