package collector

import (
	"sort"
	"strconv"

	"github.com/luisra51/cloudflare-exporter/internal/cloudflare"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	hostLabels = []string{"zone", "account", "host"}

	descHostWindow = prometheus.NewDesc("cloudflare_zone_host_window_start_timestamp_seconds",
		"Start (Unix time) of the rolling window the cloudflare_zone_host_* metrics describe.", zoneLabels, nil)
	descHostWindowSeconds = prometheus.NewDesc("cloudflare_zone_host_window_seconds",
		"Length of the rolling window the cloudflare_zone_host_* metrics describe. Divide by it to get a per-second rate.", zoneLabels, nil)
	descHostRequests = prometheus.NewDesc("cloudflare_zone_host_requests",
		"Requests per host and edge status class in the rolling window (sampled estimate; top N hosts, the rest as host=\"other\").", append(hostLabels, "status_class"), nil)
	descHostRequestsByStatus = prometheus.NewDesc("cloudflare_zone_host_requests_by_status",
		"Requests per host and exact edge status in the rolling window (sampled estimate). Only with CF_HOST_EXACT_STATUS=true.", append(hostLabels, "status"), nil)
	descHostBytes = prometheus.NewDesc("cloudflare_zone_host_bytes",
		"Bytes sent to clients per host in the rolling window (sampled estimate). Only when the zone may query edgeResponseBytes.", hostLabels, nil)
	descHostOrigin5xx = prometheus.NewDesc("cloudflare_zone_host_origin_5xx_requests",
		"Requests per host whose origin answered 5xx in the rolling window (sampled estimate). Only when the zone may query originResponseStatus.", hostLabels, nil)
	descHostOriginTime = prometheus.NewDesc("cloudflare_zone_host_origin_response_time_seconds",
		"Average origin response time per host in the rolling window. Only when the zone may query originResponseDurationMs.", hostLabels, nil)
	descHostTruncated = prometheus.NewDesc("cloudflare_zone_host_truncated",
		"1 if the per-host query hit the API row limit and counts are a lower bound.", zoneLabels, nil)

	descCertExpiry = prometheus.NewDesc("cloudflare_zone_certificate_pack_expiry_timestamp_seconds",
		"Earliest expiry (Unix time) among the certificates of an edge certificate pack.", []string{"zone", "account", "pack_id", "type", "status"}, nil)
	descCertInfo = prometheus.NewDesc("cloudflare_zone_certificate_pack_info",
		"Edge certificate pack metadata. Always 1.", []string{"zone", "account", "pack_id", "type", "status", "certificate_authority"}, nil)
	descCertActive = prometheus.NewDesc("cloudflare_zone_certificate_pack_active",
		"1 if the certificate pack status is active, 0 otherwise.", []string{"zone", "account", "pack_id", "type"}, nil)
	descCertPacks = prometheus.NewDesc("cloudflare_zone_certificate_packs",
		"Edge certificate packs of the zone (all statuses).", zoneLabels, nil)

	descTokenExpiry = prometheus.NewDesc("cloudflare_access_service_token_expiry_timestamp_seconds",
		"Expiry (Unix time) of an Access service token.", []string{"account", "name"}, nil)
	descTokenLastSeen = prometheus.NewDesc("cloudflare_access_service_token_last_seen_timestamp_seconds",
		"Last use (Unix time) of an Access service token, when Cloudflare reports it.", []string{"account", "name"}, nil)
	descTokens = prometheus.NewDesc("cloudflare_access_service_tokens",
		"Access service tokens of the account.", []string{"account"}, nil)

	descDevices = prometheus.NewDesc("cloudflare_zerotrust_devices",
		"WARP devices registered in the account.", []string{"account"}, nil)
	descDevicesLastSeen = prometheus.NewDesc("cloudflare_zerotrust_devices_by_last_seen",
		"WARP devices by time since last seen (exclusive buckets: 24h, 7d, 30d, older, never).", []string{"account", "last_seen"}, nil)
	descDevicesOS = prometheus.NewDesc("cloudflare_zerotrust_devices_by_os",
		"WARP devices by device type (windows, mac, linux, android, ios, chromeos).", []string{"account", "os"}, nil)

	descZTWindow = prometheus.NewDesc("cloudflare_zerotrust_window_start_timestamp_seconds",
		"Start (Unix time) of the rolling window the Gateway DNS and Access login metrics describe.", []string{"account"}, nil)
	descZTWindowSeconds = prometheus.NewDesc("cloudflare_zerotrust_window_seconds",
		"Length of the rolling window the Gateway DNS and Access login metrics describe.", []string{"account"}, nil)
	descGatewayDNS = prometheus.NewDesc("cloudflare_gateway_dns_queries",
		"Gateway DNS queries by resolver decision in the rolling window (sampled estimate).", []string{"account", "decision", "decision_code"}, nil)
	descAccessLogins = prometheus.NewDesc("cloudflare_access_logins",
		"Access login attempts by result (success, failure) in the rolling window (sampled estimate).", []string{"account", "result"}, nil)
)

func statusClass(code int) string {
	if code >= 100 && code <= 599 {
		return strconv.Itoa(code/100) + "xx"
	}
	return "unknown"
}

// hostAgg is one host's totals, used to rank hosts.
type hostAgg struct {
	host     string
	requests float64
}

// publishHosts must be called with c.mu held.
func (c *Collector) publishHosts(g func(*prometheus.Desc, float64, ...string), zone, acc string, zs *zoneState) {
	st := zs.hosts
	if st == nil {
		return
	}
	g(descHostWindow, float64(zs.hostsWindow[0].Unix()), zone, acc)
	g(descHostWindowSeconds, zs.hostsWindow[1].Sub(zs.hostsWindow[0]).Seconds(), zone, acc)
	trunc := 0.0
	if st.Truncated {
		trunc = 1
	}
	g(descHostTruncated, trunc, zone, acc)

	totals := map[string]float64{}
	for k, v := range st.Requests {
		totals[k.Host] += v
	}
	ranked := make([]hostAgg, 0, len(totals))
	for h, v := range totals {
		ranked = append(ranked, hostAgg{h, v})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].requests != ranked[j].requests {
			return ranked[i].requests > ranked[j].requests
		}
		return ranked[i].host < ranked[j].host
	})
	label := map[string]string{}
	for i, h := range ranked {
		if c.opts.TopHosts > 0 && i >= c.opts.TopHosts {
			label[h.host] = "other"
		} else {
			label[h.host] = h.host
		}
	}

	byClass := map[[2]string]float64{}
	byStatus := map[[2]string]float64{}
	for k, v := range st.Requests {
		h := label[k.Host]
		byClass[[2]string{h, statusClass(k.Status)}] += v
		byStatus[[2]string{h, strconv.Itoa(k.Status)}] += v
	}
	for k, v := range byClass {
		g(descHostRequests, v, zone, acc, k[0], k[1])
	}
	if c.opts.HostExactStatus {
		for k, v := range byStatus {
			g(descHostRequestsByStatus, v, zone, acc, k[0], k[1])
		}
	}
	fold := func(m map[string]float64) map[string]float64 {
		out := map[string]float64{}
		for h, v := range m {
			if l, ok := label[h]; ok {
				out[l] += v
			} else {
				out["other"] += v
			}
		}
		return out
	}
	if st.HasBytes {
		for h, v := range fold(st.Bytes) {
			g(descHostBytes, v, zone, acc, h)
		}
	}
	if st.HasOrigin {
		o := fold(st.Origin5xx)
		for _, h := range label {
			if _, ok := o[h]; !ok {
				o[h] = 0
			}
		}
		for h, v := range o {
			g(descHostOrigin5xx, v, zone, acc, h)
		}
	}
	if st.HasOriginTime {
		sum, weight := fold(st.OriginTimeSum), fold(st.OriginTimeWeight)
		for h, w := range weight {
			if w > 0 {
				g(descHostOriginTime, sum[h]/w/1000, zone, acc, h)
			}
		}
	}
}

// publishCerts must be called with c.mu held.
func publishCerts(g func(*prometheus.Desc, float64, ...string), zone, acc string, zs *zoneState) {
	if !zs.certsOK {
		return
	}
	g(descCertPacks, float64(len(zs.certs)), zone, acc)
	for _, p := range zs.certs {
		typ, status, ca := orUnknown(p.Type), orUnknown(p.Status), orUnknown(p.CertificateAuthority)
		g(descCertInfo, 1, zone, acc, p.ID, typ, status, ca)
		active := 0.0
		if p.Status == "active" {
			active = 1
		}
		g(descCertActive, active, zone, acc, p.ID, typ)
		if !p.EarliestExpiry.IsZero() {
			g(descCertExpiry, float64(p.EarliestExpiry.Unix()), zone, acc, p.ID, typ, status)
		}
	}
}

// publishZeroTrust must be called with c.mu held.
func publishZeroTrust(g func(*prometheus.Desc, float64, ...string), acc string, st *ztState) {
	if st.tokensOK {
		g(descTokens, float64(len(st.tokens)), acc)
		for _, t := range st.tokens {
			name := t.Name
			if name == "" {
				name = t.ID
			}
			if !t.ExpiresAt.IsZero() {
				g(descTokenExpiry, float64(t.ExpiresAt.Unix()), acc, name)
			}
			if !t.LastSeenAt.IsZero() {
				g(descTokenLastSeen, float64(t.LastSeenAt.Unix()), acc, name)
			}
		}
	}
	if d := st.devices; d != nil {
		g(descDevices, d.Total, acc)
		for b, v := range d.ByLastSeen {
			g(descDevicesLastSeen, v, acc, b)
		}
		for os, v := range d.ByOS {
			g(descDevicesOS, v, acc, os)
		}
	}
	if st.gateway != nil || st.logins != nil {
		w := st.gwWindow
		if st.gateway == nil {
			w = st.accWindow
		}
		g(descZTWindow, float64(w[0].Unix()), acc)
		g(descZTWindowSeconds, w[1].Sub(w[0]).Seconds(), acc)
	}
	for code, v := range st.gateway {
		name := cloudflare.GatewayDecisionNames[code]
		if name == "" {
			name = "unknown"
		}
		g(descGatewayDNS, v, acc, name, code)
	}
	for res, v := range st.logins {
		g(descAccessLogins, v, acc, res)
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
