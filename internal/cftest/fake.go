// Package cftest provides a fake Cloudflare API with synthetic data for
// tests and local development. All identifiers and names are made up.
package cftest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Synthetic identifiers.
const (
	Token     = "test-token"
	AccountID = "acc00000000000000000000000000001"
	ZoneFree  = "zone0000000000000000000000000001"
	ZonePro   = "zone0000000000000000000000000002"
	ZoneFree2 = "zone0000000000000000000000000003"
)

// Fake is an http.Handler emulating the Cloudflare endpoints the exporter
// uses. Fields may be changed between requests under the mutex.
type Fake struct {
	mu sync.Mutex

	// Zones returned by /zones.
	Zones []map[string]any
	// FirewallEventsPerHour is the number of raw firewall events generated
	// uniformly over any hour, per zone.
	FirewallEventsPerHour int
	// FailDatasets makes GraphQL queries touching these datasets fail.
	FailDatasets map[string]bool
	// FailREST makes REST calls return HTTP 500.
	FailREST bool
	// Calls counts GraphQL calls by dataset.
	Calls map[string]int
	// Seen records whether a request had an unexpected Authorization header.
	BadAuth int

	// Tunnels returned by /accounts/{id}/tunnels (and /cfd_tunnel).
	Tunnels []map[string]any
	// Connectors returned by /accounts/{id}/{type}/{tunnel}/connections,
	// keyed by tunnel id.
	Connectors map[string][]any
	// TunnelsForbidden makes tunnel endpoints answer like a token without
	// the Cloudflare Tunnel permission.
	TunnelsForbidden bool
	// TunnelsLegacyOnly makes /tunnels return 404, so only /cfd_tunnel works.
	TunnelsLegacyOnly bool
	// ConnectionsFail makes the connections endpoint return HTTP 500.
	ConnectionsFail bool
	// RESTCalls counts REST calls by path.
	RESTCalls map[string]int

	// ExtraHosts adds that many one-request hosts to per-host traffic.
	ExtraHosts int
	// RefuseOptionalHostFields makes the per-host query fail when it asks
	// for origin status, bytes or origin time.
	RefuseOptionalHostFields bool
	// ZeroTrustForbidden makes Zero Trust REST and GraphQL calls fail as
	// unauthorized.
	ZeroTrustForbidden bool
	// CertsForbidden makes certificate pack calls return 403.
	CertsForbidden bool
	// DevicesMaxPerPage, when set, rejects larger device pages with 400.
	DevicesMaxPerPage int
	// Devices returned by /accounts/{id}/devices.
	Devices []map[string]any
}

// Synthetic dates for Zero Trust and certificate fixtures.
const (
	CertExpiryEarliest = "2027-01-05T00:00:00Z"
	TokenExpiry        = "2027-02-01T00:00:00Z" // #nosec G101 -- a date, not a credential
	TokenLastSeen      = "2026-02-28T09:00:00Z" // #nosec G101 -- a date, not a credential
)

func defaultDevices() []map[string]any {
	d := func(t string, lastSeen any) map[string]any {
		return map[string]any{"id": "dev", "device_type": t, "last_seen": lastSeen, "name": "device", "ip": "192.0.2.1"}
	}
	return []map[string]any{
		d("windows", "2026-03-01T10:00:00Z"), // < 24h before 2026-03-01T12:07Z
		d("windows", "2026-02-27T10:00:00Z"), // < 7d
		d("mac", "2026-02-10T10:00:00Z"),     // < 30d
		d("linux", "2025-06-01T10:00:00Z"),   // older
		d("ios", nil),                        // never
	}
}

// Synthetic tunnel identifiers.
const (
	TunnelHealthy  = "11111111-1111-4111-8111-111111111111"
	TunnelDown     = "22222222-2222-4222-8222-222222222222"
	TunnelWARP     = "33333333-3333-4333-8333-333333333333"
	TunnelGRE      = "44444444-4444-4444-8444-444444444444"
	ConnectorA     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	ConnectorB     = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	ConnectorC     = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	TunnelActiveAt = "2026-01-02T03:04:05Z"
)

func conn(id, client, version, colo string, pending bool) map[string]any {
	return map[string]any{
		"id": id, "uuid": id, "client_id": client, "client_version": version, "colo_name": colo,
		"is_pending_reconnect": pending, "opened_at": TunnelActiveAt, "origin_ip": "198.51.100.10",
	}
}

func defaultTunnels() ([]map[string]any, map[string][]any) {
	webConns := []any{
		conn("c0000001-0000-4000-8000-000000000001", ConnectorA, "2026.1.0", "MAD", false),
		conn("c0000001-0000-4000-8000-000000000002", ConnectorA, "2026.1.0", "MAD", false),
		conn("c0000001-0000-4000-8000-000000000003", ConnectorB, "2025.11.1", "MAD", false),
		conn("c0000001-0000-4000-8000-000000000004", ConnectorB, "2025.11.1", "CDG", true),
	}
	warpConns := []any{conn("c0000003-0000-4000-8000-000000000001", ConnectorC, "2026.1.0", "LHR", false)}
	tunnels := []map[string]any{
		{"id": TunnelHealthy, "name": "web-tunnel", "status": "healthy", "tun_type": "cfd_tunnel", "config_src": "cloudflare",
			"created_at": "2025-06-01T00:00:00Z", "conns_active_at": TunnelActiveAt, "conns_inactive_at": nil, "remote_config": true, "connections": webConns},
		{"id": TunnelDown, "name": "db-tunnel", "status": "down", "tun_type": "cfd_tunnel", "config_src": "local",
			"created_at": "2025-06-01T00:00:00Z", "conns_active_at": nil, "conns_inactive_at": "2026-01-05T06:07:08Z", "remote_config": false, "connections": []any{}},
		{"id": TunnelWARP, "name": "office-connector", "status": "degraded", "tun_type": "warp_connector",
			"created_at": "2025-06-01T00:00:00Z", "conns_active_at": TunnelActiveAt, "conns_inactive_at": nil, "connections": warpConns},
		{"id": TunnelGRE, "name": "gre-1", "status": "healthy", "tun_type": "gre", "created_at": "2025-06-01T00:00:00Z"},
	}
	connectors := map[string][]any{
		TunnelHealthy: {
			map[string]any{"id": ConnectorA, "arch": "linux_amd64", "version": "2026.1.0", "run_at": TunnelActiveAt, "features": []any{}, "conns": webConns[:2]},
			map[string]any{"id": ConnectorB, "arch": "linux_arm64", "version": "2025.11.1", "run_at": TunnelActiveAt, "features": []any{}, "conns": webConns[2:]},
		},
		TunnelDown: {},
		TunnelWARP: {
			map[string]any{"id": ConnectorC, "arch": "linux_amd64", "version": "2026.1.0", "run_at": TunnelActiveAt, "conns": warpConns},
		},
	}
	return tunnels, connectors
}

// New returns a fake with three zones: two on the Free plan and one on Pro.
func New() *Fake {
	acc := map[string]any{"id": AccountID, "name": "Example Account"}
	tunnels, connectors := defaultTunnels()
	return &Fake{
		Zones: []map[string]any{
			{"id": ZoneFree, "name": "example.com", "status": "active", "plan": map[string]any{"id": "p0", "name": "Free Website", "legacy_id": "free"}, "account": acc},
			{"id": ZonePro, "name": "example.org", "status": "active", "plan": map[string]any{"id": "p1", "name": "Pro Website", "legacy_id": "pro"}, "account": acc},
			{"id": ZoneFree2, "name": "example.net", "status": "active", "plan": map[string]any{"id": "p0", "name": "Free Website", "legacy_id": "free"}, "account": acc},
		},
		FirewallEventsPerHour: 120,
		Tunnels:               tunnels,
		Connectors:            connectors,
		RESTCalls:             map[string]int{},
		Devices:               defaultDevices(),
		FailDatasets:          map[string]bool{},
		Calls:                 map[string]int{},
	}
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+Token {
		f.mu.Lock()
		f.BadAuth++
		f.mu.Unlock()
		writeJSON(w, 403, map[string]any{"success": false, "errors": []any{map[string]any{"code": 9109, "message": "Invalid access token"}}})
		return
	}
	path := r.URL.Path
	if r.Method == http.MethodGet {
		f.mu.Lock()
		f.RESTCalls[path]++
		f.mu.Unlock()
	}
	if parts := strings.Split(strings.Trim(path, "/"), "/"); len(parts) >= 3 && parts[0] == "accounts" {
		f.tunnelRoutes(w, r, parts)
		return
	}
	switch {
	case path == "/graphql" && r.Method == http.MethodPost:
		f.graphql(w, r)
	case path == "/zones":
		f.listZones(w, r)
	case strings.HasPrefix(path, "/zones/") && strings.HasSuffix(path, "/ssl/certificate_packs"):
		f.certPacks(w, r)
	case strings.HasPrefix(path, "/zones/"):
		f.getZone(w, strings.TrimPrefix(path, "/zones/"))
	case strings.HasPrefix(path, "/accounts/"):
		if f.restFail(w) {
			return
		}
		writeJSON(w, 200, map[string]any{"success": true, "errors": []any{}, "result": map[string]any{"id": strings.TrimPrefix(path, "/accounts/"), "name": "Example Account"}})
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) restFail(w http.ResponseWriter) bool {
	f.mu.Lock()
	fail := f.FailREST
	f.mu.Unlock()
	if fail {
		writeJSON(w, 500, map[string]any{"success": false, "errors": []any{map[string]any{"code": 1000, "message": "synthetic failure"}}})
	}
	return fail
}

func (f *Fake) listZones(w http.ResponseWriter, r *http.Request) {
	if f.restFail(w) {
		return
	}
	f.mu.Lock()
	zones := f.Zones
	f.mu.Unlock()
	if acc := r.URL.Query().Get("account.id"); acc != "" {
		var filtered []map[string]any
		for _, z := range zones {
			if z["account"].(map[string]any)["id"] == acc {
				filtered = append(filtered, z)
			}
		}
		zones = filtered
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage <= 0 {
		perPage = 20
	}
	// Use a page size of 2 regardless, so pagination is exercised.
	if perPage > 2 {
		perPage = 2
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	total := (len(zones) + perPage - 1) / perPage
	lo := min((page-1)*perPage, len(zones))
	hi := min(lo+perPage, len(zones))
	writeJSON(w, 200, map[string]any{
		"success": true, "errors": []any{}, "result": zones[lo:hi],
		"result_info": map[string]any{"page": page, "per_page": perPage, "total_pages": total, "count": hi - lo, "total_count": len(zones)},
	})
}

func (f *Fake) getZone(w http.ResponseWriter, id string) {
	if f.restFail(w) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, z := range f.Zones {
		if z["id"] == id {
			writeJSON(w, 200, map[string]any{"success": true, "errors": []any{}, "result": z})
			return
		}
	}
	writeJSON(w, 404, map[string]any{"success": false, "errors": []any{map[string]any{"code": 1001, "message": "Invalid zone identifier"}}})
}

var limitRE = regexp.MustCompile(`limit:\s*(\d+)`)

func (f *Fake) plan(zoneTag string) string {
	for _, z := range f.Zones {
		if z["id"] == zoneTag {
			return z["plan"].(map[string]any)["legacy_id"].(string)
		}
	}
	return ""
}

func (f *Fake) graphql(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"errors": []any{map[string]any{"message": "bad request"}}})
		return
	}
	dataset := ""
	for _, ds := range []string{"settings", "httpRequests1hGroups", "firewallEventsAdaptiveGroups", "firewallEventsAdaptive", "httpRequestsOverviewAdaptiveGroups", "httpRequestsAdaptiveGroups", "gatewayResolverQueriesAdaptiveGroups", "accessLoginRequestsAdaptiveGroups"} {
		if strings.Contains(req.Query, ds+"(") || strings.Contains(req.Query, ds+" {") {
			dataset = ds
			break
		}
	}
	f.mu.Lock()
	f.Calls[dataset]++
	fail := f.FailDatasets[dataset]
	f.mu.Unlock()
	if fail {
		writeJSON(w, 200, map[string]any{"data": nil, "errors": []any{map[string]any{"message": "synthetic failure for " + dataset}}})
		return
	}
	str := func(k string) string { s, _ := req.Variables[k].(string); return s }
	zoneTag := str("zoneTag")
	start, _ := time.Parse(time.RFC3339, str("start"))
	end, _ := time.Parse(time.RFC3339, str("end"))

	f.mu.Lock()
	plan := f.plan(zoneTag)
	perHour := f.FirewallEventsPerHour
	f.mu.Unlock()
	paid := plan != "" && plan != "free"

	zone := func(node string, v any) {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"viewer": map[string]any{"zones": []any{map[string]any{node: v}}}}})
	}

	switch dataset {
	case "settings":
		if strings.Contains(req.Query, "availableFields") {
			fields := []string{"count", "clientRequestHTTPHost", "edgeResponseStatus"}
			if paid {
				fields = append(fields, "sum_edgeResponseBytes", "originResponseStatus", "avg_originResponseDurationMs")
			}
			zone("settings", map[string]any{"httpRequestsAdaptiveGroups": map[string]any{"availableFields": fields}})
			return
		}
		zone("settings", map[string]any{
			"httpRequestsAdaptiveGroups":   map[string]any{"enabled": true, "maxPageSize": 10000, "maxDuration": 2592000, "maxNumberOfFields": 40, "notOlderThan": 2678400},
			"httpRequests1hGroups":         map[string]any{"enabled": true},
			"firewallEventsAdaptive":       map[string]any{"enabled": true, "maxPageSize": 10000, "maxDuration": 86400, "notOlderThan": 2678400},
			"firewallEventsAdaptiveGroups": map[string]any{"enabled": paid, "maxPageSize": 10000, "maxDuration": 86400, "notOlderThan": 2678400},
		})
	case "httpRequests1hGroups":
		zone("httpRequests1hGroups", []any{map[string]any{
			"dimensions": map[string]any{"datetime": start.Format(time.RFC3339)},
			"sum": map[string]any{
				"requests": 1000, "cachedRequests": 600, "encryptedRequests": 990,
				"bytes": 5000000, "cachedBytes": 3000000, "encryptedBytes": 4900000,
				"pageViews": 300, "threats": 7,
				"responseStatusMap": []any{
					map[string]any{"edgeResponseStatus": 200, "requests": 900},
					map[string]any{"edgeResponseStatus": 404, "requests": 80},
					map[string]any{"edgeResponseStatus": 503, "requests": 20},
				},
				"countryMap": []any{
					map[string]any{"clientCountryName": "US", "requests": 500, "threats": 3, "bytes": 2500000},
					map[string]any{"clientCountryName": "DE", "requests": 300, "threats": 2, "bytes": 1500000},
					map[string]any{"clientCountryName": "FR", "requests": 150, "threats": 1, "bytes": 700000},
					map[string]any{"clientCountryName": "JP", "requests": 50, "threats": 1, "bytes": 300000},
				},
				"clientHTTPVersionMap": []any{
					map[string]any{"clientHTTPProtocol": "HTTP/2", "requests": 700},
					map[string]any{"clientHTTPProtocol": "HTTP/1.1", "requests": 300},
				},
			},
			"uniq": map[string]any{"uniques": 42},
		}})
	case "firewallEventsAdaptiveGroups":
		if !paid {
			writeJSON(w, 200, map[string]any{"data": nil, "errors": []any{map[string]any{"message": "zone '" + zoneTag + "' does not have access to the path"}}})
			return
		}
		n := float64(perHour) * end.Sub(start).Hours()
		zone("firewallEventsAdaptiveGroups", []any{
			map[string]any{"count": n / 2, "dimensions": map[string]any{"action": "block", "source": "firewallCustom"}},
			map[string]any{"count": n / 2, "dimensions": map[string]any{"action": "managed_challenge", "source": "securitylevel"}},
		})
	case "firewallEventsAdaptive":
		limit := 100
		if m := limitRE.FindStringSubmatch(req.Query); m != nil {
			limit, _ = strconv.Atoi(m[1])
		}
		// Events are spread evenly: one every 3600/perHour seconds,
		// starting at the top of each hour.
		var events []any
		if perHour > 0 {
			step := time.Hour / time.Duration(perHour)
			first := start.Truncate(time.Hour)
			for t := first; t.Before(end) && len(events) < limit; t = t.Add(step) {
				if t.Before(start) {
					continue
				}
				action, source := "block", "firewallCustom"
				if len(events)%3 == 0 {
					action, source = "managed_challenge", "securitylevel"
				}
				events = append(events, map[string]any{"action": action, "source": source, "datetime": t.Format(time.RFC3339)})
			}
		}
		if events == nil {
			events = []any{}
		}
		zone("firewallEventsAdaptive", events)
	case "httpRequestsAdaptiveGroups":
		f.hostGroups(w, req.Query, zone)
	case "gatewayResolverQueriesAdaptiveGroups", "accessLoginRequestsAdaptiveGroups":
		f.mu.Lock()
		forbidden := f.ZeroTrustForbidden
		f.mu.Unlock()
		if forbidden {
			writeJSON(w, 200, map[string]any{"data": nil, "errors": []any{map[string]any{"message": "not authorized for that account"}}})
			return
		}
		var groups []any
		if dataset == "gatewayResolverQueriesAdaptiveGroups" {
			groups = []any{
				map[string]any{"count": 120, "dimensions": map[string]any{"resolverDecision": 5}},
				map[string]any{"count": 15, "dimensions": map[string]any{"resolverDecision": 9}},
				map[string]any{"count": 1, "dimensions": map[string]any{"resolverDecision": 99}},
			}
		} else {
			groups = []any{
				map[string]any{"count": 40, "dimensions": map[string]any{"isSuccessfulLogin": 1}},
				map[string]any{"count": 3, "dimensions": map[string]any{"isSuccessfulLogin": 0}},
			}
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"viewer": map[string]any{"accounts": []any{map[string]any{dataset: groups}}}}})
	case "httpRequestsOverviewAdaptiveGroups":
		writeJSON(w, 200, map[string]any{"data": map[string]any{"viewer": map[string]any{"accounts": []any{map[string]any{
			"httpRequestsOverviewAdaptiveGroups": []any{map[string]any{"sum": map[string]any{"requests": 3000, "cachedRequests": 1800, "bytes": 15000000, "cachedBytes": 9000000}}},
		}}}}})
	default:
		writeJSON(w, 200, map[string]any{"data": nil, "errors": []any{map[string]any{"message": fmt.Sprintf("unknown query: %.40q", req.Query)}}})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *Fake) tunnelRoutes(w http.ResponseWriter, r *http.Request, parts []string) {
	if (len(parts) == 4 && parts[2] == "access" && parts[3] == "service_tokens") || (len(parts) == 3 && parts[2] == "devices") {
		f.zeroTrustRoutes(w, r, parts)
		return
	}
	f.mu.Lock()
	forbidden, legacy, connFail := f.TunnelsForbidden, f.TunnelsLegacyOnly, f.ConnectionsFail
	tunnels, connectors := f.Tunnels, f.Connectors
	f.mu.Unlock()
	if forbidden {
		writeJSON(w, 403, map[string]any{"success": false, "errors": []any{map[string]any{"code": 10000, "message": "Authentication error"}}})
		return
	}
	switch {
	case len(parts) == 3 && (parts[2] == "tunnels" || parts[2] == "cfd_tunnel"):
		if parts[2] == "tunnels" && legacy {
			http.NotFound(w, r)
			return
		}
		var list []map[string]any
		for _, t := range tunnels {
			if parts[2] == "cfd_tunnel" && t["tun_type"] != "cfd_tunnel" {
				continue
			}
			list = append(list, t)
		}
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if perPage < 1 {
			perPage = 20
		}
		if page < 1 {
			page = 1
		}
		lo := min((page-1)*perPage, len(list))
		hi := min(lo+perPage, len(list))
		result := list[lo:hi]
		if result == nil {
			result = []map[string]any{}
		}
		writeJSON(w, 200, map[string]any{"success": true, "errors": []any{}, "result": result,
			"result_info": map[string]any{"page": page, "per_page": perPage, "count": hi - lo, "total_count": len(list)}})
	case len(parts) == 5 && parts[4] == "connections":
		if connFail {
			writeJSON(w, 500, map[string]any{"success": false, "errors": []any{map[string]any{"code": 1000, "message": "synthetic failure"}}})
			return
		}
		cs, ok := connectors[parts[3]]
		if !ok {
			writeJSON(w, 404, map[string]any{"success": false, "errors": []any{map[string]any{"code": 1003, "message": "tunnel not found"}}})
			return
		}
		if cs == nil {
			cs = []any{}
		}
		writeJSON(w, 200, map[string]any{"success": true, "errors": []any{}, "result": cs})
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) hostGroups(w http.ResponseWriter, query string, zone func(string, any)) {
	f.mu.Lock()
	refuse, extra := f.RefuseOptionalHostFields, f.ExtraHosts
	f.mu.Unlock()
	origin := strings.Contains(query, "originResponseStatus")
	bytes := strings.Contains(query, "edgeResponseBytes")
	dur := strings.Contains(query, "originResponseDurationMs")
	if refuse && (origin || bytes || dur) {
		writeJSON(w, 200, map[string]any{"data": nil, "errors": []any{map[string]any{"message": "unknown field originResponseStatus"}}})
		return
	}
	limit := 10000
	if m := limitRE.FindStringSubmatch(query); m != nil {
		limit, _ = strconv.Atoi(m[1])
	}
	type row struct {
		host         string
		edge, origin int
		count        float64
		ms           float64
	}
	rows := []row{
		{"www.example.com", 200, 200, 500, 80},
		// Served from cache: never reached the origin, so Cloudflare
		// reports origin status 0 and an average origin time of -1.
		{"www.example.com", 200, 0, 58, -1},
		{"www.example.com", 404, 404, 20, 20},
		{"www.example.com", 503, 503, 5, 3000},
		{"api.example.com", 200, 200, 300, 120},
		{"api.example.com", 500, 500, 10, 900},
		{"static.example.com", 200, 0, 50, -1},
	}
	for i := 0; i < extra; i++ {
		rows = append(rows, row{fmt.Sprintf("h%d.example.com", i), 200, 200, 1, 10})
	}
	var groups []any
	for _, r := range rows {
		if len(groups) >= limit {
			break
		}
		dims := map[string]any{"clientRequestHTTPHost": r.host, "edgeResponseStatus": r.edge}
		if origin {
			dims["originResponseStatus"] = r.origin
		}
		g := map[string]any{"count": r.count, "dimensions": dims}
		if bytes {
			g["sum"] = map[string]any{"edgeResponseBytes": r.count * 1000}
		}
		if dur {
			g["avg"] = map[string]any{"originResponseDurationMs": r.ms}
		}
		groups = append(groups, g)
	}
	if groups == nil {
		groups = []any{}
	}
	zone("httpRequestsAdaptiveGroups", groups)
}

func (f *Fake) certPacks(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	forbidden := f.CertsForbidden
	f.mu.Unlock()
	if forbidden {
		writeJSON(w, 403, map[string]any{"success": false, "errors": []any{map[string]any{"code": 10000, "message": "Authentication error"}}})
		return
	}
	if r.URL.Query().Get("status") != "all" {
		writeJSON(w, 400, map[string]any{"success": false, "errors": []any{map[string]any{"code": 1000, "message": "expected status=all"}}})
		return
	}
	packs := []any{
		map[string]any{"id": "pack-universal-1", "type": "universal", "status": "active", "certificate_authority": "google",
			"hosts": []any{"example.com", "*.example.com"}, "certificates": []any{
				map[string]any{"id": "cert-1", "expires_on": "2027-01-10T00:00:00Z", "status": "active"},
				map[string]any{"id": "cert-2", "expires_on": CertExpiryEarliest, "status": "active"},
			}},
		map[string]any{"id": "pack-advanced-1", "type": "advanced", "status": "pending_validation",
			"hosts": []any{"shop.example.com"}, "certificates": []any{}},
	}
	writeJSON(w, 200, map[string]any{"success": true, "errors": []any{}, "result": packs,
		"result_info": map[string]any{"page": 1, "per_page": 50, "count": len(packs), "total_count": len(packs), "total_pages": 1}})
}

func (f *Fake) zeroTrustRoutes(w http.ResponseWriter, r *http.Request, parts []string) {
	f.mu.Lock()
	forbidden, maxPer, devices := f.ZeroTrustForbidden, f.DevicesMaxPerPage, f.Devices
	f.mu.Unlock()
	if forbidden {
		writeJSON(w, 403, map[string]any{"success": false, "errors": []any{map[string]any{"code": 10000, "message": "Authentication error"}}})
		return
	}
	if parts[2] == "access" {
		tokens := []any{
			map[string]any{"id": "tok-1", "name": "ci-deploy", "client_id": "secret-client-id.access", "expires_at": TokenExpiry, "last_seen_at": TokenLastSeen, "duration": "8760h"},
			map[string]any{"id": "tok-2", "name": "legacy-bot", "client_id": "secret-client-id-2.access", "expires_at": "2125-01-01T00:00:00Z", "duration": "forever"},
		}
		writeJSON(w, 200, map[string]any{"success": true, "errors": []any{}, "result": tokens,
			"result_info": map[string]any{"page": 1, "per_page": 1000, "count": len(tokens), "total_count": len(tokens), "total_pages": 1}})
		return
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if perPage < 1 {
		perPage = 20
	}
	if maxPer > 0 && perPage > maxPer {
		writeJSON(w, 400, map[string]any{"success": false, "errors": []any{map[string]any{"code": 1001, "message": "per_page too large"}}})
		return
	}
	if page < 1 {
		page = 1
	}
	lo := min((page-1)*perPage, len(devices))
	hi := min(lo+perPage, len(devices))
	result := devices[lo:hi]
	if result == nil {
		result = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"success": true, "errors": []any{}, "result": result,
		"result_info": map[string]any{"page": page, "per_page": perPage, "count": hi - lo, "total_count": len(devices)}})
}
