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
}

// New returns a fake with three zones: two on the Free plan and one on Pro.
func New() *Fake {
	acc := map[string]any{"id": AccountID, "name": "Example Account"}
	return &Fake{
		Zones: []map[string]any{
			{"id": ZoneFree, "name": "example.com", "status": "active", "plan": map[string]any{"id": "p0", "name": "Free Website", "legacy_id": "free"}, "account": acc},
			{"id": ZonePro, "name": "example.org", "status": "active", "plan": map[string]any{"id": "p1", "name": "Pro Website", "legacy_id": "pro"}, "account": acc},
			{"id": ZoneFree2, "name": "example.net", "status": "active", "plan": map[string]any{"id": "p0", "name": "Free Website", "legacy_id": "free"}, "account": acc},
		},
		FirewallEventsPerHour: 120,
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
	switch {
	case path == "/graphql" && r.Method == http.MethodPost:
		f.graphql(w, r)
	case path == "/zones":
		f.listZones(w, r)
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
	for _, ds := range []string{"settings", "httpRequests1hGroups", "firewallEventsAdaptiveGroups", "firewallEventsAdaptive", "httpRequestsOverviewAdaptiveGroups"} {
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
		zone("settings", map[string]any{
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
