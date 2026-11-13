package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Datasets used by the exporter.
const (
	DatasetHTTP1h          = "httpRequests1hGroups"
	DatasetFirewallRaw     = "firewallEventsAdaptive"
	DatasetFirewallGroups  = "firewallEventsAdaptiveGroups"
	DatasetAccountOverview = "httpRequestsOverviewAdaptiveGroups"
	DatasetSettings        = "settings"
)

// ---------------------------------------------------------- settings ----

const zoneSettingsQuery = `query ZoneSettings($zoneTag: String!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      settings {
        httpRequests1hGroups { enabled }
        firewallEventsAdaptive { enabled maxPageSize maxDuration notOlderThan }
        firewallEventsAdaptiveGroups { enabled maxPageSize maxDuration notOlderThan }
      }
    }
  }
}`

// NodeSettings are the limits Cloudflare reports for one dataset.
type NodeSettings struct {
	Enabled      bool  `json:"enabled"`
	MaxPageSize  int   `json:"maxPageSize"`
	MaxDuration  int64 `json:"maxDuration"`  // seconds
	NotOlderThan int64 `json:"notOlderThan"` // seconds
}

// ZoneSettings describes which datasets a zone may query.
type ZoneSettings struct {
	HTTP1h         NodeSettings `json:"httpRequests1hGroups"`
	FirewallRaw    NodeSettings `json:"firewallEventsAdaptive"`
	FirewallGroups NodeSettings `json:"firewallEventsAdaptiveGroups"`
}

// DefaultZoneSettings is what the exporter assumes for a Free-plan zone
// when the settings node cannot be read.
func DefaultZoneSettings() ZoneSettings {
	return ZoneSettings{
		HTTP1h:      NodeSettings{Enabled: true},
		FirewallRaw: NodeSettings{Enabled: true, MaxPageSize: 10000, MaxDuration: 86400},
	}
}

// ZoneSettings queries the GraphQL settings node of a zone.
func (c *Client) ZoneSettings(ctx context.Context, zoneTag string) (ZoneSettings, error) {
	var out struct {
		Viewer struct {
			Zones []struct {
				Settings ZoneSettings `json:"settings"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	if err := c.GraphQL(ctx, DatasetSettings, zoneSettingsQuery, map[string]any{"zoneTag": zoneTag}, &out); err != nil {
		return ZoneSettings{}, err
	}
	if len(out.Viewer.Zones) == 0 {
		return ZoneSettings{}, errors.New("settings: zone not returned")
	}
	return out.Viewer.Zones[0].Settings, nil
}

// --------------------------------------------------- httpRequests1hGroups --

const zoneHTTP1hQuery = `query ZoneHTTPRequests1h($zoneTag: String!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      httpRequests1hGroups(limit: 4, filter: {datetime_geq: $start, datetime_lt: $end}) {
        dimensions { datetime }
        sum {
          requests
          cachedRequests
          encryptedRequests
          bytes
          cachedBytes
          encryptedBytes
          pageViews
          threats
          responseStatusMap { edgeResponseStatus requests }
          countryMap { clientCountryName requests threats bytes }
          clientHTTPVersionMap { clientHTTPProtocol requests }
        }
        uniq { uniques }
      }
    }
  }
}`

// HTTPStats aggregates HTTP traffic for one window.
type HTTPStats struct {
	Groups            int // number of hourly groups returned (0 = no traffic)
	Requests          float64
	CachedRequests    float64
	EncryptedRequests float64
	Bytes             float64
	CachedBytes       float64
	EncryptedBytes    float64
	PageViews         float64
	Threats           float64
	Uniques           float64
	ByStatus          map[string]float64
	ByHTTPVersion     map[string]float64
	Countries         map[string]CountryStats
}

// CountryStats is the per-country breakdown.
type CountryStats struct {
	Requests float64
	Threats  float64
	Bytes    float64
}

type http1hGroup struct {
	Dimensions struct {
		Datetime string `json:"datetime"`
	} `json:"dimensions"`
	Sum struct {
		Requests          float64 `json:"requests"`
		CachedRequests    float64 `json:"cachedRequests"`
		EncryptedRequests float64 `json:"encryptedRequests"`
		Bytes             float64 `json:"bytes"`
		CachedBytes       float64 `json:"cachedBytes"`
		EncryptedBytes    float64 `json:"encryptedBytes"`
		PageViews         float64 `json:"pageViews"`
		Threats           float64 `json:"threats"`
		ResponseStatusMap []struct {
			EdgeResponseStatus int     `json:"edgeResponseStatus"`
			Requests           float64 `json:"requests"`
		} `json:"responseStatusMap"`
		CountryMap []struct {
			ClientCountryName string  `json:"clientCountryName"`
			Requests          float64 `json:"requests"`
			Threats           float64 `json:"threats"`
			Bytes             float64 `json:"bytes"`
		} `json:"countryMap"`
		ClientHTTPVersionMap []struct {
			ClientHTTPProtocol string  `json:"clientHTTPProtocol"`
			Requests           float64 `json:"requests"`
		} `json:"clientHTTPVersionMap"`
	} `json:"sum"`
	Uniq struct {
		Uniques float64 `json:"uniques"`
	} `json:"uniq"`
}

// ZoneHTTP1h returns HTTP statistics for [start, end) from the hourly
// dataset, which is available on every plan including Free.
func (c *Client) ZoneHTTP1h(ctx context.Context, zoneTag string, start, end time.Time) (HTTPStats, error) {
	var out struct {
		Viewer struct {
			Zones []struct {
				Groups []http1hGroup `json:"httpRequests1hGroups"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	vars := map[string]any{"zoneTag": zoneTag, "start": rfc3339(start), "end": rfc3339(end)}
	if err := c.GraphQL(ctx, DatasetHTTP1h, zoneHTTP1hQuery, vars, &out); err != nil {
		return HTTPStats{}, err
	}
	st := HTTPStats{
		ByStatus:      map[string]float64{},
		ByHTTPVersion: map[string]float64{},
		Countries:     map[string]CountryStats{},
	}
	if len(out.Viewer.Zones) == 0 {
		return st, nil
	}
	for _, g := range out.Viewer.Zones[0].Groups {
		st.Groups++
		s := g.Sum
		st.Requests += s.Requests
		st.CachedRequests += s.CachedRequests
		st.EncryptedRequests += s.EncryptedRequests
		st.Bytes += s.Bytes
		st.CachedBytes += s.CachedBytes
		st.EncryptedBytes += s.EncryptedBytes
		st.PageViews += s.PageViews
		st.Threats += s.Threats
		st.Uniques += g.Uniq.Uniques
		for _, r := range s.ResponseStatusMap {
			st.ByStatus[fmt.Sprint(r.EdgeResponseStatus)] += r.Requests
		}
		for _, r := range s.ClientHTTPVersionMap {
			k := r.ClientHTTPProtocol
			if k == "" {
				k = "unknown"
			}
			st.ByHTTPVersion[k] += r.Requests
		}
		for _, r := range s.CountryMap {
			k := r.ClientCountryName
			if k == "" {
				k = "unknown"
			}
			cs := st.Countries[k]
			cs.Requests += r.Requests
			cs.Threats += r.Threats
			cs.Bytes += r.Bytes
			st.Countries[k] = cs
		}
	}
	return st, nil
}

// ---------------------------------------------------- firewall events ----

// FirewallKey groups firewall events.
type FirewallKey struct {
	Action string
	Source string
}

// FirewallStats counts firewall events by action and source.
type FirewallStats struct {
	Counts    map[FirewallKey]float64
	Truncated bool   // a sub-window still hit the page limit; counts are a lower bound
	Dataset   string // dataset actually used
	Queries   int    // GraphQL queries issued
}

// minFirewallWindow is the smallest window the raw-event bisection will try.
const minFirewallWindow = time.Minute

// maxFirewallQueries caps the GraphQL queries spent on raw firewall events
// for one zone and window, to stay well inside the API rate limit
// (300 queries per 5 minutes per user).
const maxFirewallQueries = 32

func firewallRawQuery(limit int) string {
	return fmt.Sprintf(`query ZoneFirewallEvents($zoneTag: String!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(limit: %d, filter: {datetime_geq: $start, datetime_lt: $end}, orderBy: [datetime_ASC]) {
        action
        source
      }
    }
  }
}`, limit)
}

func firewallGroupsQuery(limit int) string {
	return fmt.Sprintf(`query ZoneFirewallEventGroups($zoneTag: String!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptiveGroups(limit: %d, filter: {datetime_geq: $start, datetime_lt: $end}) {
        count
        dimensions { action source }
      }
    }
  }
}`, limit)
}

// ZoneFirewallEvents counts firewall events in [start, end).
//
// When the zone may use firewallEventsAdaptiveGroups (paid plans) the
// aggregation happens server side. Otherwise (Free plan) raw events are
// fetched from firewallEventsAdaptive and counted client side. Raw queries
// are capped at the page size, so a window that returns a full page is split
// in two and both halves are queried again, down to one minute. If a
// one-minute window is still full, the result is flagged as truncated.
func (c *Client) ZoneFirewallEvents(ctx context.Context, zoneTag string, start, end time.Time, s ZoneSettings) (FirewallStats, error) {
	st := FirewallStats{Counts: map[FirewallKey]float64{}}
	if s.FirewallGroups.Enabled {
		st.Dataset = DatasetFirewallGroups
		err := c.firewallGroups(ctx, zoneTag, start, end, s.FirewallGroups, &st)
		var gqlErr GraphQLErrors
		if err == nil || !errors.As(err, &gqlErr) || !s.FirewallRaw.Enabled {
			return st, err
		}
		// The settings node said yes but the query was refused: fall back
		// to raw events, which every plan can read.
		st = FirewallStats{Counts: map[FirewallKey]float64{}, Queries: st.Queries}
	}
	if !s.FirewallRaw.Enabled {
		return st, ErrDatasetUnavailable
	}
	st.Dataset = DatasetFirewallRaw
	limit := s.FirewallRaw.MaxPageSize
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	// Respect the dataset's maximum query duration.
	for _, w := range splitWindow(start, end, time.Duration(s.FirewallRaw.MaxDuration)*time.Second) {
		if err := c.firewallRaw(ctx, zoneTag, w[0], w[1], limit, &st); err != nil {
			return st, err
		}
	}
	return st, nil
}

// ErrDatasetUnavailable means the settings node reports the dataset as
// disabled for the zone or account.
var ErrDatasetUnavailable = errors.New("dataset not available for this zone")

func (c *Client) firewallRaw(ctx context.Context, zoneTag string, start, end time.Time, limit int, st *FirewallStats) error {
	var out struct {
		Viewer struct {
			Zones []struct {
				Events []struct {
					Action string `json:"action"`
					Source string `json:"source"`
				} `json:"firewallEventsAdaptive"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	vars := map[string]any{"zoneTag": zoneTag, "start": rfc3339(start), "end": rfc3339(end)}
	st.Queries++
	if err := c.GraphQL(ctx, DatasetFirewallRaw, firewallRawQuery(limit), vars, &out); err != nil {
		return err
	}
	if len(out.Viewer.Zones) == 0 {
		return nil
	}
	events := out.Viewer.Zones[0].Events
	if len(events) >= limit {
		half := end.Sub(start) / 2
		if half >= minFirewallWindow && st.Queries+2 <= maxFirewallQueries {
			mid := start.Add(half).Truncate(time.Second)
			if err := c.firewallRaw(ctx, zoneTag, start, mid, limit, st); err != nil {
				return err
			}
			return c.firewallRaw(ctx, zoneTag, mid, end, limit, st)
		}
		st.Truncated = true
	}
	for _, e := range events {
		st.Counts[FirewallKey{Action: orUnknown(e.Action), Source: orUnknown(e.Source)}]++
	}
	return nil
}

func (c *Client) firewallGroups(ctx context.Context, zoneTag string, start, end time.Time, ns NodeSettings, st *FirewallStats) error {
	limit := ns.MaxPageSize
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	for _, w := range splitWindow(start, end, time.Duration(ns.MaxDuration)*time.Second) {
		var out struct {
			Viewer struct {
				Zones []struct {
					Groups []struct {
						Count      float64 `json:"count"`
						Dimensions struct {
							Action string `json:"action"`
							Source string `json:"source"`
						} `json:"dimensions"`
					} `json:"firewallEventsAdaptiveGroups"`
				} `json:"zones"`
			} `json:"viewer"`
		}
		vars := map[string]any{"zoneTag": zoneTag, "start": rfc3339(w[0]), "end": rfc3339(w[1])}
		st.Queries++
		if err := c.GraphQL(ctx, DatasetFirewallGroups, firewallGroupsQuery(limit), vars, &out); err != nil {
			return err
		}
		if len(out.Viewer.Zones) == 0 {
			continue
		}
		groups := out.Viewer.Zones[0].Groups
		if len(groups) >= limit {
			st.Truncated = true
		}
		for _, g := range groups {
			st.Counts[FirewallKey{Action: orUnknown(g.Dimensions.Action), Source: orUnknown(g.Dimensions.Source)}] += g.Count
		}
	}
	return nil
}

// ----------------------------------------------------- account overview --

const accountOverviewQuery = `query AccountHTTPOverview($accountTag: String!, $start: Time!, $end: Time!) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      httpRequestsOverviewAdaptiveGroups(limit: 1, filter: {datetime_geq: $start, datetime_lt: $end}) {
        sum {
          requests
          cachedRequests
          bytes
          cachedBytes
        }
      }
    }
  }
}`

// AccountStats aggregates HTTP traffic across every zone of an account.
type AccountStats struct {
	Requests       float64
	CachedRequests float64
	Bytes          float64
	CachedBytes    float64
}

// AccountHTTPOverview returns account-wide HTTP totals for [start, end).
func (c *Client) AccountHTTPOverview(ctx context.Context, accountTag string, start, end time.Time) (AccountStats, error) {
	var out struct {
		Viewer struct {
			Accounts []struct {
				Groups []struct {
					Sum AccountStats `json:"sum"`
				} `json:"httpRequestsOverviewAdaptiveGroups"`
			} `json:"accounts"`
		} `json:"viewer"`
	}
	vars := map[string]any{"accountTag": accountTag, "start": rfc3339(start), "end": rfc3339(end)}
	if err := c.GraphQL(ctx, DatasetAccountOverview, accountOverviewQuery, vars, &out); err != nil {
		return AccountStats{}, err
	}
	var st AccountStats
	if len(out.Viewer.Accounts) == 0 {
		return st, nil
	}
	for _, g := range out.Viewer.Accounts[0].Groups {
		st.Requests += g.Sum.Requests
		st.CachedRequests += g.Sum.CachedRequests
		st.Bytes += g.Sum.Bytes
		st.CachedBytes += g.Sum.CachedBytes
	}
	return st, nil
}

// ------------------------------------------------------------- helpers ----

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// splitWindow splits [start, end) into consecutive windows no longer than
// max. A non-positive max returns the window unchanged.
func splitWindow(start, end time.Time, max time.Duration) [][2]time.Time {
	if max <= 0 || end.Sub(start) <= max {
		return [][2]time.Time{{start, end}}
	}
	var out [][2]time.Time
	for s := start; s.Before(end); s = s.Add(max) {
		e := s.Add(max)
		if e.After(end) {
			e = end
		}
		out = append(out, [2]time.Time{s, e})
	}
	return out
}
