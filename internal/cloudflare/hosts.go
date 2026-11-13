package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// availableFields returns settings.<dataset>.availableFields for a zone.
func (c *Client) availableFields(ctx context.Context, zoneTag, dataset string) ([]string, error) {
	q := fmt.Sprintf(`query ZoneAvailableFields($zoneTag: String!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      settings {
        %s { availableFields }
      }
    }
  }
}`, dataset)
	var out struct {
		Viewer struct {
			Zones []struct {
				Settings map[string]struct {
					AvailableFields []string `json:"availableFields"`
				} `json:"settings"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	if err := c.GraphQL(ctx, DatasetSettings, q, map[string]any{"zoneTag": zoneTag}, &out); err != nil {
		return nil, err
	}
	if len(out.Viewer.Zones) == 0 {
		return nil, errors.New("settings: zone not returned")
	}
	return out.Viewer.Zones[0].Settings[dataset].AvailableFields, nil
}

// HasField reports whether a dataset field is listed in availableFields.
// kind is "" for dimensions, or "sum"/"avg" for aggregates. Matching is
// lenient about how Cloudflare spells the path.
func (n NodeSettings) HasField(kind, name string) bool {
	for _, f := range n.AvailableFields {
		switch f {
		case name, kind + "_" + name, kind + "." + name, "dimensions_" + name, "dimensions." + name:
			return true
		}
	}
	return false
}

// HostKey identifies one host and edge status.
type HostKey struct {
	Host   string
	Status int
}

// HostStats is per-host traffic over a short window of the adaptive
// (sampled) dataset. Counts are Cloudflare's sample-adjusted estimates.
type HostStats struct {
	Requests map[HostKey]float64
	// Optional fields, filled only when the zone may query them.
	HasBytes  bool
	Bytes     map[string]float64
	HasOrigin bool
	Origin5xx map[string]float64
	// OriginRequests counts requests that reached the origin
	// (originResponseStatus > 0).
	OriginRequests map[string]float64
	HasOriginTime  bool
	// OriginTimeSum is avg(originResponseDurationMs) weighted by count,
	// summed per host; divide by OriginTimeWeight for the average.
	OriginTimeSum    map[string]float64
	OriginTimeWeight map[string]float64

	Truncated bool
	Queries   int
}

// hostQueryOptions selects the optional fields of the host query.
type hostQueryOptions struct {
	bytes, origin, originTime bool
}

func (o hostQueryOptions) any() bool { return o.bytes || o.origin || o.originTime }

func hostQuery(limit int, o hostQueryOptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, `query ZoneHostTraffic($zoneTag: String!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      httpRequestsAdaptiveGroups(limit: %d, filter: {datetime_geq: $start, datetime_lt: $end}) {
        count
        dimensions {
          clientRequestHTTPHost
          edgeResponseStatus
`, limit)
	if o.origin {
		b.WriteString("          originResponseStatus\n")
	}
	b.WriteString("        }\n")
	if o.bytes {
		b.WriteString("        sum { edgeResponseBytes }\n")
	}
	if o.originTime {
		b.WriteString("        avg { originResponseDurationMs }\n")
	}
	b.WriteString("      }\n    }\n  }\n}")
	return b.String()
}

// maxHostQueries caps the queries spent on one zone and window.
const maxHostQueries = 16

// ZoneHostTraffic returns per-host traffic in [start, end) from
// httpRequestsAdaptiveGroups. Optional fields (bytes, origin status, origin
// response time) are requested only if the settings node lists them; if
// Cloudflare still refuses the query, it is retried without them. A window
// that returns a full page is split in halves (down to one minute).
func (c *Client) ZoneHostTraffic(ctx context.Context, zoneTag string, start, end time.Time, ns NodeSettings) (HostStats, error) {
	if !ns.Enabled {
		return HostStats{}, ErrDatasetUnavailable
	}
	opts := hostQueryOptions{
		bytes:  ns.HasField("sum", "edgeResponseBytes"),
		origin: ns.HasField("", "originResponseStatus"),
		// The origin time is only meaningful per origin status: groups that
		// never reached the origin report originResponseStatus 0 and an
		// average of -1, so it needs the origin dimension to filter them.
		originTime: ns.HasField("avg", "originResponseDurationMs") && ns.HasField("", "originResponseStatus"),
	}
	limit := ns.MaxPageSize
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	st, err := c.hostTraffic(ctx, zoneTag, start, end, ns, limit, opts)
	var gqlErr GraphQLErrors
	if err != nil && opts.any() && errors.As(err, &gqlErr) {
		st, err = c.hostTraffic(ctx, zoneTag, start, end, ns, limit, hostQueryOptions{})
	}
	return st, err
}

func (c *Client) hostTraffic(ctx context.Context, zoneTag string, start, end time.Time, ns NodeSettings, limit int, o hostQueryOptions) (HostStats, error) {
	st := HostStats{
		Requests: map[HostKey]float64{}, Bytes: map[string]float64{}, Origin5xx: map[string]float64{}, OriginRequests: map[string]float64{},
		OriginTimeSum: map[string]float64{}, OriginTimeWeight: map[string]float64{},
		HasBytes: o.bytes, HasOrigin: o.origin, HasOriginTime: o.originTime,
	}
	query := hostQuery(limit, o)
	for _, w := range splitWindow(start, end, time.Duration(ns.MaxDuration)*time.Second) {
		if err := c.hostWindow(ctx, zoneTag, w[0], w[1], query, limit, &st); err != nil {
			return st, err
		}
	}
	return st, nil
}

type hostGroup struct {
	Count      float64 `json:"count"`
	Dimensions struct {
		Host         string      `json:"clientRequestHTTPHost"`
		EdgeStatus   json.Number `json:"edgeResponseStatus"`
		OriginStatus json.Number `json:"originResponseStatus"`
	} `json:"dimensions"`
	Sum struct {
		EdgeResponseBytes float64 `json:"edgeResponseBytes"`
	} `json:"sum"`
	Avg struct {
		OriginResponseDurationMs float64 `json:"originResponseDurationMs"`
	} `json:"avg"`
}

func (c *Client) hostWindow(ctx context.Context, zoneTag string, start, end time.Time, query string, limit int, st *HostStats) error {
	var out struct {
		Viewer struct {
			Zones []struct {
				Groups []hostGroup `json:"httpRequestsAdaptiveGroups"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	vars := map[string]any{"zoneTag": zoneTag, "start": rfc3339(start), "end": rfc3339(end)}
	st.Queries++
	if err := c.GraphQL(ctx, DatasetHTTPAdaptive, query, vars, &out); err != nil {
		return err
	}
	if len(out.Viewer.Zones) == 0 {
		return nil
	}
	groups := out.Viewer.Zones[0].Groups
	if len(groups) >= limit {
		half := end.Sub(start) / 2
		if half >= time.Minute && st.Queries+2 <= maxHostQueries {
			mid := start.Add(half).Truncate(time.Second)
			if err := c.hostWindow(ctx, zoneTag, start, mid, query, limit, st); err != nil {
				return err
			}
			return c.hostWindow(ctx, zoneTag, mid, end, query, limit, st)
		}
		st.Truncated = true
	}
	for _, g := range groups {
		host := strings.ToLower(g.Dimensions.Host)
		if host == "" {
			host = "unknown"
		}
		status, _ := g.Dimensions.EdgeStatus.Int64()
		st.Requests[HostKey{Host: host, Status: int(status)}] += g.Count
		if st.HasBytes {
			st.Bytes[host] += g.Sum.EdgeResponseBytes
		}
		var originStatus int64
		if st.HasOrigin {
			originStatus, _ = g.Dimensions.OriginStatus.Int64()
			if originStatus > 0 {
				st.OriginRequests[host] += g.Count
			}
			if originStatus >= 500 && originStatus <= 599 {
				st.Origin5xx[host] += g.Count
			}
		}
		// Only groups that reached the origin carry a real origin time;
		// the others report -1.
		if st.HasOriginTime && originStatus > 0 && g.Count > 0 && g.Avg.OriginResponseDurationMs >= 0 {
			st.OriginTimeSum[host] += g.Avg.OriginResponseDurationMs * g.Count
			st.OriginTimeWeight[host] += g.Count
		}
	}
	return nil
}
