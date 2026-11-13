package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Account-scoped GraphQL datasets used for Zero Trust.
const (
	DatasetGatewayDNS   = "gatewayResolverQueriesAdaptiveGroups"
	DatasetAccessLogins = "accessLoginRequestsAdaptiveGroups"
)

// IsUnavailableError reports whether err means the dataset or endpoint is
// not readable with this token or plan: a REST auth error, or a GraphQL
// error about authorization or access to the path.
func IsUnavailableError(err error) bool {
	if IsAuthError(err) {
		return true
	}
	var g GraphQLErrors
	if errors.As(err, &g) {
		for _, e := range g {
			m := strings.ToLower(e.Message)
			if strings.Contains(m, "authz") || strings.Contains(m, "not authorized") ||
				strings.Contains(m, "permission") || strings.Contains(m, "does not have access") ||
				strings.Contains(m, "unauthorized") {
				return true
			}
		}
	}
	return false
}

// paginate fetches page after page of a REST list endpoint and passes each
// page's raw result to add, which returns the number of items it decoded.
func (c *Client) paginate(ctx context.Context, op, path string, q url.Values, perPage int, add func(json.RawMessage) (int, error)) error {
	for page := 1; ; page++ {
		q.Set("page", strconv.Itoa(page))
		q.Set("per_page", strconv.Itoa(perPage))
		env, err := c.restGet(ctx, op, path+"?"+q.Encode())
		if err != nil {
			return err
		}
		n, err := add(env.Result)
		if err != nil {
			c.noteError("rest", op)
			return fmt.Errorf("decode %s: %w", op, err)
		}
		if n < perPage {
			return nil
		}
		if ri := env.ResultInfo; ri != nil {
			if ri.TotalPages > 0 && page >= ri.TotalPages {
				return nil
			}
			if ri.TotalCount > 0 && page*perPage >= ri.TotalCount {
				return nil
			}
		}
	}
}

// ------------------------------------------------- Access service tokens --

// ServiceToken is an Access service token. The client ID is deliberately
// not decoded.
type ServiceToken struct {
	ID         string
	Name       string
	ExpiresAt  time.Time // zero if unknown
	LastSeenAt time.Time // zero if never or not reported
}

// ServiceTokens lists the Access service tokens of an account.
func (c *Client) ServiceTokens(ctx context.Context, accountID string) ([]ServiceToken, error) {
	var out []ServiceToken
	err := c.paginate(ctx, "access_service_tokens", "/accounts/"+url.PathEscape(accountID)+"/access/service_tokens", url.Values{}, 1000,
		func(raw json.RawMessage) (int, error) {
			var items []struct {
				ID         string  `json:"id"`
				Name       string  `json:"name"`
				ExpiresAt  *string `json:"expires_at"`
				LastSeenAt *string `json:"last_seen_at"`
			}
			if err := json.Unmarshal(raw, &items); err != nil {
				return 0, err
			}
			for _, t := range items {
				out = append(out, ServiceToken{ID: t.ID, Name: t.Name, ExpiresAt: parseTime(t.ExpiresAt), LastSeenAt: parseTime(t.LastSeenAt)})
			}
			return len(items), nil
		})
	return out, err
}

// ------------------------------------------------------------ devices ----

// DeviceSummary aggregates the WARP devices of an account. Only counts are
// kept: no per-device data.
type DeviceSummary struct {
	Total      float64
	ByLastSeen map[string]float64 // "24h", "7d", "30d", "older", "never"
	ByOS       map[string]float64
}

// DeviceLastSeenBuckets are the last-seen buckets, exclusive: "7d" means between 24 hours and 7 days.
var DeviceLastSeenBuckets = []string{"24h", "7d", "30d", "older", "never"}

const devicesPerPage = 1000

// Devices summarises the WARP devices of an account from
// /accounts/{id}/devices. now is used for the last-seen buckets.
func (c *Client) Devices(ctx context.Context, accountID string, now time.Time) (DeviceSummary, error) {
	sum := DeviceSummary{ByLastSeen: map[string]float64{}, ByOS: map[string]float64{}}
	for _, b := range DeviceLastSeenBuckets {
		sum.ByLastSeen[b] = 0
	}
	path := "/accounts/" + url.PathEscape(accountID) + "/devices"
	add := func(raw json.RawMessage) (int, error) {
		var items []struct {
			LastSeen   *string `json:"last_seen"`
			DeviceType string  `json:"device_type"`
		}
		if err := json.Unmarshal(raw, &items); err != nil {
			return 0, err
		}
		for _, d := range items {
			sum.Total++
			os := strings.ToLower(d.DeviceType)
			if os == "" {
				os = "unknown"
			}
			sum.ByOS[os]++
			sum.ByLastSeen[lastSeenBucket(parseTime(d.LastSeen), now)]++
		}
		return len(items), nil
	}
	err := c.paginate(ctx, "devices", path, url.Values{}, devicesPerPage, add)
	var apiErr *APIError
	if err != nil && errors.As(err, &apiErr) && apiErr.Status == http.StatusBadRequest && sum.Total == 0 {
		// Some accounts reject large pages; retry with a conservative size.
		err = c.paginate(ctx, "devices", path, url.Values{}, 100, add)
	}
	return sum, err
}

func lastSeenBucket(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	switch age := now.Sub(t); {
	case age < 24*time.Hour:
		return "24h"
	case age < 7*24*time.Hour:
		return "7d"
	case age < 30*24*time.Hour:
		return "30d"
	default:
		return "older"
	}
}

// ------------------------------------------------- Gateway / Access GQL --

// GatewayDecisionNames maps documented Gateway DNS resolver decision codes
// to their names.
var GatewayDecisionNames = map[string]string{
	"3": "blockedByCategory", "4": "allowedOnNoLocation", "5": "allowedOnNoPolicyMatch",
	"6": "blockedAlwaysCategory", "7": "overrideForSafeSearch", "8": "overrideApplied",
	"9": "blockedRule", "10": "allowedRule",
}

const gatewayDNSQuery = `query GatewayDNS($accountTag: String!, $start: Time!, $end: Time!) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      gatewayResolverQueriesAdaptiveGroups(limit: 1000, filter: {datetime_geq: $start, datetime_lt: $end}) {
        count
        dimensions { resolverDecision }
      }
    }
  }
}`

// GatewayDNSQueries counts Gateway DNS queries in [start, end) by resolver
// decision code (as a string).
func (c *Client) GatewayDNSQueries(ctx context.Context, accountID string, start, end time.Time) (map[string]float64, error) {
	var out struct {
		Viewer struct {
			Accounts []struct {
				Groups []struct {
					Count      float64 `json:"count"`
					Dimensions struct {
						ResolverDecision json.RawMessage `json:"resolverDecision"`
					} `json:"dimensions"`
				} `json:"gatewayResolverQueriesAdaptiveGroups"`
			} `json:"accounts"`
		} `json:"viewer"`
	}
	vars := map[string]any{"accountTag": accountID, "start": rfc3339(start), "end": rfc3339(end)}
	if err := c.GraphQL(ctx, DatasetGatewayDNS, gatewayDNSQuery, vars, &out); err != nil {
		return nil, err
	}
	res := map[string]float64{}
	if len(out.Viewer.Accounts) == 0 {
		return res, nil
	}
	for _, g := range out.Viewer.Accounts[0].Groups {
		res[rawScalar(g.Dimensions.ResolverDecision)] += g.Count
	}
	return res, nil
}

const accessLoginsQuery = `query AccessLogins($accountTag: String!, $start: Time!, $end: Time!) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      accessLoginRequestsAdaptiveGroups(limit: 100, filter: {datetime_geq: $start, datetime_lt: $end}) {
        count
        dimensions { isSuccessfulLogin }
      }
    }
  }
}`

// AccessLogins counts Access login attempts in [start, end) as
// {"success": n, "failure": m}.
func (c *Client) AccessLogins(ctx context.Context, accountID string, start, end time.Time) (map[string]float64, error) {
	var out struct {
		Viewer struct {
			Accounts []struct {
				Groups []struct {
					Count      float64 `json:"count"`
					Dimensions struct {
						IsSuccessfulLogin json.RawMessage `json:"isSuccessfulLogin"`
					} `json:"dimensions"`
				} `json:"accessLoginRequestsAdaptiveGroups"`
			} `json:"accounts"`
		} `json:"viewer"`
	}
	vars := map[string]any{"accountTag": accountID, "start": rfc3339(start), "end": rfc3339(end)}
	if err := c.GraphQL(ctx, DatasetAccessLogins, accessLoginsQuery, vars, &out); err != nil {
		return nil, err
	}
	res := map[string]float64{"success": 0, "failure": 0}
	if len(out.Viewer.Accounts) == 0 {
		return res, nil
	}
	for _, g := range out.Viewer.Accounts[0].Groups {
		switch rawScalar(g.Dimensions.IsSuccessfulLogin) {
		case "1", "true":
			res["success"] += g.Count
		default:
			res["failure"] += g.Count
		}
	}
	return res, nil
}

// rawScalar renders a JSON scalar (number, string or bool) as a string.
func rawScalar(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if unq, err := strconv.Unquote(s); err == nil {
		return unq
	}
	if s == "" || s == "null" {
		return "unknown"
	}
	return s
}
