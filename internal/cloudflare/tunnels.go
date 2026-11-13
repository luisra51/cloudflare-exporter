package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Tunnel types the exporter reports on.
const (
	TunnelTypeCloudflared   = "cfd_tunnel"
	TunnelTypeWARPConnector = "warp_connector"
)

// Tunnel is the subset of a Cloudflare Tunnel object the exporter uses.
type Tunnel struct {
	ID              string
	Name            string
	Status          string
	Type            string
	ConfigSrc       string
	ConnsActiveAt   time.Time // zero if never active
	ConnsInactiveAt time.Time // zero if null
	// Connections embedded in the list response. Cloudflare has deprecated
	// this field and may return it empty; prefer TunnelConnectors.
	Connections []TunnelConn
}

// TunnelConn is one edge connection of a tunnel. The origin IP is
// deliberately not decoded.
type TunnelConn struct {
	ID                 string `json:"id"`
	ClientID           string `json:"client_id"`
	ClientVersion      string `json:"client_version"`
	ColoName           string `json:"colo_name"`
	IsPendingReconnect bool   `json:"is_pending_reconnect"`
}

// Connector is a running connector (a cloudflared or WARP Connector
// instance) and its edge connections.
type Connector struct {
	ID      string       `json:"id"`
	Arch    string       `json:"arch"`
	Version string       `json:"version"`
	Conns   []TunnelConn `json:"conns"`
}

type tunnelJSON struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	Status          string       `json:"status"`
	TunType         string       `json:"tun_type"`
	ConfigSrc       string       `json:"config_src"`
	ConnsActiveAt   *string      `json:"conns_active_at"`
	ConnsInactiveAt *string      `json:"conns_inactive_at"`
	Connections     []TunnelConn `json:"connections"`
}

func parseTime(s *string) time.Time {
	if s == nil || *s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (t tunnelJSON) toTunnel() Tunnel {
	typ := t.TunType
	if typ == "" {
		typ = TunnelTypeCloudflared
	}
	return Tunnel{
		ID: t.ID, Name: t.Name, Status: t.Status, Type: typ, ConfigSrc: t.ConfigSrc,
		ConnsActiveAt: parseTime(t.ConnsActiveAt), ConnsInactiveAt: parseTime(t.ConnsInactiveAt),
		Connections: t.Connections,
	}
}

const tunnelsPerPage = 100

// ListTunnels returns the non-deleted Cloudflare Tunnels (cloudflared) and
// WARP Connector tunnels of an account. It uses the generic
// /accounts/{id}/tunnels endpoint and falls back to /cfd_tunnel when that
// endpoint is not available. Other tunnel types (Magic, IPsec, GRE) are
// ignored.
func (c *Client) ListTunnels(ctx context.Context, accountID string) ([]Tunnel, error) {
	all, err := c.listTunnels(ctx, accountID, "tunnels")
	var apiErr *APIError
	if err != nil && errors.As(err, &apiErr) && !IsAuthError(err) &&
		(apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusBadRequest) {
		all, err = c.listTunnels(ctx, accountID, "cfd_tunnel")
	}
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, t := range all {
		if t.Type == TunnelTypeCloudflared || t.Type == TunnelTypeWARPConnector {
			out = append(out, t)
		}
	}
	return out, nil
}

func (c *Client) listTunnels(ctx context.Context, accountID, resource string) ([]Tunnel, error) {
	var all []Tunnel
	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("is_deleted", "false")
		q.Set("page", strconv.Itoa(page))
		q.Set("per_page", strconv.Itoa(tunnelsPerPage))
		env, err := c.restGet(ctx, "list_tunnels", "/accounts/"+url.PathEscape(accountID)+"/"+resource+"?"+q.Encode())
		if err != nil {
			return nil, err
		}
		var items []tunnelJSON
		if err := json.Unmarshal(env.Result, &items); err != nil {
			c.noteError("rest", "list_tunnels")
			return nil, fmt.Errorf("decode tunnels: %w", err)
		}
		for _, t := range items {
			all = append(all, t.toTunnel())
		}
		if len(items) < tunnelsPerPage {
			return all, nil
		}
		if env.ResultInfo != nil && env.ResultInfo.TotalPages > 0 && page >= env.ResultInfo.TotalPages {
			return all, nil
		}
		if env.ResultInfo != nil && env.ResultInfo.TotalCount > 0 && page*tunnelsPerPage >= env.ResultInfo.TotalCount {
			return all, nil
		}
	}
}

// TunnelConnectors returns the connectors of a tunnel and their edge
// connections, from /accounts/{id}/{tunnel_type}/{tunnel_id}/connections.
func (c *Client) TunnelConnectors(ctx context.Context, accountID string, t Tunnel) ([]Connector, error) {
	typ := t.Type
	if typ == "" {
		typ = TunnelTypeCloudflared
	}
	path := "/accounts/" + url.PathEscape(accountID) + "/" + url.PathEscape(typ) + "/" + url.PathEscape(t.ID) + "/connections"
	env, err := c.restGet(ctx, "tunnel_connections", path)
	if err != nil {
		return nil, err
	}
	var out []Connector
	if err := json.Unmarshal(env.Result, &out); err != nil {
		c.noteError("rest", "tunnel_connections")
		return nil, fmt.Errorf("decode tunnel connections: %w", err)
	}
	return out, nil
}
