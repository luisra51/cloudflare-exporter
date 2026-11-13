package collector

import (
	"context"

	"github.com/luisra51/cloudflare-exporter/internal/cloudflare"
)

type tunnelState struct {
	tunnel     cloudflare.Tunnel
	connectors []cloudflare.Connector
	// fromAPI is true when connectors come from the connections endpoint;
	// otherwise they are rebuilt from the list response.
	fromAPI bool
}

// collectTunnels lists the tunnels of an account and their connectors.
// On a failed list the previous tunnels are kept and the dataset is marked
// down. A missing permission is logged once per account.
func (c *Collector) collectTunnels(ctx context.Context, accountID string) bool {
	tunnels, err := c.api.ListTunnels(ctx, accountID)
	c.setStatus(statusKey{"account", accountID, dsTunnels}, err == nil, c.opts.Now())
	if err != nil {
		if cloudflare.IsAuthError(err) {
			c.mu.Lock()
			warned := c.tunnelWarned[accountID]
			c.tunnelWarned[accountID] = true
			c.mu.Unlock()
			if !warned {
				c.log.Warn("the API token cannot read Cloudflare Tunnels; add the permission Account > Cloudflare Tunnel > Read, or set CF_TUNNEL_METRICS=false",
					"account", accountID, "err", err)
			}
		} else {
			c.log.Warn("tunnel list failed", "account", accountID, "err", err)
		}
		return false
	}

	states := make([]tunnelState, 0, len(tunnels))
	connectorsOK := true
	for _, t := range tunnels {
		st := tunnelState{tunnel: t}
		conns, err := c.api.TunnelConnectors(ctx, accountID, t)
		if err != nil {
			connectorsOK = false
			c.log.Debug("tunnel connections query failed; using the list response", "account", accountID, "tunnel", t.Name, "err", err)
			st.connectors = connectorsFromList(t)
		} else {
			st.connectors, st.fromAPI = conns, true
		}
		states = append(states, st)
	}
	if len(tunnels) > 0 {
		c.setStatus(statusKey{"account", accountID, dsConnects}, connectorsOK, c.opts.Now())
	}

	c.mu.Lock()
	c.tunnels[accountID] = states
	c.mu.Unlock()
	return connectorsOK
}

// connectorsFromList groups the (deprecated) embedded connections of a
// tunnel by client_id.
func connectorsFromList(t cloudflare.Tunnel) []cloudflare.Connector {
	idx := map[string]int{}
	var out []cloudflare.Connector
	for _, conn := range t.Connections {
		i, ok := idx[conn.ClientID]
		if !ok {
			i = len(out)
			idx[conn.ClientID] = i
			out = append(out, cloudflare.Connector{ID: conn.ClientID, Version: conn.ClientVersion})
		}
		out[i].Conns = append(out[i].Conns, conn)
	}
	return out
}
