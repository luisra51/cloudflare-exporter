package collector

import (
	"context"
	"errors"
	"time"

	"github.com/luisra51/cloudflare-exporter/internal/cloudflare"
)

// Dataset names for the optional feature groups.
const (
	dsHosts         = cloudflare.DatasetHTTPAdaptive
	dsCerts         = "certificate_packs"
	dsServiceTokens = "access_service_tokens"
	dsDevices       = "devices"
	dsGatewayDNS    = cloudflare.DatasetGatewayDNS
	dsAccessLogins  = cloudflare.DatasetAccessLogins
)

// Permissions named in the "missing permission" warnings.
var permissionHint = map[string]string{
	dsHosts:         "Zone > Analytics > Read",
	dsCerts:         "Zone > SSL and Certificates > Read",
	dsServiceTokens: "Account > Access: Service Tokens > Read",
	dsDevices:       "Account > Zero Trust > Read",
	dsGatewayDNS:    "Account > Account Analytics > Read (and Zero Trust Gateway in use)",
	dsAccessLogins:  "Account > Account Analytics > Read (and Cloudflare Access in use)",
}

// #nosec G101 -- setting names, not credentials
var disableHint = map[string]string{
	dsHosts:         "CF_HOST_METRICS=false",
	dsCerts:         "CF_CERT_METRICS=false",
	dsServiceTokens: "CF_ZEROTRUST_METRICS=false",
	dsDevices:       "CF_ZEROTRUST_METRICS=false",
	dsGatewayDNS:    "CF_ZEROTRUST_METRICS=false",
	dsAccessLogins:  "CF_ZEROTRUST_METRICS=false",
}

type ztState struct {
	tokens   []cloudflare.ServiceToken
	tokensOK bool

	devices     *cloudflare.DeviceSummary
	devicesLast time.Time // last successful devices collection

	gateway   map[string]float64
	logins    map[string]float64
	gwWindow  [2]time.Time
	accWindow [2]time.Time
}

// AdaptiveWindow returns the rolling window used for the adaptive (near
// real-time) datasets: AdaptiveWindow long, ending AdaptiveDelay ago,
// aligned to the minute.
func (c *Collector) AdaptiveWindow() (start, end time.Time) {
	end = c.opts.Now().UTC().Add(-c.opts.AdaptiveDelay).Truncate(time.Minute)
	return end.Add(-c.opts.AdaptiveWindow), end
}

// report records the result of one dataset collection. An "unavailable"
// error (missing permission, or dataset not offered to this plan) is
// logged once per target; other errors are logged every time.
func (c *Collector) report(scope, id, name, dataset string, err error) bool {
	c.setStatus(statusKey{scope, id, dataset}, err == nil, c.opts.Now())
	if err == nil {
		return true
	}
	if cloudflare.IsUnavailableError(err) {
		key := scope + "/" + id + "/" + dataset
		c.mu.Lock()
		warned := c.warned[key]
		c.warned[key] = true
		c.mu.Unlock()
		if !warned {
			c.log.Warn("dataset not readable with this token; add the permission "+permissionHint[dataset]+", or set "+disableHint[dataset],
				scope, name, "dataset", dataset, "err", err)
		}
		return false
	}
	c.log.Warn("query failed", scope, name, "dataset", dataset, "err", err)
	return false
}

func (c *Collector) collectHosts(ctx context.Context, z cloudflare.Zone, s cloudflare.ZoneSettings) bool {
	start, end := c.AdaptiveWindow()
	st, err := c.api.ZoneHostTraffic(ctx, z.ID, start, end, s.HTTPAdaptive)
	if errors.Is(err, cloudflare.ErrDatasetUnavailable) {
		c.log.Debug("httpRequestsAdaptiveGroups not available for zone", "zone", z.Name)
		return true
	}
	if !c.report("zone", z.ID, z.Name, dsHosts, err) {
		return false
	}
	if st.Truncated {
		c.log.Warn("per-host traffic truncated; counts are a lower bound", "zone", z.Name, "queries", st.Queries)
	}
	c.mu.Lock()
	if zs := c.zones[z.ID]; zs != nil {
		zs.hosts, zs.hostsWindow = &st, [2]time.Time{start, end}
	}
	c.mu.Unlock()
	return true
}

func (c *Collector) collectCerts(ctx context.Context, z cloudflare.Zone) bool {
	packs, err := c.api.CertificatePacks(ctx, z.ID)
	if !c.report("zone", z.ID, z.Name, dsCerts, err) {
		return false
	}
	c.mu.Lock()
	if zs := c.zones[z.ID]; zs != nil {
		zs.certs, zs.certsOK = packs, true
	}
	c.mu.Unlock()
	return true
}

func (c *Collector) collectZeroTrust(ctx context.Context, accountID string) bool {
	c.mu.Lock()
	st := c.zt[accountID]
	if st == nil {
		st = &ztState{}
		c.zt[accountID] = st
	}
	name := c.accountNames[accountID]
	devicesLast := st.devicesLast
	c.mu.Unlock()
	if name == "" {
		name = accountID
	}
	ok := true

	tokens, err := c.api.ServiceTokens(ctx, accountID)
	if c.report("account", accountID, name, dsServiceTokens, err) {
		c.mu.Lock()
		st.tokens, st.tokensOK = tokens, true
		c.mu.Unlock()
	} else {
		ok = false
	}

	now := c.opts.Now()
	if devicesLast.IsZero() || now.Sub(devicesLast) >= c.opts.DevicesInterval {
		devs, err := c.api.Devices(ctx, accountID, now)
		if c.report("account", accountID, name, dsDevices, err) {
			c.mu.Lock()
			st.devices, st.devicesLast = &devs, now
			c.mu.Unlock()
		} else {
			ok = false
		}
	}

	start, end := c.AdaptiveWindow()
	gw, err := c.api.GatewayDNSQueries(ctx, accountID, start, end)
	if c.report("account", accountID, name, dsGatewayDNS, err) {
		c.mu.Lock()
		st.gateway, st.gwWindow = gw, [2]time.Time{start, end}
		c.mu.Unlock()
	} else {
		ok = false
	}

	logins, err := c.api.AccessLogins(ctx, accountID, start, end)
	if c.report("account", accountID, name, dsAccessLogins, err) {
		c.mu.Lock()
		st.logins, st.accWindow = logins, [2]time.Time{start, end}
		c.mu.Unlock()
	} else {
		ok = false
	}
	return ok
}
