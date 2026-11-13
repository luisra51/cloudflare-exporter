// Package collector runs the background collection loop and serves the
// cached results as Prometheus metrics. Cloudflare is never called from a
// scrape: /metrics always reads the last snapshot.
package collector

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luisra51/cloudflare-exporter/internal/cloudflare"
	"github.com/prometheus/client_golang/prometheus"
)

// API is the subset of the Cloudflare client used by the collector.
type API interface {
	ListZones(ctx context.Context, accountID string) ([]cloudflare.Zone, error)
	GetZone(ctx context.Context, id string) (cloudflare.Zone, error)
	GetAccount(ctx context.Context, id string) (cloudflare.Ref, error)
	ZoneSettings(ctx context.Context, zoneTag string) (cloudflare.ZoneSettings, error)
	ZoneHTTP1h(ctx context.Context, zoneTag string, start, end time.Time) (cloudflare.HTTPStats, error)
	ZoneFirewallEvents(ctx context.Context, zoneTag string, start, end time.Time, s cloudflare.ZoneSettings) (cloudflare.FirewallStats, error)
	AccountHTTPOverview(ctx context.Context, accountTag string, start, end time.Time) (cloudflare.AccountStats, error)
}

// Options configures the collector.
type Options struct {
	Zones          []string
	ExcludeZones   []string
	Accounts       []string
	Interval       time.Duration
	HourlyDelay    time.Duration
	TopCountries   int
	FirewallEvents bool
	AccountMetrics bool
	SettingsTTL    time.Duration // default 6h
	Now            func() time.Time
}

// Dataset names used in self-metrics labels.
const (
	dsZones    = "zones"
	dsSettings = cloudflare.DatasetSettings
	dsHTTP     = cloudflare.DatasetHTTP1h
	dsFirewall = "firewallEvents"
	dsAccount  = cloudflare.DatasetAccountOverview
)

type statusKey struct{ scope, target, dataset string }

type status struct {
	up          bool
	lastSuccess time.Time
}

type settingsEntry struct {
	s       cloudflare.ZoneSettings
	fetched time.Time
}

type zoneState struct {
	zone       cloudflare.Zone
	http       *cloudflare.HTTPStats
	httpWindow time.Time
	fw         *cloudflare.FirewallStats
	fwWindow   time.Time
}

type accountState struct {
	id, name string
	stats    *cloudflare.AccountStats
	window   time.Time
}

// Collector implements prometheus.Collector over a cached snapshot.
type Collector struct {
	api  API
	opts Options
	log  *slog.Logger

	mu           sync.Mutex
	zones        map[string]*zoneState
	accounts     map[string]*accountState
	accountNames map[string]string
	settings     map[string]settingsEntry
	statuses     map[statusKey]*status
	lastRun      time.Time
	discoveryOK  bool

	snapshot atomic.Pointer[[]prometheus.Metric]

	duration    prometheus.Gauge
	collections *prometheus.CounterVec
}

// New builds a collector. Register it, plus SelfMetrics(), with a registry.
func New(api API, opts Options, log *slog.Logger) *Collector {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.SettingsTTL <= 0 {
		opts.SettingsTTL = 6 * time.Hour
	}
	c := &Collector{
		api:          api,
		opts:         opts,
		log:          log,
		zones:        map[string]*zoneState{},
		accounts:     map[string]*accountState{},
		accountNames: map[string]string{},
		settings:     map[string]settingsEntry{},
		statuses:     map[statusKey]*status{},
		duration: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cloudflare_exporter_collection_duration_seconds",
			Help: "Duration of the last background collection cycle.",
		}),
		collections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cloudflare_exporter_collections_total",
			Help: "Background collection cycles by result (success, partial, failure).",
		}, []string{"result"}),
	}
	empty := []prometheus.Metric{}
	c.snapshot.Store(&empty)
	return c
}

// SelfMetrics returns the regular collectors owned by the collector.
func (c *Collector) SelfMetrics() []prometheus.Collector {
	return []prometheus.Collector{c.duration, c.collections}
}

// Describe implements prometheus.Collector. The collector is "unchecked":
// its metric set depends on what Cloudflare returns.
func (c *Collector) Describe(chan<- *prometheus.Desc) {}

// Collect implements prometheus.Collector by replaying the last snapshot.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, m := range *c.snapshot.Load() {
		ch <- m
	}
}

// Run collects immediately and then every Interval until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) {
	c.CollectOnce(ctx)
	t := time.NewTicker(c.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.CollectOnce(ctx)
		}
	}
}

// Window returns the last complete hour that is at least HourlyDelay old.
func (c *Collector) Window() (start, end time.Time) {
	end = c.opts.Now().UTC().Add(-c.opts.HourlyDelay).Truncate(time.Hour)
	return end.Add(-time.Hour), end
}

// CollectOnce runs one collection cycle and publishes a new snapshot.
func (c *Collector) CollectOnce(ctx context.Context) {
	began := c.opts.Now()
	start, end := c.Window()

	zones, err := c.discover(ctx)
	c.setStatus(statusKey{"exporter", "", dsZones}, err == nil, began)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		c.log.Error("zone discovery failed; serving previous data", "err", err)
		c.collections.WithLabelValues("failure").Inc()
		c.publish()
		return
	}

	c.mu.Lock()
	c.discoveryOK = true
	keep := map[string]bool{}
	for _, z := range zones {
		keep[z.ID] = true
		if st, ok := c.zones[z.ID]; ok {
			st.zone = z
		} else {
			c.zones[z.ID] = &zoneState{zone: z}
		}
		if z.Account.ID != "" && z.Account.Name != "" {
			c.accountNames[z.Account.ID] = z.Account.Name
		}
	}
	for id := range c.zones {
		if !keep[id] {
			delete(c.zones, id)
			delete(c.settings, id)
			c.dropStatuses("zone", id)
		}
	}
	c.mu.Unlock()

	var failed atomic.Int32
	var wg sync.WaitGroup
	for _, z := range zones {
		wg.Add(1)
		go func(z cloudflare.Zone) {
			defer wg.Done()
			if !c.collectZone(ctx, z, start, end) {
				failed.Add(1)
			}
		}(z)
	}
	if c.opts.AccountMetrics {
		for _, id := range c.accountIDs(ctx, zones) {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				if !c.collectAccount(ctx, id, start, end) {
					failed.Add(1)
				}
			}(id)
		}
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	elapsed := c.opts.Now().Sub(began)
	c.duration.Set(elapsed.Seconds())
	result := "success"
	if failed.Load() > 0 {
		result = "partial"
	}
	c.collections.WithLabelValues(result).Inc()
	c.mu.Lock()
	c.lastRun = c.opts.Now()
	c.mu.Unlock()
	c.publish()
	c.log.Info("collection finished", "zones", len(zones), "window_start", start.Format(time.RFC3339),
		"failed_targets", failed.Load(), "duration", elapsed.Round(time.Millisecond).String())
}

func (c *Collector) discover(ctx context.Context) ([]cloudflare.Zone, error) {
	var zones []cloudflare.Zone
	if len(c.opts.Zones) > 0 {
		var errs []error
		for _, id := range c.opts.Zones {
			z, err := c.api.GetZone(ctx, id)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			zones = append(zones, z)
		}
		if len(zones) == 0 && len(errs) > 0 {
			return nil, errors.Join(errs...)
		}
		for _, err := range errs {
			c.log.Warn("could not read configured zone", "err", err)
		}
	} else if len(c.opts.Accounts) > 0 {
		for _, a := range c.opts.Accounts {
			zs, err := c.api.ListZones(ctx, a)
			if err != nil {
				return nil, err
			}
			zones = append(zones, zs...)
		}
	} else {
		zs, err := c.api.ListZones(ctx, "")
		if err != nil {
			return nil, err
		}
		zones = zs
	}

	out := zones[:0]
	seen := map[string]bool{}
	for _, z := range zones {
		if seen[z.ID] || slices.Contains(c.opts.ExcludeZones, z.ID) {
			continue
		}
		if len(c.opts.Accounts) > 0 && !slices.Contains(c.opts.Accounts, z.Account.ID) {
			continue
		}
		seen[z.ID] = true
		out = append(out, z)
	}
	return out, nil
}

func (c *Collector) zoneSettings(ctx context.Context, z cloudflare.Zone) cloudflare.ZoneSettings {
	now := c.opts.Now()
	c.mu.Lock()
	e, ok := c.settings[z.ID]
	c.mu.Unlock()
	if ok && now.Sub(e.fetched) < c.opts.SettingsTTL {
		return e.s
	}
	s, err := c.api.ZoneSettings(ctx, z.ID)
	c.setStatus(statusKey{"zone", z.ID, dsSettings}, err == nil, now)
	if err != nil {
		c.log.Warn("could not read dataset settings; assuming Free-plan defaults", "zone", z.Name, "err", err)
		if ok {
			return e.s
		}
		return cloudflare.DefaultZoneSettings()
	}
	c.mu.Lock()
	c.settings[z.ID] = settingsEntry{s: s, fetched: now}
	c.mu.Unlock()
	return s
}

func (c *Collector) collectZone(ctx context.Context, z cloudflare.Zone, start, end time.Time) bool {
	s := c.zoneSettings(ctx, z)
	ok := true

	if s.HTTP1h.Enabled {
		st, err := c.api.ZoneHTTP1h(ctx, z.ID, start, end)
		c.setStatus(statusKey{"zone", z.ID, dsHTTP}, err == nil, c.opts.Now())
		if err != nil {
			ok = false
			c.log.Warn("http analytics query failed", "zone", z.Name, "err", err)
		} else {
			c.mu.Lock()
			if zs := c.zones[z.ID]; zs != nil {
				zs.http, zs.httpWindow = &st, start
			}
			c.mu.Unlock()
		}
	}

	if c.opts.FirewallEvents {
		st, err := c.api.ZoneFirewallEvents(ctx, z.ID, start, end, s)
		switch {
		case errors.Is(err, cloudflare.ErrDatasetUnavailable):
			c.log.Debug("firewall events not available for zone", "zone", z.Name)
		case err != nil:
			ok = false
			c.setStatus(statusKey{"zone", z.ID, dsFirewall}, false, c.opts.Now())
			c.log.Warn("firewall events query failed", "zone", z.Name, "err", err)
		default:
			c.setStatus(statusKey{"zone", z.ID, dsFirewall}, true, c.opts.Now())
			if st.Truncated {
				c.log.Warn("firewall events truncated; counts are a lower bound", "zone", z.Name, "queries", st.Queries)
			}
			c.mu.Lock()
			if zs := c.zones[z.ID]; zs != nil {
				zs.fw, zs.fwWindow = &st, start
			}
			c.mu.Unlock()
		}
	}
	return ok
}

func (c *Collector) accountIDs(ctx context.Context, zones []cloudflare.Zone) []string {
	ids := slices.Clone(c.opts.Accounts)
	if len(ids) == 0 {
		for _, z := range zones {
			if z.Account.ID != "" && !slices.Contains(ids, z.Account.ID) {
				ids = append(ids, z.Account.ID)
			}
		}
	}
	for _, id := range ids {
		c.mu.Lock()
		_, known := c.accountNames[id]
		c.mu.Unlock()
		if known {
			continue
		}
		name := id
		if a, err := c.api.GetAccount(ctx, id); err == nil && a.Name != "" {
			name = a.Name
		}
		c.mu.Lock()
		c.accountNames[id] = name
		c.mu.Unlock()
	}
	c.mu.Lock()
	for id := range c.accounts {
		if !slices.Contains(ids, id) {
			delete(c.accounts, id)
			c.dropStatuses("account", id)
		}
	}
	c.mu.Unlock()
	return ids
}

func (c *Collector) collectAccount(ctx context.Context, id string, start, end time.Time) bool {
	st, err := c.api.AccountHTTPOverview(ctx, id, start, end)
	c.setStatus(statusKey{"account", id, dsAccount}, err == nil, c.opts.Now())
	if err != nil {
		c.log.Warn("account analytics query failed", "account", id, "err", err)
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	as := c.accounts[id]
	if as == nil {
		as = &accountState{id: id}
		c.accounts[id] = as
	}
	as.name = c.accountNames[id]
	as.stats, as.window = &st, start
	return true
}

func (c *Collector) setStatus(k statusKey, up bool, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.statuses[k]
	if s == nil {
		s = &status{}
		c.statuses[k] = s
	}
	s.up = up
	if up {
		s.lastSuccess = at
	}
}

// dropStatuses must be called with c.mu held.
func (c *Collector) dropStatuses(scope, target string) {
	for k := range c.statuses {
		if k.scope == scope && k.target == target {
			delete(c.statuses, k)
		}
	}
}

// Healthy reports whether the exporter has completed at least one zone
// discovery, and when the last full cycle finished.
func (c *Collector) Healthy() (ok bool, lastRun time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.discoveryOK, c.lastRun
}
