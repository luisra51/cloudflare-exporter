package collector

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luisra51/cloudflare-exporter/internal/cftest"
	"github.com/luisra51/cloudflare-exporter/internal/cloudflare"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var fixedNow = time.Date(2026, 3, 1, 12, 7, 0, 0, time.UTC)

func setup(t *testing.T, fake *cftest.Fake, opts Options) (*Collector, *prometheus.Registry, *APIErrors) {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	apiErrs := NewAPIErrors()
	client := cloudflare.New(srv.URL, cftest.Token, cloudflare.WithRetry(0, 0), cloudflare.WithObserver(apiErrs))
	if opts.Interval == 0 {
		opts.Interval = time.Minute
	}
	if opts.HourlyDelay == 0 {
		opts.HourlyDelay = 10 * time.Minute
	}
	opts.Now = func() time.Time { return fixedNow }
	c := New(client, opts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c, apiErrs.Collector())
	reg.MustRegister(c.SelfMetrics()...)
	return c, reg, apiErrs
}

func gather(t *testing.T, reg *prometheus.Registry, names ...string) string {
	t.Helper()
	// testutil.CollectAndFormat-like output for selected families.
	var b strings.Builder
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		for _, n := range names {
			if mf.GetName() == n {
				b.WriteString(mf.String())
				b.WriteString("\n")
			}
		}
	}
	return b.String()
}

func TestWindowIsLastCompleteHourAfterDelay(t *testing.T) {
	c := New(nil, Options{HourlyDelay: 10 * time.Minute, Now: func() time.Time { return fixedNow }}, slog.Default())
	s, e := c.Window()
	// 12:07 minus 10m = 11:57 -> hour ending 11:00 is the last complete one.
	if !s.Equal(time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)) || !e.Equal(time.Date(2026, 3, 1, 11, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected window %s - %s", s, e)
	}
	c.opts.Now = func() time.Time { return time.Date(2026, 3, 1, 12, 15, 0, 0, time.UTC) }
	s, _ = c.Window()
	if s.Hour() != 11 {
		t.Fatalf("after the delay the 11:00 hour should be reported, got %s", s)
	}
}

func TestCollectFullCycle(t *testing.T) {
	fake := cftest.New()
	fake.FirewallEventsPerHour = 60
	c, reg, _ := setup(t, fake, Options{TopCountries: 2, FirewallEvents: true, AccountMetrics: true})
	c.CollectOnce(context.Background())

	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP cloudflare_zone_hourly_requests HTTP requests served by the edge during the last complete hour.
# TYPE cloudflare_zone_hourly_requests gauge
cloudflare_zone_hourly_requests{account="Example Account",zone="example.com"} 1000
cloudflare_zone_hourly_requests{account="Example Account",zone="example.net"} 1000
cloudflare_zone_hourly_requests{account="Example Account",zone="example.org"} 1000
# HELP cloudflare_zone_hourly_requests_by_country HTTP requests by client country during the last complete hour (top N countries, the rest as country="other").
# TYPE cloudflare_zone_hourly_requests_by_country gauge
cloudflare_zone_hourly_requests_by_country{account="Example Account",country="DE",zone="example.com"} 300
cloudflare_zone_hourly_requests_by_country{account="Example Account",country="DE",zone="example.net"} 300
cloudflare_zone_hourly_requests_by_country{account="Example Account",country="DE",zone="example.org"} 300
cloudflare_zone_hourly_requests_by_country{account="Example Account",country="US",zone="example.com"} 500
cloudflare_zone_hourly_requests_by_country{account="Example Account",country="US",zone="example.net"} 500
cloudflare_zone_hourly_requests_by_country{account="Example Account",country="US",zone="example.org"} 500
cloudflare_zone_hourly_requests_by_country{account="Example Account",country="other",zone="example.com"} 200
cloudflare_zone_hourly_requests_by_country{account="Example Account",country="other",zone="example.net"} 200
cloudflare_zone_hourly_requests_by_country{account="Example Account",country="other",zone="example.org"} 200
# HELP cloudflare_zone_hourly_firewall_events Firewall (security) events by action and source during the last complete hour.
# TYPE cloudflare_zone_hourly_firewall_events gauge
cloudflare_zone_hourly_firewall_events{account="Example Account",action="block",source="firewallCustom",zone="example.com"} 40
cloudflare_zone_hourly_firewall_events{account="Example Account",action="block",source="firewallCustom",zone="example.net"} 40
cloudflare_zone_hourly_firewall_events{account="Example Account",action="block",source="firewallCustom",zone="example.org"} 30
cloudflare_zone_hourly_firewall_events{account="Example Account",action="managed_challenge",source="securitylevel",zone="example.com"} 20
cloudflare_zone_hourly_firewall_events{account="Example Account",action="managed_challenge",source="securitylevel",zone="example.net"} 20
cloudflare_zone_hourly_firewall_events{account="Example Account",action="managed_challenge",source="securitylevel",zone="example.org"} 30
# HELP cloudflare_zone_hourly_firewall_events_truncated 1 if the firewall event count hit the API row limit and is a lower bound.
# TYPE cloudflare_zone_hourly_firewall_events_truncated gauge
cloudflare_zone_hourly_firewall_events_truncated{account="Example Account",dataset="firewallEventsAdaptive",zone="example.com"} 0
cloudflare_zone_hourly_firewall_events_truncated{account="Example Account",dataset="firewallEventsAdaptive",zone="example.net"} 0
cloudflare_zone_hourly_firewall_events_truncated{account="Example Account",dataset="firewallEventsAdaptiveGroups",zone="example.org"} 0
# HELP cloudflare_zone_info Zone metadata. Always 1.
# TYPE cloudflare_zone_info gauge
cloudflare_zone_info{account="Example Account",account_id="acc00000000000000000000000000001",plan="free",status="active",zone="example.com",zone_id="zone0000000000000000000000000001"} 1
cloudflare_zone_info{account="Example Account",account_id="acc00000000000000000000000000001",plan="free",status="active",zone="example.net",zone_id="zone0000000000000000000000000003"} 1
cloudflare_zone_info{account="Example Account",account_id="acc00000000000000000000000000001",plan="pro",status="active",zone="example.org",zone_id="zone0000000000000000000000000002"} 1
# HELP cloudflare_account_hourly_requests HTTP requests across all zones of the account during the last complete hour.
# TYPE cloudflare_account_hourly_requests gauge
cloudflare_account_hourly_requests{account="Example Account",account_id="acc00000000000000000000000000001"} 3000
# HELP cloudflare_zone_hourly_window_start_timestamp_seconds Start (Unix time) of the hour the cloudflare_zone_hourly_* HTTP metrics describe.
# TYPE cloudflare_zone_hourly_window_start_timestamp_seconds gauge
cloudflare_zone_hourly_window_start_timestamp_seconds{account="Example Account",zone="example.com"} 1.7723592e+09
cloudflare_zone_hourly_window_start_timestamp_seconds{account="Example Account",zone="example.net"} 1.7723592e+09
cloudflare_zone_hourly_window_start_timestamp_seconds{account="Example Account",zone="example.org"} 1.7723592e+09
`), "cloudflare_zone_hourly_requests", "cloudflare_zone_hourly_requests_by_country",
		"cloudflare_zone_hourly_firewall_events", "cloudflare_zone_hourly_firewall_events_truncated",
		"cloudflare_zone_info", "cloudflare_account_hourly_requests",
		"cloudflare_zone_hourly_window_start_timestamp_seconds"); err != nil {
		t.Fatal(err)
	}

	// Free zones must use raw events, the paid one server-side groups.
	if fake.Calls["firewallEventsAdaptive"] != 2 || fake.Calls["firewallEventsAdaptiveGroups"] != 1 {
		t.Fatalf("unexpected dataset usage: %v", fake.Calls)
	}
	if n := testutil.CollectAndCount(c, "cloudflare_exporter_up"); n == 0 {
		t.Fatal("no up metrics")
	}
	out := gather(t, reg, "cloudflare_exporter_up")
	if strings.Contains(out, "value:0") {
		t.Fatalf("all datasets should be up:\n%s", out)
	}
}

func TestSettingsAreCached(t *testing.T) {
	fake := cftest.New()
	c, _, _ := setup(t, fake, Options{FirewallEvents: true})
	c.CollectOnce(context.Background())
	c.CollectOnce(context.Background())
	if fake.Calls["settings"] != 3 {
		t.Fatalf("settings should be fetched once per zone, got %d", fake.Calls["settings"])
	}
}

func TestFailedDatasetKeepsLastValueAndReportsDown(t *testing.T) {
	fake := cftest.New()
	c, reg, _ := setup(t, fake, Options{})
	c.CollectOnce(context.Background())

	fake.FailDatasets[cloudflare.DatasetHTTP1h] = true
	c.CollectOnce(context.Background())

	if v := testutil.ToFloat64(prometheus.CollectorFunc(func(ch chan<- prometheus.Metric) {
		for _, m := range *c.snapshot.Load() {
			if strings.Contains(m.Desc().String(), `"cloudflare_zone_hourly_requests"`) {
				ch <- m
				return
			}
		}
	})); v != 1000 {
		t.Fatalf("last good value should be kept, got %v", v)
	}
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP cloudflare_exporter_api_errors_total Failed Cloudflare API calls by API (rest, graphql) and operation (REST call or GraphQL dataset).
# TYPE cloudflare_exporter_api_errors_total counter
cloudflare_exporter_api_errors_total{api="graphql",operation="httpRequests1hGroups"} 3
# HELP cloudflare_exporter_collections_total Background collection cycles by result (success, partial, failure).
# TYPE cloudflare_exporter_collections_total counter
cloudflare_exporter_collections_total{result="partial"} 1
cloudflare_exporter_collections_total{result="success"} 1
`), "cloudflare_exporter_api_errors_total", "cloudflare_exporter_collections_total"); err != nil {
		t.Fatal(err)
	}
	out := gather(t, reg, "cloudflare_exporter_up")
	if !strings.Contains(out, `value:"httpRequests1hGroups"`) {
		t.Fatalf("missing http dataset status:\n%s", out)
	}
}

func TestDiscoveryFailureServesPreviousData(t *testing.T) {
	fake := cftest.New()
	c, reg, _ := setup(t, fake, Options{})
	c.CollectOnce(context.Background())
	fake.FailREST = true
	c.CollectOnce(context.Background())
	if n := testutil.CollectAndCount(c, "cloudflare_zone_hourly_requests"); n != 3 {
		t.Fatalf("previous data should still be served, got %d series", n)
	}
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP cloudflare_exporter_collections_total Background collection cycles by result (success, partial, failure).
# TYPE cloudflare_exporter_collections_total counter
cloudflare_exporter_collections_total{result="failure"} 1
cloudflare_exporter_collections_total{result="success"} 1
`), "cloudflare_exporter_collections_total"); err != nil {
		t.Fatal(err)
	}
}

func TestZoneFiltering(t *testing.T) {
	fake := cftest.New()
	c, _, _ := setup(t, fake, Options{ExcludeZones: []string{cftest.ZonePro}})
	c.CollectOnce(context.Background())
	if n := testutil.CollectAndCount(c, "cloudflare_zone_info"); n != 2 {
		t.Fatalf("excluded zone still present: %d", n)
	}

	fake2 := cftest.New()
	c2, _, _ := setup(t, fake2, Options{Zones: []string{cftest.ZoneFree2}})
	c2.CollectOnce(context.Background())
	if n := testutil.CollectAndCount(c2, "cloudflare_zone_info"); n != 1 {
		t.Fatalf("allowlist not applied: %d", n)
	}
}

func TestRemovedZoneDisappears(t *testing.T) {
	fake := cftest.New()
	c, _, _ := setup(t, fake, Options{})
	c.CollectOnce(context.Background())
	fake.Zones = fake.Zones[:1]
	c.CollectOnce(context.Background())
	if n := testutil.CollectAndCount(c, "cloudflare_zone_hourly_requests"); n != 1 {
		t.Fatalf("removed zones should disappear, got %d", n)
	}
}

func TestTopCountries(t *testing.T) {
	m := map[string]cloudflare.CountryStats{
		"US": {Requests: 10}, "DE": {Requests: 5}, "FR": {Requests: 5, Bytes: 2}, "JP": {Requests: 1, Threats: 1},
	}
	got := topCountries(m, 2)
	if len(got) != 3 || got[0].name != "US" || got[1].name != "DE" || got[2].name != "other" {
		t.Fatalf("unexpected order: %+v", got)
	}
	if got[2].stats.Requests != 6 || got[2].stats.Bytes != 2 || got[2].stats.Threats != 1 {
		t.Fatalf("other not summed: %+v", got[2])
	}
	if len(topCountries(m, 10)) != 4 {
		t.Fatal("no other expected when under the cap")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	fake := cftest.New()
	c, _, _ := setup(t, fake, Options{Interval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
	if ok, _ := c.Healthy(); !ok {
		t.Fatal("expected a successful discovery")
	}
}
