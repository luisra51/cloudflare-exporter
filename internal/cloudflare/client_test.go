package cloudflare_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luisra51/cloudflare-exporter/internal/cftest"
	"github.com/luisra51/cloudflare-exporter/internal/cloudflare"
)

type countObserver struct{ n atomic.Int32 }

func (o *countObserver) APIError(string, string) { o.n.Add(1) }

func newClient(t *testing.T, h http.Handler, opts ...cloudflare.Option) *cloudflare.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	opts = append([]cloudflare.Option{cloudflare.WithRetry(2, time.Millisecond)}, opts...)
	return cloudflare.New(srv.URL, cftest.Token, opts...)
}

var (
	hourStart = time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	hourEnd   = hourStart.Add(time.Hour)
)

func TestListZonesPaginatesAndParsesPlan(t *testing.T) {
	c := newClient(t, cftest.New())
	zones, err := c.ListZones(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 3 {
		t.Fatalf("want 3 zones over 2 pages, got %d", len(zones))
	}
	if !zones[0].IsFree() || zones[1].PlanCode() != "pro" || zones[1].IsFree() {
		t.Fatalf("plan detection wrong: %+v", zones)
	}
	if zones[0].Account.Name != "Example Account" {
		t.Fatalf("account not parsed: %+v", zones[0].Account)
	}
}

func TestBadTokenIsAPIError(t *testing.T) {
	srv := httptest.NewServer(cftest.New())
	defer srv.Close()
	obs := &countObserver{}
	c := cloudflare.New(srv.URL, "wrong", cloudflare.WithObserver(obs))
	_, err := c.ListZones(context.Background(), "")
	var apiErr *cloudflare.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("want 403 APIError, got %v", err)
	}
	if obs.n.Load() != 1 {
		t.Fatalf("observer not notified")
	}
}

func TestRetriesOn429(t *testing.T) {
	var calls atomic.Int32
	fake := cftest.New()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fake.ServeHTTP(w, r)
	})
	c := newClient(t, h)
	if _, err := c.GetZone(context.Background(), cftest.ZoneFree); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("want 2 calls, got %d", calls.Load())
	}
}

func TestGraphQLErrorsAreReturned(t *testing.T) {
	fake := cftest.New()
	fake.FailDatasets[cloudflare.DatasetHTTP1h] = true
	obs := &countObserver{}
	c := newClient(t, fake, cloudflare.WithObserver(obs))
	_, err := c.ZoneHTTP1h(context.Background(), cftest.ZoneFree, hourStart, hourEnd)
	var gqlErr cloudflare.GraphQLErrors
	if !errors.As(err, &gqlErr) {
		t.Fatalf("want GraphQLErrors, got %v", err)
	}
	if obs.n.Load() != 1 {
		t.Fatalf("observer not notified")
	}
}

func TestZoneHTTP1h(t *testing.T) {
	c := newClient(t, cftest.New())
	st, err := c.ZoneHTTP1h(context.Background(), cftest.ZoneFree, hourStart, hourEnd)
	if err != nil {
		t.Fatal(err)
	}
	if st.Requests != 1000 || st.CachedBytes != 3e6 || st.Uniques != 42 || st.Threats != 7 {
		t.Fatalf("unexpected totals: %+v", st)
	}
	if st.ByStatus["404"] != 80 || st.ByHTTPVersion["HTTP/2"] != 700 {
		t.Fatalf("unexpected breakdowns: %+v %+v", st.ByStatus, st.ByHTTPVersion)
	}
	if st.Countries["DE"].Bytes != 1.5e6 {
		t.Fatalf("unexpected countries: %+v", st.Countries)
	}
}

func TestZoneSettings(t *testing.T) {
	c := newClient(t, cftest.New())
	s, err := c.ZoneSettings(context.Background(), cftest.ZoneFree)
	if err != nil {
		t.Fatal(err)
	}
	if !s.HTTP1h.Enabled || !s.FirewallRaw.Enabled || s.FirewallGroups.Enabled || s.FirewallRaw.MaxPageSize != 10000 {
		t.Fatalf("unexpected free settings: %+v", s)
	}
	s, err = c.ZoneSettings(context.Background(), cftest.ZonePro)
	if err != nil {
		t.Fatal(err)
	}
	if !s.FirewallGroups.Enabled {
		t.Fatalf("pro zone should have groups: %+v", s)
	}
}

func TestFirewallRawCountsClientSide(t *testing.T) {
	fake := cftest.New()
	fake.FirewallEventsPerHour = 90
	c := newClient(t, fake)
	st, err := c.ZoneFirewallEvents(context.Background(), cftest.ZoneFree, hourStart, hourEnd, cloudflare.DefaultZoneSettings())
	if err != nil {
		t.Fatal(err)
	}
	if st.Dataset != cloudflare.DatasetFirewallRaw || st.Truncated {
		t.Fatalf("unexpected: %+v", st)
	}
	total := 0.0
	for _, v := range st.Counts {
		total += v
	}
	if total != 90 {
		t.Fatalf("want 90 events, got %v (%v)", total, st.Counts)
	}
	if st.Counts[cloudflare.FirewallKey{Action: "managed_challenge", Source: "securitylevel"}] != 30 {
		t.Fatalf("unexpected split: %v", st.Counts)
	}
}

func TestFirewallRawBisectsFullPages(t *testing.T) {
	fake := cftest.New()
	fake.FirewallEventsPerHour = 1000
	c := newClient(t, fake)
	s := cloudflare.DefaultZoneSettings()
	s.FirewallRaw.MaxPageSize = 300 // force several splits
	st, err := c.ZoneFirewallEvents(context.Background(), cftest.ZoneFree, hourStart, hourEnd, s)
	if err != nil {
		t.Fatal(err)
	}
	total := 0.0
	for _, v := range st.Counts {
		total += v
	}
	if total != 1000 || st.Truncated {
		t.Fatalf("want exact 1000 after bisection, got %v truncated=%v queries=%d", total, st.Truncated, st.Queries)
	}
	if st.Queries < 5 {
		t.Fatalf("expected bisection, got %d queries", st.Queries)
	}
}

func TestFirewallRawTruncatesWhenMinuteIsFull(t *testing.T) {
	fake := cftest.New()
	fake.FirewallEventsPerHour = 3600 // 60 per minute
	c := newClient(t, fake)
	s := cloudflare.DefaultZoneSettings()
	s.FirewallRaw.MaxPageSize = 10
	st, err := c.ZoneFirewallEvents(context.Background(), cftest.ZoneFree, hourStart, hourEnd, s)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Truncated {
		t.Fatalf("expected truncation, got %+v", st)
	}
	if st.Queries > 40 {
		t.Fatalf("query budget exceeded: %d", st.Queries)
	}
}

func TestFirewallGroupsOnPaidPlan(t *testing.T) {
	fake := cftest.New()
	fake.FirewallEventsPerHour = 100
	c := newClient(t, fake)
	s := cloudflare.DefaultZoneSettings()
	s.FirewallGroups = cloudflare.NodeSettings{Enabled: true, MaxPageSize: 10000}
	st, err := c.ZoneFirewallEvents(context.Background(), cftest.ZonePro, hourStart, hourEnd, s)
	if err != nil {
		t.Fatal(err)
	}
	if st.Dataset != cloudflare.DatasetFirewallGroups || st.Counts[cloudflare.FirewallKey{Action: "block", Source: "firewallCustom"}] != 50 {
		t.Fatalf("unexpected: %+v", st)
	}
}

func TestFirewallGroupsFallBackToRaw(t *testing.T) {
	fake := cftest.New()
	fake.FirewallEventsPerHour = 30
	c := newClient(t, fake)
	s := cloudflare.DefaultZoneSettings()
	s.FirewallGroups = cloudflare.NodeSettings{Enabled: true} // free zone will refuse
	st, err := c.ZoneFirewallEvents(context.Background(), cftest.ZoneFree, hourStart, hourEnd, s)
	if err != nil {
		t.Fatal(err)
	}
	if st.Dataset != cloudflare.DatasetFirewallRaw {
		t.Fatalf("expected fallback to raw, got %+v", st)
	}
}

func TestFirewallUnavailable(t *testing.T) {
	c := newClient(t, cftest.New())
	_, err := c.ZoneFirewallEvents(context.Background(), cftest.ZoneFree, hourStart, hourEnd, cloudflare.ZoneSettings{})
	if !errors.Is(err, cloudflare.ErrDatasetUnavailable) {
		t.Fatalf("want ErrDatasetUnavailable, got %v", err)
	}
}

func TestAccountOverview(t *testing.T) {
	c := newClient(t, cftest.New())
	st, err := c.AccountHTTPOverview(context.Background(), cftest.AccountID, hourStart, hourEnd)
	if err != nil {
		t.Fatal(err)
	}
	if st.Requests != 3000 || st.CachedBytes != 9e6 {
		t.Fatalf("unexpected: %+v", st)
	}
}
