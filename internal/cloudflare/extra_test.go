package cloudflare_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/luisra51/cloudflare-exporter/internal/cftest"
	"github.com/luisra51/cloudflare-exporter/internal/cloudflare"
)

var (
	winStart = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	winEnd   = winStart.Add(5 * time.Minute)
)

func TestZoneSettingsAdaptiveAndAvailableFields(t *testing.T) {
	c := newClient(t, cftest.New())
	free, err := c.ZoneSettings(context.Background(), cftest.ZoneFree)
	if err != nil {
		t.Fatal(err)
	}
	if !free.HTTPAdaptive.Enabled || free.HTTPAdaptive.MaxFields != 40 || free.HTTPAdaptive.HasField("", "originResponseStatus") {
		t.Fatalf("free adaptive settings: %+v", free.HTTPAdaptive)
	}
	pro, err := c.ZoneSettings(context.Background(), cftest.ZonePro)
	if err != nil {
		t.Fatal(err)
	}
	if !pro.HTTPAdaptive.HasField("sum", "edgeResponseBytes") || !pro.HTTPAdaptive.HasField("avg", "originResponseDurationMs") {
		t.Fatalf("pro available fields: %+v", pro.HTTPAdaptive.AvailableFields)
	}
}

func TestZoneHostTrafficBaseFields(t *testing.T) {
	c := newClient(t, cftest.New())
	st, err := c.ZoneHostTraffic(context.Background(), cftest.ZoneFree, winStart, winEnd, cloudflare.NodeSettings{Enabled: true, MaxPageSize: 10000})
	if err != nil {
		t.Fatal(err)
	}
	if st.HasBytes || st.HasOrigin || st.HasOriginTime {
		t.Fatalf("no optional fields expected: %+v", st)
	}
	if st.Requests[cloudflare.HostKey{Host: "api.example.com", Status: 500}] != 10 || len(st.Requests) != 6 {
		t.Fatalf("unexpected requests: %v", st.Requests)
	}
}

func TestZoneHostTrafficOptionalFields(t *testing.T) {
	c := newClient(t, cftest.New())
	ns := cloudflare.NodeSettings{Enabled: true, MaxPageSize: 10000,
		AvailableFields: []string{"sum_edgeResponseBytes", "originResponseStatus", "avg_originResponseDurationMs"}}
	st, err := c.ZoneHostTraffic(context.Background(), cftest.ZonePro, winStart, winEnd, ns)
	if err != nil {
		t.Fatal(err)
	}
	if !st.HasBytes || st.Bytes["www.example.com"] != 525000 {
		t.Fatalf("bytes: %v", st.Bytes)
	}
	if st.Origin5xx["www.example.com"] != 5 || st.Origin5xx["api.example.com"] != 10 {
		t.Fatalf("origin 5xx: %v", st.Origin5xx)
	}
	// api: (300*120 + 10*900) / 310 ms
	if got := st.OriginTimeSum["api.example.com"] / st.OriginTimeWeight["api.example.com"]; got < 145 || got > 146 {
		t.Fatalf("origin time avg: %v", got)
	}
}

func TestZoneHostTrafficRetriesWithoutOptionalFields(t *testing.T) {
	fake := cftest.New()
	fake.RefuseOptionalHostFields = true
	c := newClient(t, fake)
	ns := cloudflare.NodeSettings{Enabled: true, AvailableFields: []string{"originResponseStatus"}}
	st, err := c.ZoneHostTraffic(context.Background(), cftest.ZoneFree, winStart, winEnd, ns)
	if err != nil {
		t.Fatal(err)
	}
	if st.HasOrigin || len(st.Requests) != 6 {
		t.Fatalf("expected base-field fallback: %+v", st)
	}
}

func TestZoneHostTrafficSplitsFullPages(t *testing.T) {
	fake := cftest.New()
	fake.ExtraHosts = 50
	c := newClient(t, fake)
	st, err := c.ZoneHostTraffic(context.Background(), cftest.ZoneFree, winStart, winEnd, cloudflare.NodeSettings{Enabled: true, MaxPageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Truncated || st.Queries < 3 || st.Queries > 20 {
		t.Fatalf("expected split then truncation within budget: truncated=%v queries=%d", st.Truncated, st.Queries)
	}
}

func TestZoneHostTrafficDisabled(t *testing.T) {
	c := newClient(t, cftest.New())
	if _, err := c.ZoneHostTraffic(context.Background(), cftest.ZoneFree, winStart, winEnd, cloudflare.NodeSettings{}); !errors.Is(err, cloudflare.ErrDatasetUnavailable) {
		t.Fatalf("want ErrDatasetUnavailable, got %v", err)
	}
}

func TestCertificatePacks(t *testing.T) {
	c := newClient(t, cftest.New())
	packs, err := c.CertificatePacks(context.Background(), cftest.ZoneFree)
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 2 || packs[0].EarliestExpiry.Format(time.RFC3339) != cftest.CertExpiryEarliest || !packs[1].EarliestExpiry.IsZero() {
		t.Fatalf("unexpected packs: %+v", packs)
	}
}

func TestServiceTokens(t *testing.T) {
	c := newClient(t, cftest.New())
	tokens, err := c.ServiceTokens(context.Background(), cftest.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || tokens[0].Name != "ci-deploy" || tokens[0].LastSeenAt.IsZero() || !tokens[1].LastSeenAt.IsZero() {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}
}

func TestDevicesSummaryAndSmallPageFallback(t *testing.T) {
	fake := cftest.New()
	fake.DevicesMaxPerPage = 2
	for i := 0; i < 200; i++ {
		fake.Devices = append(fake.Devices, map[string]any{"device_type": "android", "last_seen": "2026-03-01T11:00:00Z"})
	}
	c := newClient(t, fake)
	now := time.Date(2026, 3, 1, 12, 7, 0, 0, time.UTC)
	// With a 2-per-page limit, both 1000 and 100 are rejected.
	if _, err := c.Devices(context.Background(), cftest.AccountID, now); err == nil {
		t.Fatal("expected an error when every page size is rejected")
	}
	fake.DevicesMaxPerPage = 100
	sum, err := c.Devices(context.Background(), cftest.AccountID, now)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Total != 205 || sum.ByOS["android"] != 200 || sum.ByOS["windows"] != 2 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	want := map[string]float64{"24h": 201, "7d": 1, "30d": 1, "older": 1, "never": 1}
	for k, v := range want {
		if sum.ByLastSeen[k] != v {
			t.Fatalf("bucket %s: want %v, got %v (%v)", k, v, sum.ByLastSeen[k], sum.ByLastSeen)
		}
	}
}

func TestGatewayAndAccessLogins(t *testing.T) {
	c := newClient(t, cftest.New())
	gw, err := c.GatewayDNSQueries(context.Background(), cftest.AccountID, winStart, winEnd)
	if err != nil {
		t.Fatal(err)
	}
	if gw["5"] != 120 || gw["9"] != 15 || gw["99"] != 1 {
		t.Fatalf("gateway: %v", gw)
	}
	logins, err := c.AccessLogins(context.Background(), cftest.AccountID, winStart, winEnd)
	if err != nil {
		t.Fatal(err)
	}
	if logins["success"] != 40 || logins["failure"] != 3 {
		t.Fatalf("logins: %v", logins)
	}
}

func TestZeroTrustUnavailableErrors(t *testing.T) {
	fake := cftest.New()
	fake.ZeroTrustForbidden = true
	c := newClient(t, fake)
	if _, err := c.ServiceTokens(context.Background(), cftest.AccountID); !cloudflare.IsUnavailableError(err) {
		t.Fatalf("service tokens: %v", err)
	}
	if _, err := c.GatewayDNSQueries(context.Background(), cftest.AccountID, winStart, winEnd); !cloudflare.IsUnavailableError(err) {
		t.Fatalf("gateway: %v", err)
	}
}
