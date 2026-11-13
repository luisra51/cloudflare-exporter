package collector

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/luisra51/cloudflare-exporter/internal/cftest"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

func TestHostMetrics(t *testing.T) {
	fake := cftest.New()
	c, reg, _ := setup(t, fake, Options{HostMetrics: true, TopHosts: 2, Zones: []string{cftest.ZoneFree, cftest.ZonePro}})
	c.CollectOnce(context.Background())
	// fixedNow 12:07, delay 0, window 5m -> 12:02-12:07.
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP cloudflare_zone_host_requests Requests per host and edge status class in the rolling window (sampled estimate; top N hosts, the rest as host="other").
# TYPE cloudflare_zone_host_requests gauge
cloudflare_zone_host_requests{account="Example Account",host="api.example.com",status_class="2xx",zone="example.com"} 300
cloudflare_zone_host_requests{account="Example Account",host="api.example.com",status_class="2xx",zone="example.org"} 300
cloudflare_zone_host_requests{account="Example Account",host="api.example.com",status_class="5xx",zone="example.com"} 10
cloudflare_zone_host_requests{account="Example Account",host="api.example.com",status_class="5xx",zone="example.org"} 10
cloudflare_zone_host_requests{account="Example Account",host="other",status_class="2xx",zone="example.com"} 50
cloudflare_zone_host_requests{account="Example Account",host="other",status_class="2xx",zone="example.org"} 50
cloudflare_zone_host_requests{account="Example Account",host="www.example.com",status_class="2xx",zone="example.com"} 558
cloudflare_zone_host_requests{account="Example Account",host="www.example.com",status_class="2xx",zone="example.org"} 558
cloudflare_zone_host_requests{account="Example Account",host="www.example.com",status_class="4xx",zone="example.com"} 20
cloudflare_zone_host_requests{account="Example Account",host="www.example.com",status_class="4xx",zone="example.org"} 20
cloudflare_zone_host_requests{account="Example Account",host="www.example.com",status_class="5xx",zone="example.com"} 5
cloudflare_zone_host_requests{account="Example Account",host="www.example.com",status_class="5xx",zone="example.org"} 5
# HELP cloudflare_zone_host_origin_5xx_requests Requests per host whose origin answered 5xx in the rolling window (sampled estimate). Only when the zone may query originResponseStatus.
# TYPE cloudflare_zone_host_origin_5xx_requests gauge
cloudflare_zone_host_origin_5xx_requests{account="Example Account",host="api.example.com",zone="example.org"} 10
cloudflare_zone_host_origin_5xx_requests{account="Example Account",host="other",zone="example.org"} 0
cloudflare_zone_host_origin_5xx_requests{account="Example Account",host="www.example.com",zone="example.org"} 5
# HELP cloudflare_zone_host_bytes Bytes sent to clients per host in the rolling window (sampled estimate). Only when the zone may query edgeResponseBytes.
# TYPE cloudflare_zone_host_bytes gauge
cloudflare_zone_host_bytes{account="Example Account",host="api.example.com",zone="example.org"} 310000
cloudflare_zone_host_bytes{account="Example Account",host="other",zone="example.org"} 50000
cloudflare_zone_host_bytes{account="Example Account",host="www.example.com",zone="example.org"} 583000
# HELP cloudflare_zone_host_window_seconds Length of the rolling window the cloudflare_zone_host_* metrics describe. Divide by it to get a per-second rate.
# TYPE cloudflare_zone_host_window_seconds gauge
cloudflare_zone_host_window_seconds{account="Example Account",zone="example.com"} 300
cloudflare_zone_host_window_seconds{account="Example Account",zone="example.org"} 300
`), "cloudflare_zone_host_requests", "cloudflare_zone_host_origin_5xx_requests", "cloudflare_zone_host_bytes", "cloudflare_zone_host_window_seconds"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "cloudflare_zone_host_requests_by_status"); n != 0 {
		t.Fatalf("exact status must be off by default, got %d", n)
	}
	// Regression: origin-0 groups (cache hits, edge redirects, 499) report
	// avg -1 and must not pull the average down or make it negative; a
	// host with no origin traffic ("other" = static.example.com) has no
	// origin time series at all.
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP cloudflare_zone_host_origin_response_time_seconds Average origin response time per host in the rolling window, over requests that reached the origin. Absent for hosts with no origin requests in the window.
# TYPE cloudflare_zone_host_origin_response_time_seconds gauge
cloudflare_zone_host_origin_response_time_seconds{account="Example Account",host="api.example.com",zone="example.org"} 0.14516129032258063
cloudflare_zone_host_origin_response_time_seconds{account="Example Account",host="www.example.com",zone="example.org"} 0.10552380952380952
# HELP cloudflare_zone_host_origin_requests Requests per host that reached the origin (originResponseStatus > 0) in the rolling window (sampled estimate). Only when the zone may query originResponseStatus.
# TYPE cloudflare_zone_host_origin_requests gauge
cloudflare_zone_host_origin_requests{account="Example Account",host="api.example.com",zone="example.org"} 310
cloudflare_zone_host_origin_requests{account="Example Account",host="other",zone="example.org"} 0
cloudflare_zone_host_origin_requests{account="Example Account",host="www.example.com",zone="example.org"} 525
`), "cloudflare_zone_host_origin_response_time_seconds", "cloudflare_zone_host_origin_requests"); err != nil {
		t.Fatal(err)
	}
}

func TestHostExactStatusAndUnlimitedHosts(t *testing.T) {
	fake := cftest.New()
	c, _, _ := setup(t, fake, Options{HostMetrics: true, HostExactStatus: true, Zones: []string{cftest.ZoneFree}})
	c.CollectOnce(context.Background())
	if n := testutil.CollectAndCount(c, "cloudflare_zone_host_requests_by_status"); n != 6 {
		t.Fatalf("want 6 host/status series, got %d", n)
	}
	if strings.Contains(snapshotText(c), `host="other"`) {
		t.Fatal("TopHosts=0 must not fold hosts")
	}
}

func TestCertMetrics(t *testing.T) {
	fake := cftest.New()
	c, reg, _ := setup(t, fake, Options{CertMetrics: true, Zones: []string{cftest.ZoneFree}})
	c.CollectOnce(context.Background())
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP cloudflare_zone_certificate_pack_expiry_timestamp_seconds Earliest expiry (Unix time) among the certificates of an edge certificate pack.
# TYPE cloudflare_zone_certificate_pack_expiry_timestamp_seconds gauge
cloudflare_zone_certificate_pack_expiry_timestamp_seconds{account="Example Account",pack_id="pack-universal-1",status="active",type="universal",zone="example.com"} 1.7991072e+09
# HELP cloudflare_zone_certificate_pack_active 1 if the certificate pack status is active, 0 otherwise.
# TYPE cloudflare_zone_certificate_pack_active gauge
cloudflare_zone_certificate_pack_active{account="Example Account",pack_id="pack-advanced-1",type="advanced",zone="example.com"} 0
cloudflare_zone_certificate_pack_active{account="Example Account",pack_id="pack-universal-1",type="universal",zone="example.com"} 1
# HELP cloudflare_zone_certificate_pack_info Edge certificate pack metadata. Always 1.
# TYPE cloudflare_zone_certificate_pack_info gauge
cloudflare_zone_certificate_pack_info{account="Example Account",certificate_authority="google",pack_id="pack-universal-1",status="active",type="universal",zone="example.com"} 1
cloudflare_zone_certificate_pack_info{account="Example Account",certificate_authority="unknown",pack_id="pack-advanced-1",status="pending_validation",type="advanced",zone="example.com"} 1
# HELP cloudflare_zone_certificate_packs Edge certificate packs of the zone (all statuses).
# TYPE cloudflare_zone_certificate_packs gauge
cloudflare_zone_certificate_packs{account="Example Account",zone="example.com"} 2
`), "cloudflare_zone_certificate_pack_expiry_timestamp_seconds", "cloudflare_zone_certificate_pack_active",
		"cloudflare_zone_certificate_pack_info", "cloudflare_zone_certificate_packs"); err != nil {
		t.Fatal(err)
	}
}

func TestZeroTrustMetrics(t *testing.T) {
	fake := cftest.New()
	c, reg, _ := setup(t, fake, Options{ZeroTrustMetrics: true, Zones: []string{cftest.ZoneFree}})
	c.CollectOnce(context.Background())
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP cloudflare_access_service_token_expiry_timestamp_seconds Expiry (Unix time) of an Access service token.
# TYPE cloudflare_access_service_token_expiry_timestamp_seconds gauge
cloudflare_access_service_token_expiry_timestamp_seconds{account="Example Account",name="ci-deploy"} 1.80144e+09
cloudflare_access_service_token_expiry_timestamp_seconds{account="Example Account",name="legacy-bot"} 4.8913632e+09
# HELP cloudflare_access_service_tokens Access service tokens of the account.
# TYPE cloudflare_access_service_tokens gauge
cloudflare_access_service_tokens{account="Example Account"} 2
# HELP cloudflare_zerotrust_devices WARP devices registered in the account.
# TYPE cloudflare_zerotrust_devices gauge
cloudflare_zerotrust_devices{account="Example Account"} 5
# HELP cloudflare_zerotrust_devices_by_last_seen WARP devices by time since last seen (exclusive buckets: 24h, 7d, 30d, older, never).
# TYPE cloudflare_zerotrust_devices_by_last_seen gauge
cloudflare_zerotrust_devices_by_last_seen{account="Example Account",last_seen="24h"} 1
cloudflare_zerotrust_devices_by_last_seen{account="Example Account",last_seen="30d"} 1
cloudflare_zerotrust_devices_by_last_seen{account="Example Account",last_seen="7d"} 1
cloudflare_zerotrust_devices_by_last_seen{account="Example Account",last_seen="never"} 1
cloudflare_zerotrust_devices_by_last_seen{account="Example Account",last_seen="older"} 1
# HELP cloudflare_zerotrust_devices_by_os WARP devices by device type (windows, mac, linux, android, ios, chromeos).
# TYPE cloudflare_zerotrust_devices_by_os gauge
cloudflare_zerotrust_devices_by_os{account="Example Account",os="ios"} 1
cloudflare_zerotrust_devices_by_os{account="Example Account",os="linux"} 1
cloudflare_zerotrust_devices_by_os{account="Example Account",os="mac"} 1
cloudflare_zerotrust_devices_by_os{account="Example Account",os="windows"} 2
# HELP cloudflare_gateway_dns_queries Gateway DNS queries by resolver decision in the rolling window (sampled estimate).
# TYPE cloudflare_gateway_dns_queries gauge
cloudflare_gateway_dns_queries{account="Example Account",decision="allowedOnNoPolicyMatch",decision_code="5"} 120
cloudflare_gateway_dns_queries{account="Example Account",decision="blockedRule",decision_code="9"} 15
cloudflare_gateway_dns_queries{account="Example Account",decision="unknown",decision_code="99"} 1
# HELP cloudflare_access_logins Access login attempts by result (success, failure) in the rolling window (sampled estimate).
# TYPE cloudflare_access_logins gauge
cloudflare_access_logins{account="Example Account",result="failure"} 3
cloudflare_access_logins{account="Example Account",result="success"} 40
`), "cloudflare_access_service_token_expiry_timestamp_seconds", "cloudflare_access_service_tokens",
		"cloudflare_zerotrust_devices", "cloudflare_zerotrust_devices_by_last_seen", "cloudflare_zerotrust_devices_by_os",
		"cloudflare_gateway_dns_queries", "cloudflare_access_logins"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(snapshotText(c), "secret-client-id") {
		t.Fatal("service token client IDs must never be exported")
	}
	if strings.Contains(snapshotText(c), "192.0.2.1") {
		t.Fatal("device data must never be exported")
	}
}

func TestDevicesUseTheirOwnInterval(t *testing.T) {
	fake := cftest.New()
	c, _, _ := setup(t, fake, Options{ZeroTrustMetrics: true, DevicesInterval: time.Hour, Zones: []string{cftest.ZoneFree}})
	path := "/accounts/" + cftest.AccountID + "/devices"
	c.CollectOnce(context.Background())
	c.CollectOnce(context.Background())
	if fake.RESTCalls[path] != 1 {
		t.Fatalf("devices should be read once per interval, got %d", fake.RESTCalls[path])
	}
	c.opts.Now = func() time.Time { return fixedNow.Add(61 * time.Minute) }
	c.CollectOnce(context.Background())
	if fake.RESTCalls[path] != 2 {
		t.Fatalf("devices should be re-read after the interval, got %d", fake.RESTCalls[path])
	}
}

func TestMissingPermissionsWarnOnceAndKeepTheRest(t *testing.T) {
	fake := cftest.New()
	fake.ZeroTrustForbidden = true
	fake.CertsForbidden = true
	c, reg, _ := setup(t, fake, Options{ZeroTrustMetrics: true, CertMetrics: true, HostMetrics: true, Zones: []string{cftest.ZoneFree}})
	var logs bytes.Buffer
	c.log = slog.New(slog.NewTextHandler(&logs, nil))
	c.CollectOnce(context.Background())
	c.opts.Now = func() time.Time { return fixedNow.Add(2 * time.Hour) } // devices due again
	c.CollectOnce(context.Background())

	for _, perm := range []string{"SSL and Certificates > Read", "Access: Service Tokens > Read", "Zero Trust > Read", "Account Analytics > Read (and Zero Trust Gateway", "Account Analytics > Read (and Cloudflare Access"} {
		if n := strings.Count(logs.String(), perm); n != 1 {
			t.Fatalf("want exactly one warning naming %q, got %d:\n%s", perm, n, logs.String())
		}
	}
	for _, ds := range []string{"certificate_packs", "access_service_tokens", "devices", "gatewayResolverQueriesAdaptiveGroups", "accessLoginRequestsAdaptiveGroups"} {
		if v, ok := upValue(t, reg, ds); !ok || v != 0 {
			t.Fatalf("up{dataset=%q} should be 0, got %v (present=%v)", ds, v, ok)
		}
	}
	if v, ok := upValue(t, reg, "httpRequestsAdaptiveGroups"); !ok || v != 1 {
		t.Fatalf("host metrics should still work: %v %v", v, ok)
	}
	if n := testutil.CollectAndCount(c, "cloudflare_zone_hourly_requests"); n != 1 {
		t.Fatalf("zone metrics should still work, got %d", n)
	}
}

func TestStaleHostAndCertSeriesRemovedWithZone(t *testing.T) {
	fake := cftest.New()
	c, _, _ := setup(t, fake, Options{HostMetrics: true, CertMetrics: true})
	c.CollectOnce(context.Background())
	if n := testutil.CollectAndCount(c, "cloudflare_zone_certificate_packs"); n != 3 {
		t.Fatalf("want 3 zones, got %d", n)
	}
	fake.Zones = fake.Zones[:1]
	c.CollectOnce(context.Background())
	if n := testutil.CollectAndCount(c, "cloudflare_zone_certificate_packs"); n != 1 {
		t.Fatalf("cert series of removed zones should disappear, got %d", n)
	}
	if n := testutil.CollectAndCount(c, "cloudflare_zone_host_window_seconds"); n != 1 {
		t.Fatalf("host series of removed zones should disappear, got %d", n)
	}
}

func snapshotText(c *Collector) string {
	var b strings.Builder
	for _, m := range *c.snapshot.Load() {
		b.WriteString(m.Desc().String())
		b.WriteString(" ")
		b.WriteString(metricLabels(m))
		b.WriteString("\n")
	}
	return b.String()
}

func metricLabels(m interface {
	Write(*dto.Metric) error
}) string {
	var d dto.Metric
	if err := m.Write(&d); err != nil {
		return ""
	}
	return d.String()
}
