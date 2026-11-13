package collector

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/luisra51/cloudflare-exporter/internal/cftest"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const tunnelExpected = `
# HELP cloudflare_tunnel_connections Edge connections of the tunnel.
# TYPE cloudflare_tunnel_connections gauge
cloudflare_tunnel_connections{account="Example Account",tunnel="db-tunnel"} 0
cloudflare_tunnel_connections{account="Example Account",tunnel="office-connector"} 1
cloudflare_tunnel_connections{account="Example Account",tunnel="web-tunnel"} 4
# HELP cloudflare_tunnel_connections_by_colo Edge connections of the tunnel by Cloudflare data center.
# TYPE cloudflare_tunnel_connections_by_colo gauge
cloudflare_tunnel_connections_by_colo{account="Example Account",colo="CDG",tunnel="web-tunnel"} 1
cloudflare_tunnel_connections_by_colo{account="Example Account",colo="LHR",tunnel="office-connector"} 1
cloudflare_tunnel_connections_by_colo{account="Example Account",colo="MAD",tunnel="web-tunnel"} 3
# HELP cloudflare_tunnel_connections_pending_reconnect Edge connections flagged as pending reconnect (Cloudflare has deprecated this flag and may always report 0).
# TYPE cloudflare_tunnel_connections_pending_reconnect gauge
cloudflare_tunnel_connections_pending_reconnect{account="Example Account",tunnel="db-tunnel"} 0
cloudflare_tunnel_connections_pending_reconnect{account="Example Account",tunnel="office-connector"} 0
cloudflare_tunnel_connections_pending_reconnect{account="Example Account",tunnel="web-tunnel"} 1
# HELP cloudflare_tunnel_connector_info Connector metadata. Always 1.
# TYPE cloudflare_tunnel_connector_info gauge
cloudflare_tunnel_connector_info{account="Example Account",arch="linux_amd64",connector_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",tunnel="web-tunnel",version="2026.1.0"} 1
cloudflare_tunnel_connector_info{account="Example Account",arch="linux_amd64",connector_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",tunnel="office-connector",version="2026.1.0"} 1
cloudflare_tunnel_connector_info{account="Example Account",arch="linux_arm64",connector_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",tunnel="web-tunnel",version="2025.11.1"} 1
# HELP cloudflare_tunnel_connectors Distinct connectors (cloudflared or WARP Connector instances) reported for the tunnel.
# TYPE cloudflare_tunnel_connectors gauge
cloudflare_tunnel_connectors{account="Example Account",tunnel="db-tunnel"} 0
cloudflare_tunnel_connectors{account="Example Account",tunnel="office-connector"} 1
cloudflare_tunnel_connectors{account="Example Account",tunnel="web-tunnel"} 2
# HELP cloudflare_tunnel_info Tunnel metadata. Always 1.
# TYPE cloudflare_tunnel_info gauge
cloudflare_tunnel_info{account="Example Account",account_id="acc00000000000000000000000000001",config_src="cloudflare",tunnel="web-tunnel",tunnel_id="11111111-1111-4111-8111-111111111111",type="cfd_tunnel"} 1
cloudflare_tunnel_info{account="Example Account",account_id="acc00000000000000000000000000001",config_src="local",tunnel="db-tunnel",tunnel_id="22222222-2222-4222-8222-222222222222",type="cfd_tunnel"} 1
cloudflare_tunnel_info{account="Example Account",account_id="acc00000000000000000000000000001",config_src="unknown",tunnel="office-connector",tunnel_id="33333333-3333-4333-8333-333333333333",type="warp_connector"} 1
# HELP cloudflare_tunnel_status Tunnel status as a state set: 1 for the current status, 0 for the others.
# TYPE cloudflare_tunnel_status gauge
cloudflare_tunnel_status{account="Example Account",status="degraded",tunnel="db-tunnel"} 0
cloudflare_tunnel_status{account="Example Account",status="degraded",tunnel="office-connector"} 1
cloudflare_tunnel_status{account="Example Account",status="degraded",tunnel="web-tunnel"} 0
cloudflare_tunnel_status{account="Example Account",status="down",tunnel="db-tunnel"} 1
cloudflare_tunnel_status{account="Example Account",status="down",tunnel="office-connector"} 0
cloudflare_tunnel_status{account="Example Account",status="down",tunnel="web-tunnel"} 0
cloudflare_tunnel_status{account="Example Account",status="healthy",tunnel="db-tunnel"} 0
cloudflare_tunnel_status{account="Example Account",status="healthy",tunnel="office-connector"} 0
cloudflare_tunnel_status{account="Example Account",status="healthy",tunnel="web-tunnel"} 1
cloudflare_tunnel_status{account="Example Account",status="inactive",tunnel="db-tunnel"} 0
cloudflare_tunnel_status{account="Example Account",status="inactive",tunnel="office-connector"} 0
cloudflare_tunnel_status{account="Example Account",status="inactive",tunnel="web-tunnel"} 0
# HELP cloudflare_tunnel_up 1 if the tunnel status is healthy or degraded, 0 otherwise.
# TYPE cloudflare_tunnel_up gauge
cloudflare_tunnel_up{account="Example Account",tunnel="db-tunnel"} 0
cloudflare_tunnel_up{account="Example Account",tunnel="office-connector"} 1
cloudflare_tunnel_up{account="Example Account",tunnel="web-tunnel"} 1
# HELP cloudflare_tunnel_active_since_timestamp_seconds Unix time the tunnel last became active (conns_active_at).
# TYPE cloudflare_tunnel_active_since_timestamp_seconds gauge
cloudflare_tunnel_active_since_timestamp_seconds{account="Example Account",tunnel="office-connector"} 1.767323045e+09
cloudflare_tunnel_active_since_timestamp_seconds{account="Example Account",tunnel="web-tunnel"} 1.767323045e+09
# HELP cloudflare_tunnel_inactive_since_timestamp_seconds Unix time the tunnel last became inactive (conns_inactive_at). Absent when Cloudflare reports none.
# TYPE cloudflare_tunnel_inactive_since_timestamp_seconds gauge
cloudflare_tunnel_inactive_since_timestamp_seconds{account="Example Account",tunnel="db-tunnel"} 1.767593228e+09
`

var tunnelFamilies = []string{
	"cloudflare_tunnel_connections", "cloudflare_tunnel_connections_by_colo",
	"cloudflare_tunnel_connections_pending_reconnect", "cloudflare_tunnel_connector_info",
	"cloudflare_tunnel_connectors", "cloudflare_tunnel_info", "cloudflare_tunnel_status",
	"cloudflare_tunnel_up", "cloudflare_tunnel_active_since_timestamp_seconds",
	"cloudflare_tunnel_inactive_since_timestamp_seconds",
}

func TestTunnelMetrics(t *testing.T) {
	fake := cftest.New()
	c, reg, _ := setup(t, fake, Options{TunnelMetrics: true})
	c.CollectOnce(context.Background())
	if err := testutil.GatherAndCompare(reg, strings.NewReader(tunnelExpected), tunnelFamilies...); err != nil {
		t.Fatal(err)
	}
	out := gather(t, reg, "cloudflare_exporter_up")
	for _, ds := range []string{`value:"tunnels"`, `value:"tunnel_connectors"`} {
		if !strings.Contains(out, ds) {
			t.Fatalf("missing %s status:\n%s", ds, out)
		}
	}
	if strings.Contains(out, "value:0") {
		t.Fatalf("all datasets should be up:\n%s", out)
	}
	if strings.Contains(gather(t, reg, tunnelFamilies...), "198.51.100") {
		t.Fatal("origin IP must never be exported")
	}
}

func TestTunnelConnectionsFallBackToListResponse(t *testing.T) {
	fake := cftest.New()
	fake.ConnectionsFail = true
	c, reg, _ := setup(t, fake, Options{TunnelMetrics: true})
	c.CollectOnce(context.Background())
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP cloudflare_tunnel_connectors Distinct connectors (cloudflared or WARP Connector instances) reported for the tunnel.
# TYPE cloudflare_tunnel_connectors gauge
cloudflare_tunnel_connectors{account="Example Account",tunnel="db-tunnel"} 0
cloudflare_tunnel_connectors{account="Example Account",tunnel="office-connector"} 1
cloudflare_tunnel_connectors{account="Example Account",tunnel="web-tunnel"} 2
# HELP cloudflare_tunnel_connections Edge connections of the tunnel.
# TYPE cloudflare_tunnel_connections gauge
cloudflare_tunnel_connections{account="Example Account",tunnel="db-tunnel"} 0
cloudflare_tunnel_connections{account="Example Account",tunnel="office-connector"} 1
cloudflare_tunnel_connections{account="Example Account",tunnel="web-tunnel"} 4
`), "cloudflare_tunnel_connectors", "cloudflare_tunnel_connections"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gather(t, reg, "cloudflare_tunnel_connector_info"), `value:"unknown"`) {
		t.Fatal("arch should be unknown when rebuilt from the list response")
	}
}

func TestTunnelPermissionMissing(t *testing.T) {
	fake := cftest.New()
	fake.TunnelsForbidden = true
	c, reg, _ := setup(t, fake, Options{TunnelMetrics: true, AccountMetrics: true})
	var logs bytes.Buffer
	c.log = slog.New(slog.NewTextHandler(&logs, nil))
	c.CollectOnce(context.Background())
	c.CollectOnce(context.Background())

	if n := strings.Count(logs.String(), "Cloudflare Tunnel > Read"); n != 1 {
		t.Fatalf("want exactly one permission warning, got %d:\n%s", n, logs.String())
	}
	if n := testutil.CollectAndCount(c, "cloudflare_tunnel_info"); n != 0 {
		t.Fatalf("no tunnel series expected, got %d", n)
	}
	// Everything else keeps working.
	if n := testutil.CollectAndCount(c, "cloudflare_zone_hourly_requests"); n != 3 {
		t.Fatalf("zone metrics should still work, got %d", n)
	}
	if n := testutil.CollectAndCount(c, "cloudflare_account_hourly_requests"); n != 1 {
		t.Fatalf("account metrics should still work, got %d", n)
	}
	if v, ok := upValue(t, reg, "tunnels"); !ok || v != 0 {
		t.Fatalf("cloudflare_exporter_up{dataset=\"tunnels\"} should be 0, got %v (present=%v)", v, ok)
	}
}

func upValue(t *testing.T, reg *prometheus.Registry, dataset string) (float64, bool) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "cloudflare_exporter_up" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "dataset" && l.GetValue() == dataset {
					return m.GetGauge().GetValue(), true
				}
			}
		}
	}
	return 0, false
}

func TestTunnelRemovedDisappears(t *testing.T) {
	fake := cftest.New()
	c, _, _ := setup(t, fake, Options{TunnelMetrics: true})
	c.CollectOnce(context.Background())
	if n := testutil.CollectAndCount(c, "cloudflare_tunnel_info"); n != 3 {
		t.Fatalf("want 3 tunnels, got %d", n)
	}
	fake.Tunnels = fake.Tunnels[:1]
	c.CollectOnce(context.Background())
	if n := testutil.CollectAndCount(c, "cloudflare_tunnel_info"); n != 1 {
		t.Fatalf("removed tunnels should disappear, got %d", n)
	}
	if n := testutil.CollectAndCount(c, "cloudflare_tunnel_connector_info"); n != 2 {
		t.Fatalf("connectors of removed tunnels should disappear, got %d", n)
	}
}

func TestTunnelMetricsDisabled(t *testing.T) {
	fake := cftest.New()
	c, _, _ := setup(t, fake, Options{})
	c.CollectOnce(context.Background())
	for p := range fake.RESTCalls {
		if strings.Contains(p, "tunnel") {
			t.Fatalf("tunnel endpoint called while disabled: %s", p)
		}
	}
}
