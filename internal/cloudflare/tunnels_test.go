package cloudflare_test

import (
	"context"
	"testing"

	"github.com/luisra51/cloudflare-exporter/internal/cftest"
	"github.com/luisra51/cloudflare-exporter/internal/cloudflare"
)

func TestListTunnelsFiltersTypes(t *testing.T) {
	c := newClient(t, cftest.New())
	tunnels, err := c.ListTunnels(context.Background(), cftest.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnels) != 3 {
		t.Fatalf("want 3 tunnels (gre filtered out), got %d: %+v", len(tunnels), tunnels)
	}
	byID := map[string]cloudflare.Tunnel{}
	for _, tn := range tunnels {
		byID[tn.ID] = tn
	}
	if byID[cftest.TunnelWARP].Type != cloudflare.TunnelTypeWARPConnector {
		t.Fatalf("warp connector type lost: %+v", byID[cftest.TunnelWARP])
	}
	down := byID[cftest.TunnelDown]
	if down.Status != "down" || !down.ConnsActiveAt.IsZero() || down.ConnsInactiveAt.IsZero() || len(down.Connections) != 0 {
		t.Fatalf("down tunnel parsed wrong: %+v", down)
	}
	if len(byID[cftest.TunnelHealthy].Connections) != 4 {
		t.Fatalf("embedded connections not parsed: %+v", byID[cftest.TunnelHealthy])
	}
}

func TestListTunnelsPaginates(t *testing.T) {
	fake := cftest.New()
	base := fake.Tunnels[0]
	for i := 0; i < 230; i++ {
		cp := map[string]any{}
		for k, v := range base {
			cp[k] = v
		}
		cp["id"] = base["id"].(string) + "-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		fake.Tunnels = append(fake.Tunnels, cp)
	}
	c := newClient(t, fake)
	tunnels, err := c.ListTunnels(context.Background(), cftest.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnels) != 233 {
		t.Fatalf("want 233 tunnels across pages, got %d", len(tunnels))
	}
}

func TestListTunnelsFallsBackToCfdTunnel(t *testing.T) {
	fake := cftest.New()
	fake.TunnelsLegacyOnly = true
	c := newClient(t, fake)
	tunnels, err := c.ListTunnels(context.Background(), cftest.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnels) != 2 {
		t.Fatalf("want the 2 cfd tunnels from the legacy endpoint, got %d", len(tunnels))
	}
}

func TestListTunnelsAuthError(t *testing.T) {
	fake := cftest.New()
	fake.TunnelsForbidden = true
	c := newClient(t, fake)
	_, err := c.ListTunnels(context.Background(), cftest.AccountID)
	if !cloudflare.IsAuthError(err) {
		t.Fatalf("want auth error, got %v", err)
	}
	if fake.RESTCalls["/accounts/"+cftest.AccountID+"/cfd_tunnel"] != 0 {
		t.Fatal("an auth error must not trigger the legacy fallback")
	}
}

func TestTunnelConnectors(t *testing.T) {
	c := newClient(t, cftest.New())
	cs, err := c.TunnelConnectors(context.Background(), cftest.AccountID, cloudflare.Tunnel{ID: cftest.TunnelHealthy, Type: "cfd_tunnel"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 || cs[1].Arch != "linux_arm64" || len(cs[1].Conns) != 2 || !cs[1].Conns[1].IsPendingReconnect {
		t.Fatalf("unexpected connectors: %+v", cs)
	}
	cs, err = c.TunnelConnectors(context.Background(), cftest.AccountID, cloudflare.Tunnel{ID: cftest.TunnelDown, Type: "cfd_tunnel"})
	if err != nil || len(cs) != 0 {
		t.Fatalf("down tunnel should have no connectors: %v %+v", err, cs)
	}
}
