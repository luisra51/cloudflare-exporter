package config

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) LookupFunc {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestDefaults(t *testing.T) {
	c, err := Load(nil, env(map[string]string{"CF_API_TOKEN": "x"}), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.MetricsPath != "/metrics" || c.ScrapeInterval != 5*time.Minute ||
		c.HourlyDelay != 10*time.Minute || c.TopCountries != 20 || !c.FirewallEvents || !c.AccountMetrics || !c.TunnelMetrics {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestEnvAndFlags(t *testing.T) {
	e := env(map[string]string{
		"CF_API_TOKEN": "x", "CF_ZONES": " a, b ,,", "CF_EXCLUDE_ZONES": "c", "CF_ACCOUNTS": "d",
		"LISTEN": ":9000", "SCRAPE_INTERVAL": "1m", "LOG_FORMAT": "json",
	})
	c, err := Load([]string{"--listen", ":9100", "--top-countries", "5"}, e, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9100" || c.TopCountries != 5 || c.ScrapeInterval != time.Minute || c.LogFormat != "json" {
		t.Fatalf("flags should override env: %+v", c)
	}
	if strings.Join(c.Zones, "|") != "a|b" || c.ExcludeZones[0] != "c" || c.Accounts[0] != "d" {
		t.Fatalf("lists not parsed: %+v", c)
	}
}

func TestValidation(t *testing.T) {
	_, err := Load(nil, env(map[string]string{"SCRAPE_INTERVAL": "nope", "LOG_FORMAT": "xml", "METRICS_PATH": "metrics"}), &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"CF_API_TOKEN", "SCRAPE_INTERVAL", "LOG_FORMAT", "METRICS_PATH"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s: %v", want, err)
		}
	}
}

func TestTokenNeverInHelpOrString(t *testing.T) {
	const secret = "s3cr3t-token-value"
	var out bytes.Buffer
	_, err := Load([]string{"--help"}, env(map[string]string{"CF_API_TOKEN": secret}), &out)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("want ErrHelp, got %v", err)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatal("token leaked into --help output")
	}
	c, err := Load(nil, env(map[string]string{"CF_API_TOKEN": secret}), &out)
	if err != nil {
		t.Fatal(err)
	}
	if c.APIToken != secret {
		t.Fatal("token from env not applied")
	}
	if strings.Contains(c.String(), secret) {
		t.Fatal("token leaked into String()")
	}
}
