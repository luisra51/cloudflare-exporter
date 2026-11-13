// Package config loads the exporter configuration from environment variables
// and command-line flags. Flags take precedence over environment variables.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the runtime configuration of the exporter.
type Config struct {
	APIToken string // never log this value

	APIURL string // Cloudflare API base URL, e.g. https://api.cloudflare.com/client/v4

	Zones        []string // optional zone-id allowlist
	ExcludeZones []string // zone ids to skip
	Accounts     []string // optional account-id allowlist

	Listen      string
	MetricsPath string

	ScrapeInterval time.Duration
	HourlyDelay    time.Duration
	HTTPTimeout    time.Duration
	Concurrency    int

	TopCountries   int
	FirewallEvents bool
	AccountMetrics bool

	LogLevel  string
	LogFormat string

	ShowVersion bool
}

// String renders the configuration without the API token.
func (c Config) String() string {
	return fmt.Sprintf("api_url=%s zones=%d exclude_zones=%d accounts=%d listen=%s metrics_path=%s scrape_interval=%s hourly_delay=%s concurrency=%d top_countries=%d firewall_events=%t account_metrics=%t",
		c.APIURL, len(c.Zones), len(c.ExcludeZones), len(c.Accounts), c.Listen, c.MetricsPath,
		c.ScrapeInterval, c.HourlyDelay, c.Concurrency, c.TopCountries, c.FirewallEvents, c.AccountMetrics)
}

// LookupFunc mirrors os.LookupEnv so tests can inject an environment.
type LookupFunc func(string) (string, bool)

// Load parses args (without the program name) using env as the source of
// defaults. Usage output is written to out.
func Load(args []string, env LookupFunc, out io.Writer) (Config, error) {
	if env == nil {
		env = os.LookupEnv
	}
	get := func(key, def string) string {
		if v, ok := env(key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return def
	}

	fs := flag.NewFlagSet("cloudflare-exporter", flag.ContinueOnError)
	fs.SetOutput(out)

	var (
		c                                  Config
		zones, excludeZones, accounts      string
		scrapeInterval, hourlyDelay, httpT string
		concurrency, topCountries          string
		firewall, accountMetrics           string
	)

	// The token default is not taken from the environment here so that
	// --help never prints it; the env var is applied after parsing.
	fs.StringVar(&c.APIToken, "api-token", "", "Cloudflare API token (env CF_API_TOKEN). Prefer the env var: flags are visible in the process list.")
	fs.StringVar(&c.APIURL, "api-url", get("CF_API_URL", "https://api.cloudflare.com/client/v4"), "Cloudflare API base URL (env CF_API_URL)")
	fs.StringVar(&zones, "zones", get("CF_ZONES", ""), "comma-separated zone IDs to collect; empty = every zone the token can see (env CF_ZONES)")
	fs.StringVar(&excludeZones, "exclude-zones", get("CF_EXCLUDE_ZONES", ""), "comma-separated zone IDs to skip (env CF_EXCLUDE_ZONES)")
	fs.StringVar(&accounts, "accounts", get("CF_ACCOUNTS", ""), "comma-separated account IDs; restricts zone discovery and account metrics (env CF_ACCOUNTS)")
	fs.StringVar(&c.Listen, "listen", get("LISTEN", ":8080"), "HTTP listen address (env LISTEN)")
	fs.StringVar(&c.MetricsPath, "metrics-path", get("METRICS_PATH", "/metrics"), "path for the metrics endpoint (env METRICS_PATH)")
	fs.StringVar(&scrapeInterval, "scrape-interval", get("SCRAPE_INTERVAL", "5m"), "how often to query Cloudflare in the background (env SCRAPE_INTERVAL)")
	fs.StringVar(&hourlyDelay, "hourly-delay", get("CF_HOURLY_DELAY", "10m"), "wait this long after an hour ends before reporting it (env CF_HOURLY_DELAY)")
	fs.StringVar(&httpT, "http-timeout", get("CF_HTTP_TIMEOUT", "30s"), "timeout for each Cloudflare API request (env CF_HTTP_TIMEOUT)")
	fs.StringVar(&concurrency, "concurrency", get("CF_CONCURRENCY", "4"), "maximum concurrent Cloudflare API requests (env CF_CONCURRENCY)")
	fs.StringVar(&topCountries, "top-countries", get("CF_TOP_COUNTRIES", "20"), "countries exported per zone; the rest are summed as country=\"other\"; 0 disables country metrics (env CF_TOP_COUNTRIES)")
	fs.StringVar(&firewall, "firewall-events", get("CF_FIREWALL_EVENTS", "true"), "collect firewall (security) events (env CF_FIREWALL_EVENTS)")
	fs.StringVar(&accountMetrics, "account-metrics", get("CF_ACCOUNT_METRICS", "true"), "collect account-level HTTP metrics (env CF_ACCOUNT_METRICS)")
	fs.StringVar(&c.LogLevel, "log-level", get("LOG_LEVEL", "info"), "log level: debug, info, warn, error (env LOG_LEVEL)")
	fs.StringVar(&c.LogFormat, "log-format", get("LOG_FORMAT", "text"), "log format: text or json (env LOG_FORMAT)")
	fs.BoolVar(&c.ShowVersion, "version", false, "print version and exit")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "cloudflare-exporter: Prometheus exporter for Cloudflare analytics (works with Free-plan zones)\n\nUsage:\n  cloudflare-exporter [flags]\n\nEvery flag can also be set with the environment variable shown in its description.\n\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if c.ShowVersion {
		return c, nil
	}

	if c.APIToken == "" {
		c.APIToken = get("CF_API_TOKEN", "")
	}

	var err error
	c.Zones = splitList(zones)
	c.ExcludeZones = splitList(excludeZones)
	c.Accounts = splitList(accounts)

	var errs []error
	if c.APIToken == "" {
		errs = append(errs, errors.New("CF_API_TOKEN is required"))
	}
	if c.ScrapeInterval, err = parsePositiveDuration("SCRAPE_INTERVAL", scrapeInterval); err != nil {
		errs = append(errs, err)
	}
	if c.HourlyDelay, err = time.ParseDuration(hourlyDelay); err != nil || c.HourlyDelay < 0 {
		errs = append(errs, fmt.Errorf("CF_HOURLY_DELAY: invalid duration %q", hourlyDelay))
	}
	if c.HTTPTimeout, err = parsePositiveDuration("CF_HTTP_TIMEOUT", httpT); err != nil {
		errs = append(errs, err)
	}
	if c.Concurrency, err = strconv.Atoi(concurrency); err != nil || c.Concurrency < 1 {
		errs = append(errs, fmt.Errorf("CF_CONCURRENCY: must be a positive integer, got %q", concurrency))
	}
	if c.TopCountries, err = strconv.Atoi(topCountries); err != nil || c.TopCountries < 0 {
		errs = append(errs, fmt.Errorf("CF_TOP_COUNTRIES: must be a non-negative integer, got %q", topCountries))
	}
	if c.FirewallEvents, err = strconv.ParseBool(firewall); err != nil {
		errs = append(errs, fmt.Errorf("CF_FIREWALL_EVENTS: invalid boolean %q", firewall))
	}
	if c.AccountMetrics, err = strconv.ParseBool(accountMetrics); err != nil {
		errs = append(errs, fmt.Errorf("CF_ACCOUNT_METRICS: invalid boolean %q", accountMetrics))
	}
	if !strings.HasPrefix(c.MetricsPath, "/") {
		errs = append(errs, fmt.Errorf("METRICS_PATH must start with '/', got %q", c.MetricsPath))
	}
	if c.MetricsPath == "/healthz" {
		errs = append(errs, errors.New("METRICS_PATH cannot be /healthz"))
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		errs = append(errs, fmt.Errorf("LOG_FORMAT must be text or json, got %q", c.LogFormat))
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "warning", "error":
	default:
		errs = append(errs, fmt.Errorf("LOG_LEVEL must be debug, info, warn or error, got %q", c.LogLevel))
	}
	c.APIURL = strings.TrimRight(c.APIURL, "/")

	return c, errors.Join(errs...)
}

func parsePositiveDuration(name, v string) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: must be a positive duration, got %q", name, v)
	}
	return d, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
