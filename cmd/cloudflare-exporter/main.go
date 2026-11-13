// Command cloudflare-exporter exports Cloudflare analytics as Prometheus
// metrics. It works with Free-plan zones.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/luisra51/cloudflare-exporter/internal/cloudflare"
	"github.com/luisra51/cloudflare-exporter/internal/collector"
	"github.com/luisra51/cloudflare-exporter/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Set at build time with -ldflags "-X main.version=...".
var (
	version  = "dev"
	revision = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(args, os.LookupEnv, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "configuration error:\n%v\n", err)
		return 2
	}
	if cfg.ShowVersion {
		_, _ = fmt.Fprintf(stdout, "cloudflare-exporter %s (%s, %s)\n", version, revision, runtime.Version())
		return 0
	}

	logger := newLogger(cfg, stderr)
	logger.Info("starting cloudflare-exporter", "version", version, "config", cfg.String())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	apiErrors := collector.NewAPIErrors()
	client := cloudflare.New(cfg.APIURL, cfg.APIToken,
		cloudflare.WithHTTPClient(&http.Client{Timeout: cfg.HTTPTimeout}),
		cloudflare.WithConcurrency(cfg.Concurrency),
		cloudflare.WithObserver(apiErrors),
	)
	col := collector.New(client, collector.Options{
		Zones:          cfg.Zones,
		ExcludeZones:   cfg.ExcludeZones,
		Accounts:       cfg.Accounts,
		Interval:       cfg.ScrapeInterval,
		HourlyDelay:    cfg.HourlyDelay,
		TopCountries:   cfg.TopCountries,
		FirewallEvents: cfg.FirewallEvents,
		AccountMetrics: cfg.AccountMetrics,
		TunnelMetrics:  cfg.TunnelMetrics,

		HostMetrics:      cfg.HostMetrics,
		HostExactStatus:  cfg.HostExactStatus,
		TopHosts:         cfg.TopHosts,
		AdaptiveWindow:   cfg.AdaptiveWindow,
		AdaptiveDelay:    cfg.AdaptiveDelay,
		ZeroTrustMetrics: cfg.ZeroTrustMetrics,
		DevicesInterval:  cfg.DevicesInterval,
		CertMetrics:      cfg.CertMetrics,
	}, logger)

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		col,
		apiErrors.Collector(),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "cloudflare_exporter_build_info",
			Help:        "Build information. Always 1.",
			ConstLabels: prometheus.Labels{"version": version, "revision": revision, "goversion": runtime.Version()},
		}, func() float64 { return 1 }),
	)
	reg.MustRegister(col.SelfMetrics()...)

	mux := http.NewServeMux()
	mux.Handle(cfg.MetricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError)}))
	mux.HandleFunc("/healthz", healthHandler(col))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<html><head><title>Cloudflare exporter</title></head><body><h1>Cloudflare exporter</h1><p><a href="%s">Metrics</a> &middot; <a href="/healthz">Health</a></p></body></html>`, html.EscapeString(cfg.MetricsPath))
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		col.Run(ctx)
	}()

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "address", cfg.Listen, "metrics_path", cfg.MetricsPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()

	exit := 0
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-serveErr:
		if err != nil {
			logger.Error("http server failed", "err", err)
			exit = 1
		}
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
	}
	select {
	case <-done:
	case <-shutdownCtx.Done():
		logger.Warn("collection loop did not stop in time")
	}
	return exit
}

func healthHandler(col *collector.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		ok, last := col.Healthy()
		body := map[string]any{"status": "ok", "zone_discovery_succeeded": ok}
		if !last.IsZero() {
			body["last_collection"] = last.UTC().Format(time.RFC3339)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

func newLogger(cfg config.Config, w io.Writer) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}
