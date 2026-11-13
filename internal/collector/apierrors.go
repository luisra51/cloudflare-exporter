package collector

import "github.com/prometheus/client_golang/prometheus"

// APIErrors counts failed Cloudflare API calls. It implements
// cloudflare.Observer.
type APIErrors struct {
	vec *prometheus.CounterVec
}

// NewAPIErrors returns a registered-ready API error counter.
func NewAPIErrors() *APIErrors {
	return &APIErrors{vec: prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cloudflare_exporter_api_errors_total",
		Help: "Failed Cloudflare API calls by API (rest, graphql) and operation (REST call or GraphQL dataset).",
	}, []string{"api", "operation"})}
}

// APIError implements cloudflare.Observer.
func (a *APIErrors) APIError(api, operation string) { a.vec.WithLabelValues(api, operation).Inc() }

// Collector returns the underlying collector for registration.
func (a *APIErrors) Collector() prometheus.Collector { return a.vec }
