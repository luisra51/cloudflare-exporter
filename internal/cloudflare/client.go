// Package cloudflare is a small client for the parts of the Cloudflare REST
// and GraphQL Analytics APIs the exporter needs.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Observer receives notifications about API calls. It is used for the
// exporter self-metrics; a nil Observer is valid.
type Observer interface {
	APIError(api, operation string)
}

// Client talks to the Cloudflare API with a bearer token.
type Client struct {
	baseURL  string
	token    string
	http     *http.Client
	sem      chan struct{}
	observer Observer
	retries  int
	backoff  time.Duration
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient sets the underlying HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithObserver sets the observer for API errors.
func WithObserver(o Observer) Option { return func(c *Client) { c.observer = o } }

// WithConcurrency limits the number of in-flight requests.
func WithConcurrency(n int) Option {
	return func(c *Client) {
		if n > 0 {
			c.sem = make(chan struct{}, n)
		}
	}
}

// WithRetry sets the number of retries for 429/5xx responses and the base
// backoff between attempts.
func WithRetry(retries int, backoff time.Duration) Option {
	return func(c *Client) { c.retries, c.backoff = retries, backoff }
}

// New returns a client. baseURL is e.g. https://api.cloudflare.com/client/v4.
func New(baseURL, token string, opts ...Option) *Client {
	c := &Client{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
		sem:     make(chan struct{}, 4),
		retries: 2,
		backoff: 2 * time.Second,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// APIError is returned when Cloudflare answers with an error.
type APIError struct {
	Status   int
	Messages []string
}

func (e *APIError) Error() string {
	if len(e.Messages) == 0 {
		return fmt.Sprintf("cloudflare API: HTTP %d", e.Status)
	}
	return fmt.Sprintf("cloudflare API: HTTP %d: %v", e.Status, e.Messages)
}

func (c *Client) noteError(api, op string) {
	if c.observer != nil {
		c.observer.APIError(api, op)
	}
}

// do performs a request with retries on 429 and 5xx. body may be nil.
func (c *Client) do(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
	defer func() { <-c.sem }()

	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			wait := c.backoff * time.Duration(1<<(attempt-1))
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			}
		}
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "cloudflare-exporter")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			// Strip the URL details that net/http adds; they never contain
			// the token, but keep errors short.
			var uerr *url.Error
			if errors.As(err, &uerr) {
				err = uerr.Err
			}
			lastErr = fmt.Errorf("%s %s: %w", method, path, err)
			if ctx.Err() != nil {
				return nil, 0, lastErr
			}
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = &APIError{Status: resp.StatusCode, Messages: restErrorMessages(data)}
			if ra, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && ra > 0 && ra <= 60 {
				select {
				case <-time.After(time.Duration(ra) * time.Second):
				case <-ctx.Done():
					return nil, 0, ctx.Err()
				}
			}
			continue
		}
		return data, resp.StatusCode, nil
	}
	return nil, 0, lastErr
}

// ---------------------------------------------------------------- REST ----

// Zone is the subset of the REST zone object the exporter uses.
type Zone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Paused  bool   `json:"paused"`
	Plan    Plan   `json:"plan"`
	Account Ref    `json:"account"`
}

// Plan describes the zone plan.
type Plan struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	LegacyID string `json:"legacy_id"`
}

// Ref is an {id, name} pair.
type Ref struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PlanCode returns a short, lower-case plan identifier such as "free",
// "pro", "business" or "enterprise".
func (z Zone) PlanCode() string {
	if z.Plan.LegacyID != "" {
		return z.Plan.LegacyID
	}
	if z.Plan.Name != "" {
		return z.Plan.Name
	}
	return "unknown"
}

// IsFree reports whether the zone is on the Free plan.
func (z Zone) IsFree() bool { return z.PlanCode() == "free" }

type restEnvelope struct {
	Success    bool            `json:"success"`
	Errors     []restMessage   `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type restMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func restErrorMessages(data []byte) []string {
	var env restEnvelope
	if json.Unmarshal(data, &env) != nil {
		return nil
	}
	out := make([]string, 0, len(env.Errors))
	for _, e := range env.Errors {
		out = append(out, fmt.Sprintf("%d: %s", e.Code, e.Message))
	}
	return out
}

func (c *Client) restGet(ctx context.Context, op, path string) (*restEnvelope, error) {
	data, status, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		c.noteError("rest", op)
		return nil, err
	}
	var env restEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		c.noteError("rest", op)
		return nil, fmt.Errorf("decode %s: HTTP %d: %w", op, status, err)
	}
	if status >= 400 || !env.Success {
		c.noteError("rest", op)
		return nil, &APIError{Status: status, Messages: restErrorMessages(data)}
	}
	return &env, nil
}

// ListZones returns every zone visible to the token. If accountID is not
// empty, only zones of that account are returned.
func (c *Client) ListZones(ctx context.Context, accountID string) ([]Zone, error) {
	var all []Zone
	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("page", strconv.Itoa(page))
		q.Set("per_page", "50")
		if accountID != "" {
			q.Set("account.id", accountID)
		}
		env, err := c.restGet(ctx, "list_zones", "/zones?"+q.Encode())
		if err != nil {
			return nil, err
		}
		var zones []Zone
		if err := json.Unmarshal(env.Result, &zones); err != nil {
			c.noteError("rest", "list_zones")
			return nil, fmt.Errorf("decode zones: %w", err)
		}
		all = append(all, zones...)
		if env.ResultInfo == nil || page >= env.ResultInfo.TotalPages || len(zones) == 0 {
			return all, nil
		}
	}
}

// GetZone returns a single zone by id.
func (c *Client) GetZone(ctx context.Context, id string) (Zone, error) {
	env, err := c.restGet(ctx, "get_zone", "/zones/"+url.PathEscape(id))
	if err != nil {
		return Zone{}, err
	}
	var z Zone
	if err := json.Unmarshal(env.Result, &z); err != nil {
		c.noteError("rest", "get_zone")
		return Zone{}, fmt.Errorf("decode zone: %w", err)
	}
	return z, nil
}

// GetAccount returns the account name for an id.
func (c *Client) GetAccount(ctx context.Context, id string) (Ref, error) {
	env, err := c.restGet(ctx, "get_account", "/accounts/"+url.PathEscape(id))
	if err != nil {
		return Ref{}, err
	}
	var a Ref
	if err := json.Unmarshal(env.Result, &a); err != nil {
		c.noteError("rest", "get_account")
		return Ref{}, fmt.Errorf("decode account: %w", err)
	}
	return a, nil
}

// ------------------------------------------------------------- GraphQL ----

// GraphQLError is one entry of the GraphQL "errors" array.
type GraphQLError struct {
	Message string `json:"message"`
	Path    []any  `json:"path"`
}

// GraphQLErrors is returned when the response carries errors.
type GraphQLErrors []GraphQLError

func (e GraphQLErrors) Error() string {
	msgs := make([]string, 0, len(e))
	for _, m := range e {
		msgs = append(msgs, m.Message)
	}
	return fmt.Sprintf("cloudflare graphql: %v", msgs)
}

// GraphQL executes query with variables and decodes "data" into out.
// operation is a short name used in metrics.
func (c *Client) GraphQL(ctx context.Context, operation, query string, variables map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return err
	}
	data, status, err := c.do(ctx, http.MethodPost, "/graphql", body)
	if err != nil {
		c.noteError("graphql", operation)
		return err
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors GraphQLErrors   `json:"errors"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		c.noteError("graphql", operation)
		return fmt.Errorf("decode graphql %s: HTTP %d: %w", operation, status, err)
	}
	if len(env.Errors) > 0 {
		c.noteError("graphql", operation)
		return env.Errors
	}
	if status >= 400 {
		c.noteError("graphql", operation)
		return &APIError{Status: status}
	}
	if out != nil && len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, out); err != nil {
			c.noteError("graphql", operation)
			return fmt.Errorf("decode graphql %s data: %w", operation, err)
		}
	}
	return nil
}
