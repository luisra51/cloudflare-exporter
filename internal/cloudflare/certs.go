package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

// CertificatePack is an edge certificate pack of a zone.
type CertificatePack struct {
	ID                   string
	Type                 string
	Status               string
	CertificateAuthority string
	// EarliestExpiry is the earliest expires_on among the pack's
	// certificates; zero if none is reported.
	EarliestExpiry time.Time
}

// CertificatePacks lists every certificate pack of a zone (status=all).
func (c *Client) CertificatePacks(ctx context.Context, zoneID string) ([]CertificatePack, error) {
	var out []CertificatePack
	q := url.Values{}
	q.Set("status", "all")
	err := c.paginate(ctx, "certificate_packs", "/zones/"+url.PathEscape(zoneID)+"/ssl/certificate_packs", q, 50,
		func(raw json.RawMessage) (int, error) {
			var items []struct {
				ID                   string `json:"id"`
				Type                 string `json:"type"`
				Status               string `json:"status"`
				CertificateAuthority string `json:"certificate_authority"`
				Certificates         []struct {
					ExpiresOn *string `json:"expires_on"`
				} `json:"certificates"`
			}
			if err := json.Unmarshal(raw, &items); err != nil {
				return 0, err
			}
			for _, p := range items {
				cp := CertificatePack{ID: p.ID, Type: p.Type, Status: p.Status, CertificateAuthority: p.CertificateAuthority}
				for _, cert := range p.Certificates {
					if t := parseTime(cert.ExpiresOn); !t.IsZero() && (cp.EarliestExpiry.IsZero() || t.Before(cp.EarliestExpiry)) {
						cp.EarliestExpiry = t
					}
				}
				out = append(out, cp)
			}
			return len(items), nil
		})
	return out, err
}
