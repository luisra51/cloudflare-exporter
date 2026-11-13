// Command fake-cloudflare serves a fake Cloudflare API with synthetic data,
// for trying the exporter locally without a Cloudflare account:
//
//	go run ./hack/fake-cloudflare -listen :8787
//	CF_API_TOKEN=test-token CF_API_URL=http://localhost:8787 go run ./cmd/cloudflare-exporter
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/luisra51/cloudflare-exporter/internal/cftest"
)

func main() {
	listen := flag.String("listen", ":8787", "listen address")
	flag.Parse()
	log.Printf("fake Cloudflare API on %s (token %q)", *listen, cftest.Token)
	srv := &http.Server{Addr: *listen, Handler: cftest.New(), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
