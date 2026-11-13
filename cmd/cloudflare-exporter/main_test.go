package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpAndVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if rc := run([]string{"--help"}, &out, &errOut); rc != 0 {
		t.Fatalf("--help rc=%d", rc)
	}
	if !strings.Contains(out.String(), "CF_API_TOKEN") {
		t.Fatalf("help should document env vars:\n%s", out.String())
	}
	out.Reset()
	if rc := run([]string{"--version"}, &out, &errOut); rc != 0 || !strings.Contains(out.String(), "cloudflare-exporter") {
		t.Fatalf("--version rc=%d out=%q", rc, out.String())
	}
}

func TestMissingTokenFails(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "")
	var out, errOut bytes.Buffer
	if rc := run(nil, &out, &errOut); rc != 2 || !strings.Contains(errOut.String(), "CF_API_TOKEN") {
		t.Fatalf("rc=%d err=%q", rc, errOut.String())
	}
}
