package rspamd_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/isaiahiroko/envelope/internal/filter/rspamd"
)

func TestCheckParsesVerdict(t *testing.T) {
	var gotMethod, gotPath, gotFrom string
	var gotRcpts []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotFrom = r.Header.Get("From")
		gotRcpts = r.Header.Values("Rcpt")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"action":         "no action",
			"score":          2.5,
			"required_score": 15.0,
			"symbols": map[string]any{
				"BAYES_HAM": map[string]any{"name": "BAYES_HAM", "score": -1.5},
				"R_SPF_ALLOW": map[string]any{
					"name": "R_SPF_ALLOW", "score": 0.0,
				},
			},
		})
	}))
	defer srv.Close()

	c := rspamd.New(srv.URL)
	verdict, err := c.Check(context.Background(), "sender@example.com", []string{"a@example.com", "b@example.com"}, strings.NewReader("From: sender@example.com\r\n\r\nbody"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	if gotMethod != http.MethodPost || gotPath != "/checkv2" {
		t.Fatalf("unexpected request: %s %s", gotMethod, gotPath)
	}
	if gotFrom != "sender@example.com" {
		t.Fatalf("From header = %q", gotFrom)
	}
	if len(gotRcpts) != 2 || gotRcpts[0] != "a@example.com" || gotRcpts[1] != "b@example.com" {
		t.Fatalf("Rcpt headers = %v", gotRcpts)
	}

	if verdict.Action != "no action" || verdict.Score != 2.5 || verdict.RequiredScore != 15.0 {
		t.Fatalf("unexpected verdict: %+v", verdict)
	}
	if verdict.Symbols["BAYES_HAM"] != -1.5 || verdict.Symbols["R_SPF_ALLOW"] != 0.0 {
		t.Fatalf("unexpected symbols: %+v", verdict.Symbols)
	}
}

func TestCheckNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := rspamd.New(srv.URL)
	if _, err := c.Check(context.Background(), "a@example.com", nil, strings.NewReader("x")); err == nil {
		t.Fatal("expected error for non-200 response")
	}
}
