package rspamd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Verdict is rspamd's checkv2 scan result, trimmed to the fields the filter
// pipeline needs to act on (TRD FR-2.4/FR-2.5). Real accept/quarantine/
// reject decisions are wired in Phase 4 — this client only fetches and
// parses the score.
type Verdict struct {
	Action        string             `json:"action"`
	Score         float64            `json:"score"`
	RequiredScore float64            `json:"required_score"`
	Symbols       map[string]float64 `json:"-"`
}

// rspamd represents each symbol as an object ({"name": ..., "score": ...}),
// not a bare number, so Verdict.Symbols is populated from this shape rather
// than unmarshaled directly.
type rawResponse struct {
	Action        string  `json:"action"`
	Score         float64 `json:"score"`
	RequiredScore float64 `json:"required_score"`
	Symbols       map[string]struct {
		Score float64 `json:"score"`
	} `json:"symbols"`
}

// Client is an HTTP client for an rspamd sidecar's checkv2 endpoint
// (TRD §9: rspamd, run as sidecar).
type Client struct {
	baseURL string
	http    *http.Client
}

// clientTimeout bounds how long Check waits for rspamd before the FR-2.6
// fail-open path takes over. Kept short (rspamd's own scan time is
// normally well under a second) so an unreachable/hung rspamd degrades
// inbound latency by seconds, not by however long the caller's own
// timeout happens to be — observed directly running Phase 4 against no
// rspamd at all: 10s made single-recipient delivery noticeably sluggish.
const clientTimeout = 3 * time.Second

// New returns a Client that scans messages via the rspamd instance at
// baseURL (e.g. "http://rspamd:11333").
func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: clientTimeout},
	}
}

// Check submits a message to rspamd's checkv2 endpoint and returns its
// verdict. from and rcpts populate the envelope headers rspamd's symbols
// (SPF, DMARC alignment, etc.) key off; body is the raw RFC 5322 message.
func (c *Client) Check(ctx context.Context, from string, rcpts []string, body io.Reader) (*Verdict, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/checkv2", body)
	if err != nil {
		return nil, fmt.Errorf("rspamd: build request: %w", err)
	}
	if from != "" {
		req.Header.Set("From", from)
	}
	for _, rcpt := range rcpts {
		req.Header.Add("Rcpt", rcpt)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rspamd: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rspamd: unexpected status %d", resp.StatusCode)
	}

	var raw rawResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("rspamd: decode response: %w", err)
	}

	symbols := make(map[string]float64, len(raw.Symbols))
	for name, sym := range raw.Symbols {
		symbols[name] = sym.Score
	}

	return &Verdict{
		Action:        raw.Action,
		Score:         raw.Score,
		RequiredScore: raw.RequiredScore,
		Symbols:       symbols,
	}, nil
}
