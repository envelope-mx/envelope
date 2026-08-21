package logging_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/envelope-mx/envelope/internal/logging"
)

func TestJSONLoggerAttachesCorrelationIDFromContext(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewJSONLogger(&buf, slog.LevelInfo)

	ctx := logging.WithCorrelationID(context.Background(), "corr-123")
	logger.InfoContext(ctx, "message stored", "mailbox", "INBOX")

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("output is not valid JSON: %v (raw: %s)", err, buf.String())
	}
	if record["correlation_id"] != "corr-123" {
		t.Fatalf("correlation_id = %v, want corr-123", record["correlation_id"])
	}
	if record["msg"] != "message stored" {
		t.Fatalf("msg = %v, want %q", record["msg"], "message stored")
	}
	if record["mailbox"] != "INBOX" {
		t.Fatalf("mailbox = %v, want INBOX", record["mailbox"])
	}
}

func TestJSONLoggerOmitsCorrelationIDWhenAbsent(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewJSONLogger(&buf, slog.LevelInfo)

	logger.InfoContext(context.Background(), "no correlation here")

	if strings.Contains(buf.String(), "correlation_id") {
		t.Fatalf("expected no correlation_id field, got: %s", buf.String())
	}
}

func TestJSONLoggerRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewJSONLogger(&buf, slog.LevelWarn)

	logger.InfoContext(context.Background(), "should be filtered out")
	if buf.Len() != 0 {
		t.Fatalf("expected Info to be suppressed at Warn level, got: %s", buf.String())
	}

	logger.WarnContext(context.Background(), "should appear")
	if buf.Len() == 0 {
		t.Fatalf("expected Warn to be logged")
	}
}

func TestTwoDistinctCorrelationIDsAreDistinct(t *testing.T) {
	a, b := logging.NewCorrelationID(), logging.NewCorrelationID()
	if a == b {
		t.Fatalf("expected distinct correlation IDs, got %q twice", a)
	}
}

func TestLevelFromEnv(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"":        slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"bogus":   slog.LevelInfo,
	}
	for in, want := range cases {
		if got := logging.LevelFromEnv(in); got != want {
			t.Errorf("LevelFromEnv(%q) = %v, want %v", in, got, want)
		}
	}
}
