package logger

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestGetLoggerAutoInit must be the first test in this file: it exercises the
// `logger == nil` auto-init path before any other test initializes the logger.
func TestGetLoggerAutoInit(t *testing.T) {
	l := GetLogger()
	if l == nil {
		t.Fatal("GetLogger returned nil")
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"DEBUG":   slog.LevelDebug,
		"INFO":    slog.LevelInfo,
		"WARN":    slog.LevelWarn,
		"ERROR":   slog.LevelError,
		"UNKNOWN": slog.LevelInfo,
		"":        slog.LevelInfo,
	}
	for input, want := range cases {
		if got := parseLevel(input); got != want {
			t.Errorf("parseLevel(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestInitWriterSmoke(t *testing.T) {
	var buf bytes.Buffer
	InitWriter("INFO", &buf)
	if GetLogger() == nil {
		t.Fatal("logger not initialized after InitWriter")
	}
}

func TestLogAttrs(t *testing.T) {
	// The global logger is bound to os.Stdout by TestGetLoggerAutoInit (sync.Once),
	// so here we only verify the call path runs without panicking.
	LogAttrs(context.Background(), slog.LevelInfo, "hello", slog.String("k", "v"))
}

func TestWithRequestID(t *testing.T) {
	ctx := WithRequestID(context.Background(), 42)
	if got := RequestIDFromContext(ctx); got != 42 {
		t.Fatalf("RequestIDFromContext = %d, want 42", got)
	}
}

func TestRequestIDFromContextMismatchType(t *testing.T) {
	ctx := context.WithValue(context.Background(), requestIDKey, "not-an-int")
	if got := RequestIDFromContext(ctx); got != 0 {
		t.Fatalf("RequestIDFromContext(mismatched type) = %d, want 0", got)
	}
}

func TestRequestIDFromContextNil(t *testing.T) {
	if got := RequestIDFromContext(context.Background()); got != 0 {
		t.Fatalf("RequestIDFromContext(empty) = %d, want 0", got)
	}
}

func TestWarpSlogHandleWithAndWithoutRequestID(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	w := &warpSlogHandle{handler}

	mkRecord := func() slog.Record {
		return slog.NewRecord(time.Now(), slog.LevelInfo, "msg", 0)
	}

	// With request ID in context -> req_id attr added.
	withID := mkRecord()
	ctxWithID := WithRequestID(context.Background(), 7)
	if err := w.Handle(ctxWithID, withID); err != nil {
		t.Fatalf("Handle(with id) error = %v", err)
	}
	if !strings.Contains(buf.String(), "req_id=7") {
		t.Fatalf("expected req_id attr, got %q", buf.String())
	}

	buf.Reset()
	// Without request ID -> no req_id attr.
	noID := mkRecord()
	if err := w.Handle(context.Background(), noID); err != nil {
		t.Fatalf("Handle(no id) error = %v", err)
	}
	if strings.Contains(buf.String(), "req_id") {
		t.Fatalf("unexpected req_id attr, got %q", buf.String())
	}
}
