package logger

import (
	"context"
	"log/slog"
	"os"
	"sync"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const requestIDKey contextKey = "request_id"

var (
	logger *slog.Logger
	once   sync.Once
)

// Init initializes the global logger with the given level.
func Init(level string) {
	once.Do(func() {
		var logLevel slog.Level
		switch level {
		case "DEBUG":
			logLevel = slog.LevelDebug
		case "INFO":
			logLevel = slog.LevelInfo
		case "WARN":
			logLevel = slog.LevelWarn
		case "ERROR":
			logLevel = slog.LevelError
		default:
			logLevel = slog.LevelInfo
		}

		opts := &slog.HandlerOptions{
			Level: logLevel,
		}

		handler := slog.NewJSONHandler(os.Stdout, opts)
		logger = slog.New(handler)
	})
}

// GetLogger returns the global logger.
func GetLogger() *slog.Logger {
	if logger == nil {
		Init("INFO")
	}
	return logger
}

// WithRequestID returns a new context with the request ID attached.
func WithRequestID(ctx context.Context, requestID int) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// RequestIDFromContext extracts the request ID from context.
func RequestIDFromContext(ctx context.Context) int {
	if v := ctx.Value(requestIDKey); v != nil {
		if id, ok := v.(int); ok {
			return id
		}
	}
	return 0
}

// LoggerForContext returns a logger instance with request ID from context.
func LoggerForContext(ctx context.Context) *slog.Logger {
	base := GetLogger()
	if requestID := RequestIDFromContext(ctx); requestID != 0 {
		return base.With("request_id", requestID)
	}
	return base
}

// Debug logs a debug message.
func Debug(ctx context.Context, msg string, args ...any) {
	loggerForCtx := LoggerForContext(ctx)
	loggerForCtx.Debug(msg, args...)
}

// Info logs an info message.
func Info(ctx context.Context, msg string, args ...any) {
	loggerForCtx := LoggerForContext(ctx)
	loggerForCtx.Info(msg, args...)
}

// Warn logs a warning message.
func Warn(ctx context.Context, msg string, args ...any) {
	loggerForCtx := LoggerForContext(ctx)
	loggerForCtx.Warn(msg, args...)
}

// Error logs an error message.
func Error(ctx context.Context, msg string, args ...any) {
	loggerForCtx := LoggerForContext(ctx)
	loggerForCtx.Error(msg, args...)
}
