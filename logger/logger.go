package logger

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Level defines the logging severity level
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// toSlogLevel converts an internal Level to the equivalent slog.Level
func (l Level) toSlogLevel() slog.Level {
	switch l {
	case LevelDebug:
		return slog.LevelDebug
	case LevelInfo:
		return slog.LevelInfo
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// fromSlogLevel converts a slog.Level to the closest internal Level
func fromSlogLevel(sl slog.Level) Level {
	switch {
	case sl < slog.LevelInfo:
		return LevelDebug
	case sl < slog.LevelWarn:
		return LevelInfo
	case sl < slog.LevelError:
		return LevelWarn
	default:
		return LevelError
	}
}

type Logger interface {
	Debug(format string, args ...any)
	Info(format string, args ...any)
	Warn(format string, args ...any)
	Error(format string, args ...any)
	Close() error
}

var _ Logger = (*FileLogger)(nil)

// FileLogger base structure
type FileLogger struct {
	mu          sync.RWMutex
	prefix      string
	level       Level
	stdout      bool
	file        *os.File
	filePath    string
	maxSize     int64 // Maximum bytes per individual file, defaults to 10MB
	currentSize int64

	// Real-time streaming support (subscribed via API)
	brokers    map[chan string]struct{}
	register   chan chan string
	unregister chan chan string
	logChan    chan string
}

// Options initialization configuration parameters
type Options struct {
	Prefix   string
	Level    Level
	Stdout   bool
	FilePath string // If empty, logs will not be written to a file
	MaxSize  int64  // Size in bytes
}

// New creates a completely new logger instance
func New(opts Options) (*FileLogger, error) {
	if opts.MaxSize <= 0 {
		opts.MaxSize = 10 * 1024 * 1024 // Defaults to 10MB
	}

	l := &FileLogger{
		prefix:     opts.Prefix,
		level:      opts.Level,
		stdout:     opts.Stdout,
		filePath:   opts.FilePath,
		maxSize:    opts.MaxSize,
		brokers:    make(map[chan string]struct{}),
		register:   make(chan chan string),
		unregister: make(chan chan string),
		logChan:    make(chan string, 1024),
	}

	if l.filePath != "" {
		if err := l.initFile(); err != nil {
			return nil, err
		}
	}

	// Start the API stream broker
	go l.startBroker()

	return l, nil
}

func (l *FileLogger) initFile() error {
	dir := filepath.Dir(l.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	fi, err := f.Stat()
	if err == nil {
		l.currentSize = fi.Size()
	}

	l.file = f
	return nil
}

// checkRotate checks and rotates the log file if necessary
func (l *FileLogger) checkRotate(writeLen int) {
	if l.file == nil {
		return
	}

	if l.currentSize+int64(writeLen) > l.maxSize {
		l.file.Close()

		// Backup the old file: log.txt -> log.txt.20260708_150405
		backupPath := fmt.Sprintf("%s.%s", l.filePath, time.Now().Format("20060102_150405"))
		_ = os.Rename(l.filePath, backupPath)

		_ = l.initFile()
	}
}

// startBroker dispatches real-time log records to all active Web API rolling windows
func (l *FileLogger) startBroker() {
	for {
		select {
		case ch := <-l.register:
			l.brokers[ch] = struct{}{}
		case ch := <-l.unregister:
			delete(l.brokers, ch)
			close(ch)
		case msg := <-l.logChan:
			for ch := range l.brokers {
				select {
				case ch <- msg:
				default: // Drop message if buffer is full to prevent slow clients from blocking the core pipeline
				}
			}
		}
	}
}

// output unified core for formatted log output
func (l *FileLogger) output(level Level, format string, args ...any) {
	if level < l.level {
		return
	}

	timeStr := time.Now().Format("2006-01-02 15:04:05.000")
	var msg string
	if l.prefix != "" {
		msg = fmt.Sprintf("[%s] %s [%s] %s\n", timeStr, l.prefix, level.String(), fmt.Sprintf(format, args...))
	} else {
		msg = fmt.Sprintf("[%s] [%s] %s\n", timeStr, level.String(), fmt.Sprintf(format, args...))
	}

	l.write(msg)
}

// write is the shared sink: stdout, file (with rotation), and the live-tail
// broker. Both the Debug/Info/Warn/Error helpers and the slog.Handler
// adapter funnel through here so there is exactly one write path.
func (l *FileLogger) write(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// 1. Stdout Output
	if l.stdout {
		_, _ = os.Stdout.WriteString(msg)
	}

	// 2. File Output and Rotation
	if l.file != nil {
		l.checkRotate(len(msg))
		n, err := l.file.WriteString(msg)
		if err == nil {
			l.currentSize += int64(n)
		}
	}

	// 3. Deliver to real-time API queue
	select {
	case l.logChan <- msg:
	default:
	}
}

func (l *FileLogger) Debug(format string, args ...any) { l.output(LevelDebug, format, args...) }
func (l *FileLogger) Info(format string, args ...any)  { l.output(LevelInfo, format, args...) }
func (l *FileLogger) Warn(format string, args ...any)  { l.output(LevelWarn, format, args...) }
func (l *FileLogger) Error(format string, args ...any) { l.output(LevelError, format, args...) }

// Close gracefully releases resources
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// ── log/slog Handler Adapter ──────────────────────────────────────────────
//
// slogHandler lets FileLogger act as the backing store for log/slog, so
// existing code can migrate to slog.Logger while keeping the same file
// rotation, stdout mirroring, and SSE live-tail behavior. It carries only
// the attrs/group state that slog.Handler requires; the actual write path
// is FileLogger.write, so there is still a single sink.
type slogHandler struct {
	fl     *FileLogger
	attrs  []slog.Attr
	groups []string
}

var _ slog.Handler = (*slogHandler)(nil)

// SlogHandler returns a slog.Handler backed by this FileLogger.
func (l *FileLogger) SlogHandler() slog.Handler {
	return &slogHandler{fl: l}
}

// Slog returns a ready-to-use *slog.Logger backed by this FileLogger.
func (l *FileLogger) Slog() *slog.Logger {
	return slog.New(l.SlogHandler())
}

func (h *slogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return fromSlogLevel(level) >= h.fl.level
}

func (h *slogHandler) Handle(_ context.Context, r slog.Record) error {
	level := fromSlogLevel(r.Level)
	if level < h.fl.level {
		return nil
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("[%s] ", r.Time.Format("2006-01-02 15:04:05.000")))
	if h.fl.prefix != "" {
		b.WriteString(fmt.Sprintf("%s ", h.fl.prefix))
	}
	b.WriteString(fmt.Sprintf("[%s] %s", level.String(), r.Message))

	writeAttr := func(a slog.Attr) {
		if a.Equal(slog.Attr{}) {
			return
		}
		key := a.Key
		for i := len(h.groups) - 1; i >= 0; i-- {
			key = h.groups[i] + "." + key
		}
		fmt.Fprintf(&b, " %s=%v", key, a.Value.Resolve())
	}

	for _, a := range h.attrs {
		writeAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(a)
		return true
	})

	b.WriteString("\n")
	h.fl.write(b.String())
	return nil
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &slogHandler{fl: h.fl, attrs: merged, groups: h.groups}
}

func (h *slogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	groups := make([]string, 0, len(h.groups)+1)
	groups = append(groups, h.groups...)
	groups = append(groups, name)
	return &slogHandler{fl: h.fl, attrs: h.attrs, groups: groups}
}

// ── HTTP API Streaming Adapter (Based on Server-Sent Events - SSE) ───────────

// StreamHandler returns an HTTP handler function for real-time log scrolling via web browsers or third-party tools
func (l *FileLogger) StreamHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set standard SSE response headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*") // Allow CORS

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
			return
		}

		// Create a dedicated channel for this specific client
		clientChan := make(chan string, 128)
		l.register <- clientChan

		defer func() {
			l.unregister <- clientChan
		}()

		// Listen for client disconnection
		ctx := r.Context()

		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-clientChan:
				// Use standard SSE protocol formatting: data: content\n\n
				_, _ = fmt.Fprintf(w, "data: %s\n", msg)
				flusher.Flush() // Flush directly to the network interface card buffer
			}
		}
	}
}
