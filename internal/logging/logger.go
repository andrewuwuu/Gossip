package logging

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultLogPath = "gossip.logs"
	maxLogBytes    = 2048
)

var (
	logOnce sync.Once
	logFile *os.File
	logMu   sync.Mutex
)

func Debugf(format string, args ...any) {
	logf("DEBUG", format, args...)
}

func Infof(format string, args ...any) {
	logf("INFO", format, args...)
}

func Warnf(format string, args ...any) {
	logf("WARN", format, args...)
}

func Errorf(format string, args ...any) {
	logf("ERROR", format, args...)
}

func logf(level, format string, args ...any) {
	logOnce.Do(openLogFile)
	if logFile == nil {
		return
	}

	message := fmt.Sprintf(format, args...)
	sanitized := sanitize(message)
	if sanitized == "" {
		return
	}

	line := fmt.Sprintf("%s [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), level, sanitized)
	logMu.Lock()
	_, _ = logFile.WriteString(line)
	logMu.Unlock()
}

func openLogFile() {
	path := os.Getenv("GOSSIP_LOG_PATH")
	if path == "" {
		path = defaultLogPath
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	logFile = file
}

func sanitize(input string) string {
	if len(input) > maxLogBytes {
		input = input[:maxLogBytes]
	}

	var builder strings.Builder
	builder.Grow(len(input))
	for _, r := range input {
		switch {
		case r >= 32 && r <= 126:
			builder.WriteRune(r)
		case r == '\n' || r == '\r' || r == '\t':
			builder.WriteByte(' ')
		default:
			builder.WriteByte('?')
		}
	}

	return strings.TrimSpace(builder.String())
}
