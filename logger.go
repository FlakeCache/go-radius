//go:build !windows

package main

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Event     string `json:"event"`
	User      string `json:"user,omitempty"`
	NAS       string `json:"nas,omitempty"`
	IP        string `json:"assigned_ip,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message,omitempty"`
}

var useJSON bool

// InitLogger initializes logging for non-Windows platforms (stdout/stderr)
func InitLogger() error {
	log.SetOutput(os.Stdout)
	log.SetFlags(0) // No prefix, we'll add our own
	return nil
}

// SetJSONLogging enables or disables JSON logging
func SetJSONLogging(enabled bool) {
	useJSON = enabled
}

// CloseLogger closes the logger
func CloseLogger() {
	// Nothing to do on non-Windows
}

func logJSON(entry LogEntry) {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, _ := json.Marshal(entry)
	log.Println(string(data))
}

// LogInfo logs an informational message
func LogInfo(msg string) {
	if useJSON {
		logJSON(LogEntry{Level: "info", Message: msg})
	} else {
		log.Println("[INFO]", time.Now().Format("2006-01-02 15:04:05"), msg)
	}
}

// LogWarning logs a warning message
func LogWarning(msg string) {
	if useJSON {
		logJSON(LogEntry{Level: "warn", Message: msg})
	} else {
		log.Println("[WARN]", time.Now().Format("2006-01-02 15:04:05"), msg)
	}
}

// LogError logs an error message
func LogError(msg string) {
	if useJSON {
		logJSON(LogEntry{Level: "error", Message: msg})
	} else {
		log.Println("[ERROR]", time.Now().Format("2006-01-02 15:04:05"), msg)
	}
}

// LogAuthRequest logs an authentication request
func LogAuthRequest(user, nas, nasID string) {
	if useJSON {
		logJSON(LogEntry{
			Level: "info",
			Event: "auth_request",
			User:  user,
			NAS:   nas,
		})
	} else {
		log.Printf("[INFO] %s Auth request: user=%s, NAS=%s, NAS-ID=%s",
			time.Now().Format("2006-01-02 15:04:05"), user, nas, nasID)
	}
}

// LogAuthSuccess logs a successful authentication
func LogAuthSuccess(user, nas, assignedIP string) {
	if useJSON {
		logJSON(LogEntry{
			Level: "info",
			Event: "auth_success",
			User:  user,
			NAS:   nas,
			IP:    assignedIP,
		})
	} else {
		log.Printf("[INFO] %s Auth success: user=%s, NAS=%s, assigned_ip=%s",
			time.Now().Format("2006-01-02 15:04:05"), user, nas, assignedIP)
	}
}

// LogAuthFailure logs a failed authentication
func LogAuthFailure(user, nas, reason string) {
	if useJSON {
		logJSON(LogEntry{
			Level:  "warn",
			Event:  "auth_failure",
			User:   user,
			NAS:    nas,
			Reason: reason,
		})
	} else {
		log.Printf("[WARN] %s Auth failure: user=%s, NAS=%s, reason=%s",
			time.Now().Format("2006-01-02 15:04:05"), user, nas, reason)
	}
}
