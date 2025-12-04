//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/sys/windows/svc/eventlog"
)

const eventLogName = "RADIUS-AD"

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

var (
	elog    *eventlog.Log
	useJSON bool
)

// InitLogger initializes Windows Event Log
func InitLogger() error {
	// Try to open existing event log source
	var err error
	elog, err = eventlog.Open(eventLogName)
	if err != nil {
		// Try to install the event source first
		err = eventlog.InstallAsEventCreate(eventLogName, eventlog.Error|eventlog.Warning|eventlog.Info)
		if err != nil {
			// If we can't install (no admin rights), fall back to stdout
			log.SetOutput(os.Stdout)
			log.SetFlags(0)
			log.Println("[WARN] Could not open Windows Event Log, using stdout:", err)
			return nil
		}
		elog, err = eventlog.Open(eventLogName)
		if err != nil {
			log.SetOutput(os.Stdout)
			log.SetFlags(0)
			log.Println("[WARN] Could not open Windows Event Log, using stdout:", err)
			return nil
		}
	}

	// Also log to stdout for console visibility
	log.SetOutput(os.Stdout)
	log.SetFlags(0)

	return nil
}

// SetJSONLogging enables or disables JSON logging
func SetJSONLogging(enabled bool) {
	useJSON = enabled
}

// CloseLogger closes the Windows Event Log
func CloseLogger() {
	if elog != nil {
		elog.Close()
	}
}

func logJSON(entry LogEntry) string {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, _ := json.Marshal(entry)
	return string(data)
}

// LogInfo logs an informational message to Event Log and stdout
func LogInfo(msg string) {
	var output string
	if useJSON {
		output = logJSON(LogEntry{Level: "info", Message: msg})
	} else {
		output = fmt.Sprintf("[INFO] %s %s", time.Now().Format("2006-01-02 15:04:05"), msg)
	}
	log.Println(output)
	if elog != nil {
		elog.Info(1, msg)
	}
}

// LogWarning logs a warning message to Event Log and stdout
func LogWarning(msg string) {
	var output string
	if useJSON {
		output = logJSON(LogEntry{Level: "warn", Message: msg})
	} else {
		output = fmt.Sprintf("[WARN] %s %s", time.Now().Format("2006-01-02 15:04:05"), msg)
	}
	log.Println(output)
	if elog != nil {
		elog.Warning(2, msg)
	}
}

// LogError logs an error message to Event Log and stdout
func LogError(msg string) {
	var output string
	if useJSON {
		output = logJSON(LogEntry{Level: "error", Message: msg})
	} else {
		output = fmt.Sprintf("[ERROR] %s %s", time.Now().Format("2006-01-02 15:04:05"), msg)
	}
	log.Println(output)
	if elog != nil {
		elog.Error(3, msg)
	}
}

// LogAuthRequest logs an authentication request
func LogAuthRequest(user, nas, nasID string) {
	msg := fmt.Sprintf("Auth request: user=%s, NAS=%s, NAS-ID=%s", user, nas, nasID)
	if useJSON {
		output := logJSON(LogEntry{
			Level: "info",
			Event: "auth_request",
			User:  user,
			NAS:   nas,
		})
		log.Println(output)
	} else {
		log.Printf("[INFO] %s %s", time.Now().Format("2006-01-02 15:04:05"), msg)
	}
	if elog != nil {
		elog.Info(100, msg)
	}
}

// LogAuthSuccess logs a successful authentication
func LogAuthSuccess(user, nas, assignedIP string) {
	msg := fmt.Sprintf("Auth success: user=%s, NAS=%s, assigned_ip=%s", user, nas, assignedIP)
	if useJSON {
		output := logJSON(LogEntry{
			Level: "info",
			Event: "auth_success",
			User:  user,
			NAS:   nas,
			IP:    assignedIP,
		})
		log.Println(output)
	} else {
		log.Printf("[INFO] %s %s", time.Now().Format("2006-01-02 15:04:05"), msg)
	}
	if elog != nil {
		elog.Info(101, msg)
	}
}

// LogAuthFailure logs a failed authentication
func LogAuthFailure(user, nas, reason string) {
	msg := fmt.Sprintf("Auth failure: user=%s, NAS=%s, reason=%s", user, nas, reason)
	if useJSON {
		output := logJSON(LogEntry{
			Level:  "warn",
			Event:  "auth_failure",
			User:   user,
			NAS:    nas,
			Reason: reason,
		})
		log.Println(output)
	} else {
		log.Printf("[WARN] %s %s", time.Now().Format("2006-01-02 15:04:05"), msg)
	}
	if elog != nil {
		elog.Warning(102, msg)
	}
}
