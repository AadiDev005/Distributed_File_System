package main

import (
	"encoding/json"

	"os"
	"sync"
	"time"
)

type AuditEventType string

const (
	EventFileAccess       AuditEventType = "file_access"
	EventFileStore        AuditEventType = "file_store"
	EventFileDelete       AuditEventType = "file_delete"
	EventUserLogin        AuditEventType = "user_login"
	EventUserLogout       AuditEventType = "user_logout"
	EventPermissionChange AuditEventType = "permission_change"
)

type AuditEvent struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	EventType  AuditEventType         `json:"event_type"`
	UserID     string                 `json:"user_id"`
	ResourceID string                 `json:"resource_id,omitempty"`
	Action     string                 `json:"action"`
	Result     string                 `json:"result"` // success/failure
	IPAddress  string                 `json:"ip_address,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

type AuditLogger struct {
	logFile string
	mutex   sync.Mutex
	events  []AuditEvent
}

func NewAuditLogger(logFile string) *AuditLogger {
	return &AuditLogger{
		logFile: logFile,
		events:  make([]AuditEvent, 0),
	}
}

func (al *AuditLogger) LogEvent(eventType AuditEventType, userID, resourceID, action, result string, details map[string]interface{}) error {
	al.mutex.Lock()
	defer al.mutex.Unlock()

	event := AuditEvent{
		ID:         generateID(),
		Timestamp:  time.Now(),
		EventType:  eventType,
		UserID:     userID,
		ResourceID: resourceID,
		Action:     action,
		Result:     result,
		Details:    details,
	}

	// Add to memory store
	al.events = append(al.events, event)

	// Write to file
	return al.writeToFile(event)
}

func (al *AuditLogger) writeToFile(event AuditEvent) error {
	file, err := os.OpenFile(al.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}

	_, err = file.WriteString(string(eventJSON) + "\n")
	return err
}

func (al *AuditLogger) GetEvents(limit int) []AuditEvent {
	al.mutex.Lock()
	defer al.mutex.Unlock()

	if limit <= 0 || limit > len(al.events) {
		limit = len(al.events)
	}

	// Return most recent events
	start := len(al.events) - limit
	if start < 0 {
		start = 0
	}
	return al.events[start:]
}

func (al *AuditLogger) GetEventsByUser(userID string, limit int) []AuditEvent {
	al.mutex.Lock()
	defer al.mutex.Unlock()

	var userEvents []AuditEvent
	for _, event := range al.events {
		if event.UserID == userID {
			userEvents = append(userEvents, event)
		}
	}

	if limit <= 0 || limit > len(userEvents) {
		limit = len(userEvents)
	}

	start := len(userEvents) - limit
	if start < 0 {
		start = 0
	}
	return userEvents[start:]
}
