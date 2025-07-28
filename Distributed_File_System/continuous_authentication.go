package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"
)

/* ==== DATA TYPES ======================================================= */

// A single behavioural event coming from the client
type BehaviourEvent struct {
	SessionID string                 `json:"session_id"`
	UserID    string                 `json:"user_id"`
	EventType string                 `json:"event_type"` // keystroke, mouse, geo, device
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// Baseline profile per user (very small demo model)
type BehaviourProfile struct {
	UserID           string    `json:"user_id"`
	AvgKeyInterval   float64   `json:"avg_key_interval_ms"`
	AvgMouseSpeed    float64   `json:"avg_mouse_speed_px_s"`
	UsualCountries   []string  `json:"usual_countries"`
	LastUpdated      time.Time `json:"last_updated"`
	EventCount       int       `json:"event_count"`
	AnomalyThreshold float64   `json:"anomaly_threshold"` // 0-1 score
}

// Live session trust state
type SessionTrust struct {
	UserID        string    `json:"user_id"`
	SessionID     string    `json:"session_id"`
	TrustScore    float64   `json:"trust_score"` // 0-100
	LastEventAt   time.Time `json:"last_event_at"`
	LastDecayAt   time.Time `json:"last_decay_at"`
	IsLocked      bool      `json:"is_locked"`
	ViolationNote string    `json:"violation_note,omitempty"`
}

/* ==== MANAGER ========================================================== */

type ContinuousAuthManager struct {
	profiles   map[string]*BehaviourProfile   // userID -> profile
	sessions   map[string]*SessionTrust       // sessionID -> trust
	mutex      sync.RWMutex
	server     *EnterpriseFileServer
	decayStep  float64
	lockThresh float64
}

func NewContinuousAuthManager(server *EnterpriseFileServer) *ContinuousAuthManager {
	return &ContinuousAuthManager{
		profiles:   make(map[string]*BehaviourProfile),
		sessions:   make(map[string]*SessionTrust),
		server:     server,
		decayStep:  0.4,  // trust loss per minute w/out events
		lockThresh: 35.0, // below this -> lock
	}
}

/* ==== PUBLIC API ======================================================= */

// IngestEvent is called by the REST handler
func (cam *ContinuousAuthManager) IngestEvent(ev *BehaviourEvent) {
	cam.mutex.Lock()
	defer cam.mutex.Unlock()

	// Ensure baseline
	p, ok := cam.profiles[ev.UserID]
	if !ok {
		p = &BehaviourProfile{
			UserID:           ev.UserID,
			AvgKeyInterval:   120, // ms
			AvgMouseSpeed:    500, // px/s
			UsualCountries:   []string{},
			AnomalyThreshold: 0.35,
		}
		cam.profiles[ev.UserID] = p
	}

	// Update baseline (very naïve)
	if ev.EventType == "keystroke" {
		if iv, ok := ev.Data["interval"].(float64); ok {
			p.AvgKeyInterval = (p.AvgKeyInterval*float64(p.EventCount) + iv) / float64(p.EventCount+1)
		}
	}
	if ev.EventType == "mouse" {
		if sp, ok := ev.Data["speed"].(float64); ok {
			p.AvgMouseSpeed = (p.AvgMouseSpeed*float64(p.EventCount) + sp) / float64(p.EventCount+1)
		}
	}
	p.EventCount++
	p.LastUpdated = time.Now()

	// Session trust
	st, ok := cam.sessions[ev.SessionID]
	if !ok {
		st = &SessionTrust{
			UserID:      ev.UserID,
			SessionID:   ev.SessionID,
			TrustScore:  80, // fresh session
			LastDecayAt: time.Now(),
		}
		cam.sessions[ev.SessionID] = st
	}

	anomaly := cam.anomalyScore(ev, p)
	// Simple formula: subtract 100*anomaly (0-1) but never <0
	st.TrustScore = math.Max(0, st.TrustScore-100*anomaly*0.5)
	st.LastEventAt = time.Now()

	// audit
	if cam.server.auditLogger != nil {
		cam.server.auditLogger.LogEvent(
			"behaviour_event",
			ev.UserID,
			ev.SessionID,
			ev.EventType,
			fmt.Sprintf("%.2f", anomaly),
			ev.Data,
		)
	}

	// Lock?
	if st.TrustScore < cam.lockThresh && !st.IsLocked {
		st.IsLocked = true
		st.ViolationNote = "Trust below threshold"
		if cam.server.auditLogger != nil {
			cam.server.auditLogger.LogEvent(
				"session_locked",
				ev.UserID,
				ev.SessionID,
				"continuous_auth",
				"critical",
				map[string]interface{}{"trust": st.TrustScore},
			)
		}
	}
}

// GetSession returns live trust info
func (cam *ContinuousAuthManager) GetSession(sessionID string) *SessionTrust {
	cam.mutex.RLock()
	defer cam.mutex.RUnlock()
	return cam.sessions[sessionID]
}

// Metrics snapshot
func (cam *ContinuousAuthManager) Metrics() map[string]interface{} {
	cam.mutex.RLock()
	defer cam.mutex.RUnlock()
	return map[string]interface{}{
		"profiles":  len(cam.profiles),
		"sessions":  len(cam.sessions),
		"lockCount": cam.lockCount(),
	}
}

/* ==== INTERNAL ========================================================= */

func (cam *ContinuousAuthManager) lockCount() int {
	c := 0
	for _, s := range cam.sessions {
		if s.IsLocked {
			c++
		}
	}
	return c
}

func (cam *ContinuousAuthManager) anomalyScore(ev *BehaviourEvent, p *BehaviourProfile) float64 {
	switch ev.EventType {

	case "keystroke":
		if iv, ok := ev.Data["interval"].(float64); ok && p.AvgKeyInterval > 0 {
			return math.Min(1, math.Abs(iv-p.AvgKeyInterval)/p.AvgKeyInterval)
		}

	case "mouse":
		if sp, ok := ev.Data["speed"].(float64); ok && p.AvgMouseSpeed > 0 {
			return math.Min(1, math.Abs(sp-p.AvgMouseSpeed)/p.AvgMouseSpeed)
		}

	case "geo":
		if ctry, ok := ev.Data["country"].(string); ok {
			for _, u := range p.UsualCountries {
				if u == ctry {
					return 0
				}
			}
			return 0.7
		}

	case "device":
		if h, ok := ev.Data["hardware_hash"].(string); ok {
			sum := sha256.Sum256([]byte(p.UserID))
			ref := fmt.Sprintf("%x", sum)[:8]
			if h != ref {
				return 0.5
			}
		}
	}
	return 0
}

/* ==== BACKGROUND DECAY LOOP =========================================== */

func (cam *ContinuousAuthManager) Start() {
	go func() {
		t := time.NewTicker(1 * time.Minute)
		for range t.C {
			cam.decay()
		}
	}()
}

func (cam *ContinuousAuthManager) decay() {
	cam.mutex.Lock()
	defer cam.mutex.Unlock()
	for _, st := range cam.sessions {
		mins := time.Since(st.LastDecayAt).Minutes()
		if mins >= 1 && !st.IsLocked {
			st.TrustScore = math.Max(0, st.TrustScore-cam.decayStep*mins)
			st.LastDecayAt = time.Now()
		}
	}
}

/* ==== HTTP HANDLERS ==================================================== */

// POST /api/cont-auth/event
func (efs *EnterpriseFileServer) handleContAuthEvent(w http.ResponseWriter, r *http.Request) {
	var ev BehaviourEvent
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "bad JSON", 400); return
	}
	ev.Timestamp = time.Now()
	efs.contAuth.IngestEvent(&ev)
	w.WriteHeader(http.StatusAccepted)
}

// GET /api/cont-auth/status?session=xxx
func (efs *EnterpriseFileServer) handleContAuthStatus(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("session")
	if sid == "" { http.Error(w,"missing session",400); return }
	st := efs.contAuth.GetSession(sid)
	if st == nil { http.Error(w,"not found",404); return }
	json.NewEncoder(w).Encode(st)
}

// GET /api/cont-auth/system
func (efs *EnterpriseFileServer) handleContAuthSystem(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(efs.contAuth.Metrics())
}
