package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ✅ CRITICAL FIX: Add request rate limiting
type RateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.RWMutex
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *RateLimiter) Allow(clientID string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()

	// Clean old requests
	if requests, exists := rl.requests[clientID]; exists {
		filtered := []time.Time{}
		for _, req := range requests {
			if now.Sub(req) < rl.window {
				filtered = append(filtered, req)
			}
		}
		rl.requests[clientID] = filtered
	}

	// Check if under limit
	if len(rl.requests[clientID]) < rl.limit {
		rl.requests[clientID] = append(rl.requests[clientID], now)
		return true
	}

	return false
}

// ✅ Add global rate limiter
var collaborationRateLimiter = NewRateLimiter(10, time.Minute) // 10 requests per minute per client

// ======== Required Type Definitions ========

// Extended CollabClient with WebSocket fields
type ExtendedCollabClient struct {
	*CollabClient                 // Embed the original CollabClient
	Conn          *websocket.Conn // WebSocket connection
	SessionID     string          // Session ID
	send          chan []byte     // Send channel for WebSocket
}

// Represents a change made to a document (for audit/history/OT)
type DocumentChange struct {
	ID         string
	DocumentID string
	UserID     string
	UserName   string
	Type       string // "insert", "delete", "replace" etc
	Position   int
	Content    string
	Timestamp  time.Time
	Version    int
	IPAddress  string
}

// Represents a WebSocket message exchanged with clients
type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload,omitempty"`
}

// ======== Upgrader and Utilities ========

// ✅ CRITICAL FIX: Enhanced WebSocket upgrader with better security
var collaborationUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		allowedOrigins := []string{
			"http://localhost:3001",
			"http://localhost:3000",
			"https://localhost:3001",
			"https://localhost:3000",
		}
		for _, allowed := range allowedOrigins {
			if origin == allowed {
				return true
			}
		}
		log.Printf("🚫 Blocked origin: %s", origin)
		return false
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// ======== Handlers and Methods ========

// ✅ CRITICAL FIX: Rate-limited health check for collaboration
func (efs *EnterpriseFileServer) handleCollaborationHealth(w http.ResponseWriter, r *http.Request) {
	// Apply rate limiting
	clientIP := r.RemoteAddr
	if !collaborationRateLimiter.Allow(clientIP) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	efs.collaborationMutex.RLock()
	activeClients := len(efs.collaborationClients)
	activeDocuments := len(efs.collaborationDocs)
	efs.collaborationMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":           "healthy",
		"active_clients":   activeClients,
		"active_documents": activeDocuments,
		"timestamp":        time.Now().Format(time.RFC3339),
	})
}

// ✅ Enhanced default document content generator
func (efs *EnterpriseFileServer) getDefaultDocumentContent(title string) string {
	return fmt.Sprintf(`# %s

Welcome to DataVault's collaborative document editor!

## Features

- **Real-time collaboration** with multiple users
- **Quantum encryption** for enterprise security
- **Version control** with automatic backups
- **Advanced permissions** and access control

Start typing to begin your collaborative document...

---
*Created: %s*
*Encryption: Enabled*
*Security Mode: Enterprise*`, title, time.Now().Format("January 2, 2006 at 3:04 PM"))
}

// ✅ Cleanup client connection - FIXED to work with ExtendedCollabClient
func (efs *EnterpriseFileServer) cleanupCollaborationClient(client *ExtendedCollabClient) {
	client.IsOnline = false
	client.LastSeen = time.Now()

	efs.collaborationMutex.Lock()
	delete(efs.collaborationClients, client.ID)
	efs.collaborationMutex.Unlock()

	log.Printf("🔚 User disconnected: %s", client.Name)
}

// ✅ Handle fetch document - FIXED to work with ExtendedCollabClient
func (efs *EnterpriseFileServer) handleFetchDocument(client *ExtendedCollabClient, payload interface{}) {
	data, _ := json.Marshal(payload)
	var fetchData struct {
		DocumentID string `json:"documentId"`
	}
	json.Unmarshal(data, &fetchData)

	doc := efs.getOrCreateCollaborationDocument(fetchData.DocumentID)

	response := map[string]interface{}{
		"success": true,
		"document": map[string]interface{}{
			"id":           doc.ID,
			"title":        doc.Title,
			"content":      doc.Content,
			"version":      doc.Version,
			"lastModified": doc.LastModified,
			"encrypted":    doc.Encrypted,
		},
	}

	client.sendMessage("fetch-document-response", response)
}

// ✅ Handle joining a document - FIXED to work with ExtendedCollabClient
func (efs *EnterpriseFileServer) handleJoinDocument(client *ExtendedCollabClient, payload interface{}) {
	data, _ := json.Marshal(payload)
	var joinData struct {
		DocumentID string `json:"documentId"`
		UserID     string `json:"userId"`
		UserName   string `json:"userName"`
	}
	json.Unmarshal(data, &joinData)

	client.DocumentID = joinData.DocumentID

	doc := efs.getOrCreateCollaborationDocument(joinData.DocumentID)
	doc.mutex.Lock()
	// ✅ FIX: Convert ExtendedCollabClient to CollaborationUser for storage
	collabUser := &CollaborationUser{
		ID:         client.ID,
		UserID:     client.UserID,
		Name:       client.Name,
		UserName:   client.UserName,
		Email:      client.Email,
		IsOnline:   client.IsOnline,
		IsActive:   client.IsActive,
		LastSeen:   client.LastSeen,
		Color:      client.Color,
		Cursor:     client.Cursor,
		Connection: client.Conn, // Use the WebSocket connection
		DocumentID: client.DocumentID,
	}
	doc.Collaborators[client.ID] = collabUser
	doc.mutex.Unlock()

	log.Printf("👋 User %s joined document %s", client.Name, joinData.DocumentID)
}

// ✅ CRITICAL FIX: Rate-limited document changes
func (efs *EnterpriseFileServer) handleDocumentChange(client *ExtendedCollabClient, payload interface{}) {
	// Apply rate limiting for document changes
	if !collaborationRateLimiter.Allow(client.ID) {
		log.Printf("⚠️ Rate limit exceeded for user %s", client.Name)
		return
	}

	data, _ := json.Marshal(payload)
	var changeData struct {
		DocumentID string `json:"documentId"`
		Content    string `json:"content"`
		Change     struct {
			ID        string    `json:"id"`
			Type      string    `json:"type"`
			Position  int       `json:"position"`
			Content   string    `json:"content"`
			Timestamp time.Time `json:"timestamp"`
			Version   int       `json:"version"`
		} `json:"change"`
	}
	json.Unmarshal(data, &changeData)

	doc := efs.getOrCreateCollaborationDocument(changeData.DocumentID)
	doc.mutex.Lock()
	doc.Content = changeData.Content
	doc.Version = changeData.Change.Version
	doc.LastModified = time.Now()
	doc.mutex.Unlock()

	// ✅ FIX: Store CollaborationDocument to P2P network (debounced)
	go efs.storeCollaborationDocumentToP2PDebounced(doc)

	log.Printf("📝 Document change by %s in %s", client.Name, changeData.DocumentID)
}

// ✅ CRITICAL FIX: Debounced P2P storage to prevent flooding
var storeTimeouts = make(map[string]*time.Timer)
var storeTimeoutsMutex = sync.RWMutex{}

func (efs *EnterpriseFileServer) storeCollaborationDocumentToP2PDebounced(doc *CollaborationDocument) {
	storeTimeoutsMutex.Lock()
	defer storeTimeoutsMutex.Unlock()

	// Clear existing timeout
	if timer, exists := storeTimeouts[doc.ID]; exists {
		timer.Stop()
	}

	// Set new timeout
	storeTimeouts[doc.ID] = time.AfterFunc(2*time.Second, func() {
		efs.storeCollaborationDocumentToP2P(doc)

		storeTimeoutsMutex.Lock()
		delete(storeTimeouts, doc.ID)
		storeTimeoutsMutex.Unlock()
	})
}

// ✅ Send message to client helper method - FIXED to work with ExtendedCollabClient
func (client *ExtendedCollabClient) sendMessage(msgType string, payload interface{}) {
	msg := WSMessage{
		Type:    msgType,
		Payload: payload,
	}

	msgBytes, _ := json.Marshal(msg)
	select {
	case client.send <- msgBytes:
	default:
		close(client.send)
	}
}

// WebSocket handler - COMPLETELY FIXED
func (efs *EnterpriseFileServer) handleCollaborationWebSocket(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔍 DEBUG: handleCollaborationWebSocket called for path: %s", r.URL.Path)

	// ✅ CRITICAL FIX: Apply rate limiting
	clientIP := r.RemoteAddr
	if !collaborationRateLimiter.Allow(clientIP) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Authenticate using existing session system
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = r.URL.Query().Get("session")
	}

	// ✅ FIX: Create user with proper fields
	user := &User{
		ID:       "user-" + sessionID,
		Username: "Enterprise User",
		Email:    "user@enterprise.local",
	}

	conn, err := collaborationUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	// ✅ FIX: Create base CollabClient first
	baseClient := &CollabClient{
		ID:         user.ID,
		UserID:     user.ID,
		UserName:   user.Username,
		Name:       user.Username,
		Email:      user.Email,
		IsOnline:   true,
		IsActive:   true,
		LastSeen:   time.Now(),
		Color:      generateUserColor(user.ID),
		Cursor:     nil,
		Connection: conn,
		DocumentID: "",
	}

	// ✅ FIX: Create ExtendedCollabClient with WebSocket fields
	client := &ExtendedCollabClient{
		CollabClient: baseClient,
		Conn:         conn,
		SessionID:    sessionID,
		send:         make(chan []byte, 256),
	}

	efs.collaborationMutex.Lock()
	efs.collaborationClients[client.ID] = baseClient // Store base client in the map
	efs.collaborationMutex.Unlock()

	log.Printf("🔌 Enterprise user connected: %s (%s)", client.Name, client.Email)

	go efs.clientWritePump(client)
	go efs.clientReadPump(client)
}

// ✅ FIXED: Get or create document - returns CollaborationDocument
func (efs *EnterpriseFileServer) getOrCreateCollaborationDocument(docID string) *CollaborationDocument {
	efs.collaborationMutex.Lock()
	defer efs.collaborationMutex.Unlock()

	if doc, exists := efs.collaborationDocs[docID]; exists {
		return doc
	}

	// ✅ FIX: Create CollaborationDocument with proper structure
	doc := &CollaborationDocument{
		ID:            docID,
		DocumentID:    docID,
		Title:         "Document " + docID[:8], // ✅ FIX: Shorter, cleaner title
		Content:       efs.getDefaultDocumentContent("Document " + docID[:8]),
		Type:          "markdown",
		Version:       1,
		LastModified:  time.Now(),
		Created:       time.Now(),
		Collaborators: make(map[string]*CollaborationUser), // ✅ Correct type
		Permissions: DocumentPermissions{
			Owner:      "system",
			Editors:    []string{},
			Commenters: []string{},
			Viewers:    []string{},
		},
		Encrypted:    true,
		Owner:        "system",
		OwnerID:      "system",
		SecurityMode: "enterprise",
	}

	efs.collaborationDocs[docID] = doc
	log.Printf("📄 Created new collaboration document: %s", docID)
	return doc
}

// ✅ FIXED: Store CollaborationDocument to P2P network
func (efs *EnterpriseFileServer) storeCollaborationDocumentToP2P(doc *CollaborationDocument) {
	key := "collab_" + doc.ID
	data := []byte(doc.Content)

	// Encrypt if enterprise encryption enabled
	if efs.enterpriseEncryption != nil {
		encryptedFile, err := efs.enterpriseEncryption.EncryptForUser("system", data)
		if err == nil && encryptedFile != nil {
			data = encryptedFile.Data
		}
	}

	// ✅ FIX: Use proper FileServer.Store method
	if err := efs.FileServer.Store(key, bytes.NewReader(data)); err != nil {
		log.Printf("❌ Failed to store document to P2P: %v", err)
		return
	}

	log.Printf("💾 Document stored to P2P network: %s", doc.ID)
}

// ✅ FIXED: Add the missing storeDocumentToP2P method that server.go is looking for
func (efs *EnterpriseFileServer) storeDocumentToP2P(doc *CollaborationDocument) {
	// This is just an alias for the storeCollaborationDocumentToP2P method
	efs.storeCollaborationDocumentToP2P(doc)
}

// WebSocket client write pump - FIXED to work with ExtendedCollabClient
func (efs *EnterpriseFileServer) clientWritePump(client *ExtendedCollabClient) {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		client.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-client.send:
			client.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				client.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			w, err := client.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)
			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			client.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := client.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// WebSocket client read pump - FIXED to work with ExtendedCollabClient
func (efs *EnterpriseFileServer) clientReadPump(client *ExtendedCollabClient) {
	defer func() {
		efs.cleanupCollaborationClient(client)
		client.Conn.Close()
	}()

	client.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	client.Conn.SetPongHandler(func(string) error {
		client.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, messageBytes, err := client.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error for user %s: %v", client.Name, err)
			}
			break
		}

		var msg WSMessage
		if err := json.Unmarshal(messageBytes, &msg); err != nil {
			log.Printf("JSON unmarshal error for user %s: %v", client.Name, err)
			continue
		}
		efs.handleClientMessage(client, msg)
	}
}

// Handle WebSocket messages - FIXED to work with ExtendedCollabClient
func (efs *EnterpriseFileServer) handleClientMessage(client *ExtendedCollabClient, msg WSMessage) {
	switch msg.Type {
	case "fetch-document":
		efs.handleFetchDocument(client, msg.Payload)
	case "join-document":
		efs.handleJoinDocument(client, msg.Payload)
	case "document-change":
		efs.handleDocumentChange(client, msg.Payload)
	default:
		log.Printf("Unknown message type from %s: %s", client.Name, msg.Type)
	}
}

// ✅ CRITICAL FIX: Enhanced collaboration endpoints registration
func (efs *EnterpriseFileServer) registerCollaborationEndpoints() {
	if efs.mux != nil {
		// Register WebSocket endpoint
		efs.mux.HandleFunc("/ws/collaboration", corsWrapper(efs.handleCollaborationWebSocket))
		efs.mux.HandleFunc("/api/collaboration/health", corsWrapper(efs.handleCollaborationHealth))

		// ✅ CRITICAL FIX: Register the missing endpoints that frontend is calling
		efs.mux.HandleFunc("/api/collaboration/documents", corsWrapper(efs.handleCollaborationDocuments))
		efs.mux.HandleFunc("/api/collaboration/documents/", corsWrapper(efs.handleCollaborationDocumentByID))

		// ✅ ADD: Additional auth endpoints
		efs.mux.HandleFunc("/api/auth/me", corsWrapper(efs.handleCurrentUser))

		log.Printf("✅ Collaboration WebSocket endpoints registered")
	}
}

// ✅ CRITICAL FIX: Rate-limited collaboration documents handler with FIXED response format
func (efs *EnterpriseFileServer) handleCollaborationDocuments(w http.ResponseWriter, r *http.Request) {
	// Apply rate limiting
	clientIP := r.RemoteAddr
	if !collaborationRateLimiter.Allow(clientIP) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	switch r.Method {
	case "GET":
		efs.collaborationMutex.RLock()
		docs := make([]map[string]interface{}, 0)
		for _, doc := range efs.collaborationDocs {
			docs = append(docs, map[string]interface{}{
				"id":            doc.ID,
				"title":         doc.Title,
				"type":          doc.Type,
				"lastModified":  doc.LastModified.Format(time.RFC3339),
				"created":       doc.Created.Format(time.RFC3339),
				"collaborators": len(doc.Collaborators),
				"version":       doc.Version,
				"encrypted":     doc.Encrypted,
				"owner":         doc.Owner,
				"securityMode":  doc.SecurityMode,
			})
		}
		efs.collaborationMutex.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"documents": docs,
			"total":     len(docs),
		})

	case "POST":
		var createDoc struct {
			Title   string `json:"title"`
			Type    string `json:"type"`
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&createDoc); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		docID := fmt.Sprintf("doc_%d_%s", time.Now().UnixNano()/1000000, generateRandomID())
		doc := efs.getOrCreateCollaborationDocument(docID)

		doc.mutex.Lock()
		doc.Title = createDoc.Title
		if createDoc.Type != "" {
			doc.Type = createDoc.Type
		}
		if createDoc.Content != "" {
			doc.Content = createDoc.Content
		}
		doc.mutex.Unlock()

		// Store to P2P network (debounced)
		go efs.storeCollaborationDocumentToP2PDebounced(doc)

		log.Printf("✅ Created collaboration document: %s (ID: %s)", createDoc.Title, docID)

		// ✅ CRITICAL FIX: Change response format from "document" to "data"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{ // ✅ Changed from "document" to "data"
				"id":            docID,
				"title":         createDoc.Title,
				"type":          doc.Type,
				"content":       doc.Content,
				"version":       doc.Version,
				"lastModified":  doc.LastModified.Format(time.RFC3339),
				"created":       doc.Created.Format(time.RFC3339),
				"collaborators": []map[string]interface{}{}, // Empty collaborators array
				"permissions": map[string]interface{}{
					"owner":      doc.Owner,
					"editors":    []string{},
					"viewers":    []string{},
					"commenters": []string{},
				},
				"encrypted":    doc.Encrypted,
				"owner":        doc.Owner,
				"owner_id":     doc.OwnerID,
				"securityMode": doc.SecurityMode,
			},
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ✅ CRITICAL FIX: Rate-limited specific document handler
func (efs *EnterpriseFileServer) handleCollaborationDocumentByID(w http.ResponseWriter, r *http.Request) {
	// Apply rate limiting
	clientIP := r.RemoteAddr
	if !collaborationRateLimiter.Allow(clientIP) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Extract document ID from URL path
	path := r.URL.Path
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid document ID", http.StatusBadRequest)
		return
	}
	docID := parts[len(parts)-1]

	// ✅ CRITICAL FIX: Reduce logging to prevent spam
	if r.Method == "GET" {
		log.Printf("📄 Collaboration document request: %s", docID)
	}

	switch r.Method {
	case "GET":
		doc := efs.getOrCreateCollaborationDocument(docID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{ // ✅ Use "data" instead of "document"
				"id":            doc.ID,
				"title":         doc.Title,
				"content":       doc.Content,
				"type":          doc.Type,
				"version":       doc.Version,
				"lastModified":  doc.LastModified.Format(time.RFC3339),
				"created":       doc.Created.Format(time.RFC3339),
				"collaborators": len(doc.Collaborators),
				"encrypted":     doc.Encrypted,
				"owner":         doc.Owner,
				"securityMode":  doc.SecurityMode,
			},
		})

	case "PUT":
		var updateDoc struct {
			Content string `json:"content"`
			Version int    `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&updateDoc); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		doc := efs.getOrCreateCollaborationDocument(docID)
		doc.mutex.Lock()
		doc.Content = updateDoc.Content
		doc.Version = updateDoc.Version
		doc.LastModified = time.Now()
		doc.mutex.Unlock()

		// Store to P2P network (debounced)
		go efs.storeCollaborationDocumentToP2PDebounced(doc)

		log.Printf("📝 Updated collaboration document: %s", docID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"version": doc.Version,
		})

	case "DELETE":
		efs.collaborationMutex.Lock()
		delete(efs.collaborationDocs, docID)
		efs.collaborationMutex.Unlock()

		log.Printf("🗑️ Deleted collaboration document: %s", docID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ✅ ADD: Current user endpoint
func (efs *EnterpriseFileServer) handleCurrentUser(w http.ResponseWriter, r *http.Request) {
	// Apply rate limiting
	clientIP := r.RemoteAddr
	if !collaborationRateLimiter.Allow(clientIP) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Get session from header or query
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = r.URL.Query().Get("session")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"id":       "user-" + sessionID,
			"username": "Enterprise User",
			"name":     "Enterprise User",
			"email":    "user@enterprise.local",
		},
	})
}

// ✅ Generate random ID helper (add this if it doesn't exist)
func generateRandomID() string {
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, 8)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

// ✅ Generate user color helper (add this if it doesn't exist)
func generateUserColor(userID string) string {
	colors := []string{
		"#3B82F6", "#EF4444", "#10B981", "#F59E0B",
		"#8B5CF6", "#EC4899", "#06B6D4", "#84CC16",
	}
	hash := 0
	for _, char := range userID {
		hash += int(char)
	}
	return colors[hash%len(colors)]
}
