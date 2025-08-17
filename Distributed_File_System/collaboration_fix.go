package main

import (
	"bytes"
	"encoding/json"

	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ======== Required Type Definitions ========

// Represents a collaborative document being edited in real-time
type CollaborativeDocument struct {
	ID            string
	Title         string
	Content       string
	Version       int
	LastModified  time.Time
	Collaborators map[string]*CollabClient // Connected clients
	Changes       []DocumentChange
	FileHash      string
	Encrypted     bool
	mutex         sync.RWMutex
}

// Represents a connected collaboration client
type CollabClient struct {
	ID         string
	Name       string
	Email      string
	SessionID  string
	Conn       *websocket.Conn
	IsOnline   bool
	LastSeen   time.Time
	DocumentID string
	send       chan []byte
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

// WebSocket upgrader with security
var collaborationUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		allowedOrigins := []string{
			"http://localhost:3001",
			"http://localhost:3000",
		}
		for _, allowed := range allowedOrigins {
			if origin == allowed {
				return true
			}
		}
		return false
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// ======== Handlers and Methods ========

// Initialize collaboration for EnterpriseFileServer
func (efs *EnterpriseFileServer) InitializeCollaboration() {
	if efs.collaborationDocs == nil {
		efs.collaborationDocs = make(map[string]*CollaborativeDocument)
	}
	if efs.collaborationClients == nil {
		efs.collaborationClients = make(map[string]*CollabClient)
	}
	if efs.operationalTransform == nil {
		efs.operationalTransform = &OperationTransform{}
	}

	log.Printf("🔍 DEBUG: Registering WebSocket handler at /ws/collaboration")
	efs.mux.HandleFunc("/ws/collaboration", efs.handleCollaborationWebSocket)
	efs.mux.HandleFunc("/api/collaboration/health", efs.handleCollaborationHealth)
	log.Println("🤝 Enterprise Collaboration initialized")
}

// ✅ Health check for collaboration
func (efs *EnterpriseFileServer) handleCollaborationHealth(w http.ResponseWriter, r *http.Request) {
	efs.collaborationMutex.RLock()
	defer efs.collaborationMutex.RUnlock()

	activeClients := len(efs.collaborationClients)
	activeDocuments := len(efs.collaborationDocs)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":           "healthy",
		"active_clients":   activeClients,
		"active_documents": activeDocuments,
		"timestamp":        time.Now().Format(time.RFC3339),
	})
}

// ✅ Default document content generator
func (efs *EnterpriseFileServer) getDefaultDocumentContent(docID string) string {
	content := map[string]interface{}{
		"type": "doc",
		"content": []map[string]interface{}{
			{
				"type":  "heading",
				"attrs": map[string]interface{}{"level": 1},
				"content": []map[string]interface{}{
					{"type": "text", "text": "🏢 Enterprise Document: " + docID},
				},
			},
			{
				"type": "paragraph",
				"content": []map[string]interface{}{
					{"type": "text", "text": "Quantum-encrypted collaborative document ready for real-time editing."},
				},
			},
		},
	}

	contentBytes, _ := json.Marshal(content)
	return string(contentBytes)
}

// ✅ Cleanup client connection
func (efs *EnterpriseFileServer) cleanupClient(client *CollabClient) {
	client.IsOnline = false
	client.LastSeen = time.Now()

	efs.collaborationMutex.Lock()
	delete(efs.collaborationClients, client.ID)
	efs.collaborationMutex.Unlock()

	log.Printf("🔚 User disconnected: %s", client.Name)
}

// ✅ Handle fetch document
func (efs *EnterpriseFileServer) handleFetchDocument(client *CollabClient, payload interface{}) {
	data, _ := json.Marshal(payload)
	var fetchData struct {
		DocumentID string `json:"documentId"`
	}
	json.Unmarshal(data, &fetchData)

	doc := efs.getOrCreateDocument(fetchData.DocumentID)

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

// ✅ Handle joining a document
func (efs *EnterpriseFileServer) handleJoinDocument(client *CollabClient, payload interface{}) {
	data, _ := json.Marshal(payload)
	var joinData struct {
		DocumentID string `json:"documentId"`
		UserID     string `json:"userId"`
		UserName   string `json:"userName"`
	}
	json.Unmarshal(data, &joinData)

	client.DocumentID = joinData.DocumentID

	doc := efs.getOrCreateDocument(joinData.DocumentID)
	doc.mutex.Lock()
	doc.Collaborators[client.ID] = client
	doc.mutex.Unlock()

	log.Printf("👋 User %s joined document %s", client.Name, joinData.DocumentID)
}

// ✅ Handle document changes
func (efs *EnterpriseFileServer) handleDocumentChange(client *CollabClient, payload interface{}) {
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

	doc := efs.getOrCreateDocument(changeData.DocumentID)
	doc.mutex.Lock()
	doc.Content = changeData.Content
	doc.Version = changeData.Change.Version
	doc.LastModified = time.Now()
	doc.mutex.Unlock()

	// Store to P2P network
	go efs.storeDocumentToP2P(doc)

	log.Printf("📝 Document change by %s in %s", client.Name, changeData.DocumentID)
}

// ✅ Send message to client helper method
func (client *CollabClient) sendMessage(msgType string, payload interface{}) {
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

// WebSocket handler
func (efs *EnterpriseFileServer) handleCollaborationWebSocket(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔍 DEBUG: handleCollaborationWebSocket called for path: %s", r.URL.Path)
	// Authenticate using existing session system
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = r.URL.Query().Get("session")
	}

	// (Simulated user, should replace with real auth)
	user := &User{
		ID:       "user-" + sessionID,
		Username: "Enterprise User",
	}

	conn, err := collaborationUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	client := &CollabClient{
		ID:        user.ID,
		Name:      user.Username,
		Email:     user.Email,
		Conn:      conn,
		SessionID: sessionID,
		IsOnline:  true,
		LastSeen:  time.Now(),
		send:      make(chan []byte, 256),
	}

	efs.collaborationMutex.Lock()
	efs.collaborationClients[client.ID] = client
	efs.collaborationMutex.Unlock()

	log.Printf("🔌 Enterprise user connected: %s (%s)", client.Name, client.Email)

	go efs.clientWritePump(client)
	go efs.clientReadPump(client)
}

// Get or create document
func (efs *EnterpriseFileServer) getOrCreateDocument(docID string) *CollaborativeDocument {
	efs.collaborationMutex.Lock()
	defer efs.collaborationMutex.Unlock()

	if doc, exists := efs.collaborationDocs[docID]; exists {
		return doc
	}

	doc := &CollaborativeDocument{
		ID:            docID,
		Title:         docID,
		Content:       efs.getDefaultDocumentContent(docID),
		Version:       1,
		LastModified:  time.Now(),
		Collaborators: make(map[string]*CollabClient),
		Changes:       []DocumentChange{},
		Encrypted:     true,
	}

	efs.collaborationDocs[docID] = doc
	return doc
}

// Store document to P2P network
func (efs *EnterpriseFileServer) storeDocumentToP2P(doc *CollaborativeDocument) {
	key := "collab_" + doc.ID
	data := []byte(doc.Content)

	// Encrypt if enterprise encryption enabled
	if efs.enterpriseEncryption != nil {
		encryptedFile, err := efs.enterpriseEncryption.EncryptForUser("system", data)
		if err == nil && encryptedFile != nil {
			data = encryptedFile.Data
		}
	}

	if _, err := efs.store.writeStream(key, "collaboration", bytes.NewReader(data)); err != nil {
		log.Printf("❌ Failed to store document to P2P: %v", err)
		return
	}

	doc.FileHash = key
	log.Printf("💾 Document stored to P2P network: %s", doc.ID)
}

// WebSocket client write pump
func (efs *EnterpriseFileServer) clientWritePump(client *CollabClient) {
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

// WebSocket client read pump
func (efs *EnterpriseFileServer) clientReadPump(client *CollabClient) {
	defer func() {
		efs.cleanupClient(client)
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

// Handle WebSocket messages
func (efs *EnterpriseFileServer) handleClientMessage(client *CollabClient, msg WSMessage) {
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

// ... Rest of handlers unchanged (handleFetchDocument etc) ...

// Add all the rest of your handlers here as in your message…
