// main.go – DataVault Enterprise / flat-file storage
package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"net/http" // ADD THIS
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/anthdm/foreverstore/p2p"
	"github.com/rs/cors"
)

/* ── helpers ─────────────────────────────────────────── */

func generateNodeID() string {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return fmt.Sprintf("node-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("node-%x", id)
}

func detectMimeType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".txt":
		return "text/plain"
	case ".md":
		return "text/markdown"
	case ".json":
		return "application/json"
	case ".pdf":
		return "application/pdf"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	default:
		return "application/octet-stream"
	}
}

// ✅ NEW: CORS configuration function
func createCORSMiddleware() *cors.Cors {
	return cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000",
			"http://localhost:3001",
			"http://localhost:3002",
			"http://localhost:3003",
		},
		AllowCredentials: true,
		AllowedMethods: []string{
			"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD",
		},
		AllowedHeaders: []string{
			"Accept", "Authorization", "Content-Type", "X-CSRF-Token",
			"X-Session-ID", "X-Requested-With", "Accept-Encoding",
			"Accept-Language", "Cache-Control",
		},
		ExposedHeaders: []string{
			"Content-Length", "Content-Disposition", "Content-Type",
		},
		MaxAge: int(24 * time.Hour.Seconds()),
		Debug:  true, // Set to false in production
	})
}

/* ── bootstrap ──────────────────────────────────────── */

func makeEnterpriseServer(listenAddr, webAPIPort string, peers []string) *EnterpriseFileServer {
	/* transport */
	tcp := p2p.NewTCPTransport(p2p.TCPTransportOpts{
		ListenAddr:    listenAddr,
		HandshakeFunc: p2p.NOPHandshakeFunc,
		Decoder:       p2p.DefaultDecoder{},
	})

	/* core security */
	auth := NewAuthManager()
	encKey := newEncryptionKey()
	entEnc := NewEnterpriseEncryption(encKey)
	audit := NewAuditLogger(fmt.Sprintf("%s_audit.log", listenAddr))

	/* bootstrap admin */
	admin, err := auth.CreateUser("admin", "admin123", RoleSuperAdmin)
	if err != nil {
		log.Fatalf("create admin: %v", err)
	}
	if err := entEnc.GenerateUserKey(admin.ID); err != nil {
		log.Fatalf("admin key: %v", err)
	}

	/* shared flat storage */
	root := "./storage/shared"
	if err := os.MkdirAll(root, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", root, err)
	}

	/* path transform – flat namespace */
	fsOpts := FileServerOpts{
		EncKey:      newEncryptionKey(),
		StorageRoot: root,
		PathTransformFunc: func(key string) PathKey {
			return PathKey{Filename: key}
		},
		Transport: tcp,
	}

	s := NewEnterpriseFileServer(EnterpriseFileServerOpts{
		FileServerOpts:       fsOpts,
		AuthManager:          auth,
		EnterpriseEncryption: entEnc,
		AuditLogger:          audit,
		EnableWebAPI:         true,
		WebAPIPort:           webAPIPort,
		PeerList:             peers,
		SelfAddr:             "localhost:" + webAPIPort,
	})

	// ✅ NEW: Apply CORS middleware to the server's HTTP handler
	corsMiddleware := createCORSMiddleware()

	// Wrap the existing mux with CORS
	if s.mux != nil {
		wrappedHandler := corsMiddleware.Handler(s.mux)
		s.httpServer = &http.Server{
			Addr:         ":" + webAPIPort,
			Handler:      wrappedHandler, // ✅ CRITICAL: Use CORS-wrapped handler
			ReadTimeout:  45 * time.Second,
			WriteTimeout: 45 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
	}

	log.Printf("✅ Node %s → storage %s (CORS enabled)", s.FileServer.ID, root)

	/* enterprise extras */
	nodeID := generateNodeID() + "-" + listenAddr
	s.initializeBFTConsensus(nodeID)
	s.initializePostQuantumCrypto(nodeID)
	s.initializeDynamicSharding(nodeID)
	s.initializeAdvancedZeroTrust()
	s.initializeThresholdSecretSharing()
	s.initializeAttributeBasedEncryption()
	s.initializeContinuousAuthentication()
	s.initializePIIDetection()
	s.initializeGDPRCompliance()
	s.initializeImmutableAudit()
	s.initializePolicyEngine()

	if s.FileServer.Transport != nil {
		log.Println("🔗 Peer connection handling initialized")
	}
	return s
}

/* ── demo utilities ─────────────────────────────────── */

func createDemoFiles(s *EnterpriseFileServer, sess string) {
	if os.Getenv("DATAVAULT_NO_DEMO") == "true" {
		return
	}
	files := map[string]string{
		"readme.md": "# DataVault Enterprise\n",
	}
	for name, body := range files {
		if err := s.AuthenticatedStore(sess, name, bytes.NewReader([]byte(body))); err != nil {
			log.Printf("demo store %s: %v", name, err)
		}
	}
}

/* ── main ───────────────────────────────────────────── */

func main() {
	fmt.Println("🚀 DataVault Enterprise – flat storage")

	/* graceful shutdown */
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	peers := []string{"localhost:8080", "localhost:8081", "localhost:8082"}

	n1 := makeEnterpriseServer(":9000", "8080", peers)
	n2 := makeEnterpriseServer(":9001", "8081", peers)
	n3 := makeEnterpriseServer(":9002", "8082", peers)

	nodes := []*EnterpriseFileServer{n1, n2, n3}

	for i, srv := range nodes {
		go func(idx int, efs *EnterpriseFileServer) {
			log.Printf("🚀 node %d: %s (API :%s) with CORS middleware",
				idx+1, efs.FileServer.Transport.Addr(), efs.webAPIPort)
			if err := efs.Start(); err != nil {
				log.Fatalf("node %d died: %v", idx+1, err)
			}
		}(i, srv)
	}

	time.Sleep(3 * time.Second)

	/* tiny demo file on node-3 */
	user, _ := n3.authManager.CreateUser("demo", "demo", RoleUser)
	sess, _ := n3.authManager.Login(user.Username, "demo")
	createDemoFiles(n3, sess.ID)

	fmt.Println("✅ All nodes ready with CORS – Ctrl-C to stop")
	<-sig
	fmt.Println("🛑 shutting down")
}
