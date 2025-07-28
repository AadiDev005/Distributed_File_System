package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/anthdm/foreverstore/p2p"
)

func makeEnterpriseServer(listenAddr, webAPIPort string, nodes ...string) *EnterpriseFileServer {
	tcptransportOpts := p2p.TCPTransportOpts{
		ListenAddr:    listenAddr,
		HandshakeFunc: p2p.NOPHandshakeFunc,
		Decoder:       p2p.DefaultDecoder{},
	}
	tcpTransport := p2p.NewTCPTransport(tcptransportOpts)

	authManager := NewAuthManager()
	masterKey := newEncryptionKey()
	enterpriseEncryption := NewEnterpriseEncryption(masterKey)
	auditLogger := NewAuditLogger(fmt.Sprintf("%s_audit.log", listenAddr))

	adminUser, err := authManager.CreateUser("admin", "admin123", RoleSuperAdmin)
	if err != nil {
		log.Fatal("Failed to create admin user:", err)
	}

	if err := enterpriseEncryption.GenerateUserKey(adminUser.ID); err != nil {
		log.Fatal("Failed to generate admin key:", err)
	}

	fileServerOpts := FileServerOpts{
		EncKey:            newEncryptionKey(),
		StorageRoot:       listenAddr + "_enterprise_network",
		PathTransformFunc: CASPathTransformFunc,
		Transport:         tcpTransport,
	}

	enterpriseOpts := EnterpriseFileServerOpts{
		FileServerOpts:       fileServerOpts,
		AuthManager:          authManager,
		EnterpriseEncryption: enterpriseEncryption,
		AuditLogger:          auditLogger,
		EnableWebAPI:         true,
		WebAPIPort:           webAPIPort,
	}

	s := NewEnterpriseFileServer(enterpriseOpts)

	// Initialize Zero-Trust Gateway

	// Initialize Compliance Engine
	// Initialize BFT Consensus
	s.initializeBFTConsensus()

	// Initialize Post-Quantum Cryptography
	s.initializePostQuantumCrypto()

	// Initialize Dynamic Sharding
	s.initializeDynamicSharding()

	// Initialize Advanced Zero-Trust Gateway
	s.initializeAdvancedZeroTrust()

	// Initialize Threshold Secret Sharing
	s.initializeThresholdSecretSharing()

	// Initialize Attribute-Based Encryption
	s.initializeAttributeBasedEncryption()

	// Initialise Continuous Authentication
	s.initializeContinuousAuthentication()

	// Initialize PII Detection Engine
	s.initializePIIDetection()

	// Initialize GDPR Compliance Engine
	s.initializeGDPRCompliance()

	// Initialize Immutable Audit Trail System
	s.initializeImmutableAudit()

	// Initialize AI-Powered Policy Recommendation Engine
	s.initializePolicyEngine()
	tcpTransport.OnPeer = s.FileServer.OnPeer

	return s
}

func main() {
	fmt.Println("🚀 Starting DataVault Enterprise with BFT...")

	s1 := makeEnterpriseServer(":3000", "8080", "")
	s2 := makeEnterpriseServer(":4000", "8081", "")
	s3 := makeEnterpriseServer(":5000", "8082", ":3000", ":4000")

	go func() { log.Fatal(s1.Start()) }()
	time.Sleep(500 * time.Millisecond)

	go func() { log.Fatal(s2.Start()) }()
	time.Sleep(2 * time.Second)

	go s3.Start()
	time.Sleep(3 * time.Second)

	fmt.Println("\n=== DataVault Enterprise with BFT Demo ===")

	testUser, err := s3.authManager.CreateUser("testuser", "password123", RoleUser)
	if err != nil {
		log.Fatal("Failed to create test user:", err)
	}

	if err := s3.enterpriseEncryption.GenerateUserKey(testUser.ID); err != nil {
		log.Fatal("Failed to generate test user key:", err)
	}

	session, err := s3.authManager.Login("testuser", "password123")
	if err != nil {
		log.Fatal("Failed to login:", err)
	}

	fmt.Printf("✅ Test user logged in with session: %s\n", session.ID[:8]+"...")

	fmt.Println("\n📁 Testing BFT consensus file storage...")
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("bft_doc_%d.txt", i)
		data := bytes.NewReader([]byte(fmt.Sprintf("BFT Document #%d - Byzantine Fault Tolerant Content", i)))

		if err := s3.AuthenticatedStore(session.ID, key, data); err != nil {
			log.Printf("❌ Failed to store %s: %v", key, err)
		} else {
			fmt.Printf("✅ Stored %s with BFT consensus\n", key)
		}
	}

	fmt.Println("\n📖 Retrieving BFT protected files...")
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("bft_doc_%d.txt", i)

		r, err := s3.AuthenticatedGet(session.ID, key)
		if err != nil {
			log.Printf("❌ Failed to get %s: %v", key, err)
		} else {
			content, _ := io.ReadAll(r)
			fmt.Printf("✅ Retrieved %s: %s\n", key, string(content))
		}
	}

	events := s3.auditLogger.GetEvents(10)
	fmt.Printf("\n📊 Recent Audit Events (%d total):\n", len(events))
	for i, event := range events {
		if i < 5 {
			fmt.Printf("[%s] %s: %s - %s (User: %s)\n",
				event.Timestamp.Format("15:04:05"),
				event.EventType,
				event.Action,
				event.Result,
				event.UserID[:8]+"...")
		}
	}

	fmt.Println("\n🎉 DataVault Enterprise with BFT is running!")
	fmt.Println("\n🌐 Web Dashboards with BFT Status:")
	fmt.Println("- Node 1 (P2P :3000): http://localhost:8080")
	fmt.Println("- Node 2 (P2P :4000): http://localhost:8081")
	fmt.Println("- Node 3 (P2P :5000): http://localhost:8082")

	fmt.Println("\n🔐 Test Credentials:")
	fmt.Println("- Admin: admin / admin123")
	fmt.Println("- User: testuser / password123")

	fmt.Println("\n🛡️ Byzantine Fault Tolerance Features:")
	fmt.Println("- Consensus mechanism for file operations")
	fmt.Println("- Network health monitoring")
	fmt.Println("- Automatic byzantine node detection")
	fmt.Println("- Fault tolerant operation with failed nodes")

	select {}
}
