package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	// "encoding/json"
	"fmt"
	// "io"
	"strings"
	"sync"
	"time"
)

// AttributeBasedEncryptionManager handles ABE policies and encryption
type AttributeBasedEncryptionManager struct {
	nodeID             string
	attributeAuthority *AttributeAuthority
	policyEngine       *PolicyEngine
	accessStructures   map[string]*AccessStructure
	userAttributes     map[string]*UserAttributeSet
	encryptionPolicies map[string]*EncryptionPolicy
	decryptionKeys     map[string]*DecryptionKey
	attributeKeys      map[string]*AttributeKey
	accessRequests     map[string]*AccessRequest
	mutex              sync.RWMutex
	server             *EnterpriseFileServer
	config             *ABEConfig
}

// AttributeAuthority manages attribute certificates and policies
type AttributeAuthority struct {
	AuthorityID  string                    `json:"authority_id"`
	Name         string                    `json:"name"`
	PublicKey    string                    `json:"public_key"`
	PrivateKey   string                    `json:"-"` // Never serialize
	ManagedAttrs []string                  `json:"managed_attributes"`
	IssuedCerts  map[string]*AttributeCert `json:"issued_certificates"`
	TrustLevel   float64                   `json:"trust_level"`
	Status       string                    `json:"status"`
	CreatedAt    time.Time                 `json:"created_at"`
	LastActivity time.Time                 `json:"last_activity"`
}

// PolicyEngine evaluates access policies against user attributes
type PolicyEngine struct {
	EngineID         string                   `json:"engine_id"`
	PolicyLanguage   string                   `json:"policy_language"` // boolean_formula, tree_based, linear_secret_sharing
	EvaluationCache  map[string]*PolicyResult `json:"evaluation_cache"`
	Statistics       *PolicyStatistics        `json:"statistics"`
	LastOptimized    time.Time                `json:"last_optimized"`
	OptimizerEnabled bool                     `json:"optimizer_enabled"`
}

// AccessStructure defines the access policy for encrypted data
type AccessStructure struct {
	StructureID     string           `json:"structure_id"`
	PolicyFormula   string           `json:"policy_formula"`
	RequiredAttrs   []string         `json:"required_attributes"`
	PolicyType      string           `json:"policy_type"` // threshold, boolean, hierarchical
	MinThreshold    int              `json:"min_threshold"`
	MaxUsers        int              `json:"max_users"`
	TimeRestriction *TimeRestriction `json:"time_restriction,omitempty"`
	LocationPolicy  *LocationPolicy  `json:"location_policy,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	CreatedBy       string           `json:"created_by"`
	IsActive        bool             `json:"is_active"`
}

// UserAttributeSet contains all attributes for a user
type UserAttributeSet struct {
	UserID           string                    `json:"user_id"`
	Attributes       map[string]*UserAttribute `json:"attributes"`
	AttributeCerts   map[string]*AttributeCert `json:"attribute_certificates"`
	LastUpdated      time.Time                 `json:"last_updated"`
	ExpirationTime   time.Time                 `json:"expiration_time"`
	RevocationStatus string                    `json:"revocation_status"`
	TrustScore       float64                   `json:"trust_score"`
}

// UserAttribute represents a single attribute with metadata
type UserAttribute struct {
	AttrID          string     `json:"attribute_id"`
	AttrName        string     `json:"attribute_name"`
	AttrValue       string     `json:"attribute_value"`
	AttrType        string     `json:"attribute_type"` // role, clearance, department, location
	Authority       string     `json:"issuing_authority"`
	IssueDate       time.Time  `json:"issue_date"`
	ExpirationDate  *time.Time `json:"expiration_date,omitempty"`
	VerificationSig string     `json:"verification_signature"`
	IsVerified      bool       `json:"is_verified"`
	RevocationCheck bool       `json:"revocation_check_required"`
}

// AttributeCert represents a cryptographic certificate for an attribute
type AttributeCert struct {
	CertID          string    `json:"certificate_id"`
	UserID          string    `json:"user_id"`
	AttributeID     string    `json:"attribute_id"`
	PublicKey       string    `json:"public_key"`
	PrivateKey      string    `json:"-"` // Never serialize
	Authority       string    `json:"issuing_authority"`
	IssueDate       time.Time `json:"issue_date"`
	ExpirationDate  time.Time `json:"expiration_date"`
	RevocationList  string    `json:"revocation_list_url"`
	IsRevoked       bool      `json:"is_revoked"`
	CertificateData []byte    `json:"certificate_data"`
}

// EncryptionPolicy defines how data should be encrypted with ABE
type EncryptionPolicy struct {
	PolicyID        string           `json:"policy_id"`
	Name            string           `json:"name"`
	AccessStructure *AccessStructure `json:"access_structure"`
	EncryptionAlg   string           `json:"encryption_algorithm"`
	KeySize         int              `json:"key_size"`
	Attributes      []string         `json:"required_attributes"`
	DataClass       string           `json:"data_classification"`
	RetentionPolicy *RetentionPolicy `json:"retention_policy"`
	ComplianceReqs  []string         `json:"compliance_requirements"`
	CreatedAt       time.Time        `json:"created_at"`
	CreatedBy       string           `json:"created_by"`
	IsActive        bool             `json:"is_active"`
}

// DecryptionKey contains the user's decryption capabilities
type DecryptionKey struct {
	KeyID      string    `json:"key_id"`
	UserID     string    `json:"user_id"`
	Attributes []string  `json:"attributes"`
	KeyData    []byte    `json:"-"` // Never serialize
	Algorithm  string    `json:"algorithm"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	UsageCount int       `json:"usage_count"`
	MaxUsage   int       `json:"max_usage"`
	IsActive   bool      `json:"is_active"`
}

// AttributeKey represents cryptographic material for an attribute
type AttributeKey struct {
	AttrKeyID   string    `json:"attribute_key_id"`
	AttributeID string    `json:"attribute_id"`
	UserID      string    `json:"user_id"`
	KeyMaterial []byte    `json:"-"` // Never serialize
	DerivedFrom string    `json:"derived_from"`
	Authority   string    `json:"issuing_authority"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	KeyVersion  int       `json:"key_version"`
	IsActive    bool      `json:"is_active"`
}

// AccessRequest tracks ABE access attempts
type AccessRequest struct {
	RequestID         string        `json:"request_id"`
	UserID            string        `json:"user_id"`
	ResourceID        string        `json:"resource_id"`
	PolicyID          string        `json:"policy_id"`
	UserAttrs         []string      `json:"user_attributes"`
	PolicyResult      *PolicyResult `json:"policy_result"`
	DecryptionAttempt bool          `json:"decryption_attempted"`
	Success           bool          `json:"success"`
	FailureReason     string        `json:"failure_reason,omitempty"`
	RequestTime       time.Time     `json:"request_time"`
	ProcessingTime    time.Duration `json:"processing_time"`
	AuditTrail        []string      `json:"audit_trail"`
}

// PolicyResult contains the result of policy evaluation
type PolicyResult struct {
	ResultID       string
	PolicyID       string
	UserID         string
	Satisfied      bool
	MatchedAttrs   []string
	MissingAttrs   []string
	Score          float64
	EvaluationTime time.Duration // stay: how long the evaluation took
	EvaluatedAt    time.Time     // NEW: when the result was produced
	CacheHit       bool
	Explanation    string
}

// Supporting types
type TimeRestriction struct {
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	AllowedHours []int     `json:"allowed_hours"`
	AllowedDays  []string  `json:"allowed_days"`
	TimeZone     string    `json:"timezone"`
	IsActive     bool      `json:"is_active"`
}

type LocationPolicy struct {
	AllowedCountries []string `json:"allowed_countries"`
	AllowedRegions   []string `json:"allowed_regions"`
	RestrictedIPs    []string `json:"restricted_ip_ranges"`
	GeofenceRadius   float64  `json:"geofence_radius_km"`
	LocationRequired bool     `json:"location_verification_required"`
}

type PolicyStatistics struct {
	TotalEvaluations  int64         `json:"total_evaluations"`
	SuccessfulAccess  int64         `json:"successful_access"`
	DeniedAccess      int64         `json:"denied_access"`
	CacheHitRate      float64       `json:"cache_hit_rate"`
	AvgEvaluationTime time.Duration `json:"avg_evaluation_time"`
	LastReset         time.Time     `json:"last_reset"`
}

type ABEConfig struct {
	DefaultKeySize          int           `json:"default_key_size"`
	AttributeExpiration     time.Duration `json:"attribute_expiration"`
	PolicyCacheTimeout      time.Duration `json:"policy_cache_timeout"`
	MaxAttributesPerUser    int           `json:"max_attributes_per_user"`
	RequireMultiAuth        bool          `json:"require_multi_authority"`
	EnablePolicyCache       bool          `json:"enable_policy_cache"`
	AuditAllAccess          bool          `json:"audit_all_access"`
	RevocationCheckInterval time.Duration `json:"revocation_check_interval"`
}

// ABEEncryptedData represents data encrypted with attribute-based encryption
type ABEEncryptedData struct {
	EncryptedData   []byte           `json:"encrypted_data"`
	PolicyID        string           `json:"policy_id"`
	AccessStructure *AccessStructure `json:"access_structure"`
	EncryptionKey   []byte           `json:"encryption_key"` // Encrypted with ABE
	Algorithm       string           `json:"algorithm"`
	Nonce           []byte           `json:"nonce"`
	CreatedAt       time.Time        `json:"created_at"`
	CreatedBy       string           `json:"created_by"`
	DataHash        string           `json:"data_hash"`
}

func NewAttributeBasedEncryptionManager(nodeID string, server *EnterpriseFileServer) *AttributeBasedEncryptionManager {
	return &AttributeBasedEncryptionManager{
		nodeID:             nodeID,
		attributeAuthority: NewAttributeAuthority(),
		policyEngine:       NewPolicyEngine(),
		accessStructures:   make(map[string]*AccessStructure),
		userAttributes:     make(map[string]*UserAttributeSet),
		encryptionPolicies: make(map[string]*EncryptionPolicy),
		decryptionKeys:     make(map[string]*DecryptionKey),
		attributeKeys:      make(map[string]*AttributeKey),
		accessRequests:     make(map[string]*AccessRequest),
		server:             server,
		config: &ABEConfig{
			DefaultKeySize:          256,
			AttributeExpiration:     365 * 24 * time.Hour, // 1 year
			PolicyCacheTimeout:      1 * time.Hour,
			MaxAttributesPerUser:    50,
			RequireMultiAuth:        true,
			EnablePolicyCache:       true,
			AuditAllAccess:          true,
			RevocationCheckInterval: 24 * time.Hour,
		},
	}
}

func NewAttributeAuthority() *AttributeAuthority {
	return &AttributeAuthority{
		AuthorityID:  generateID(),
		Name:         "Enterprise Attribute Authority",
		ManagedAttrs: []string{"role", "department", "clearance", "location", "project"},
		IssuedCerts:  make(map[string]*AttributeCert),
		TrustLevel:   1.0,
		Status:       "active",
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		EngineID:        generateID(),
		PolicyLanguage:  "boolean_formula",
		EvaluationCache: make(map[string]*PolicyResult),
		Statistics: &PolicyStatistics{
			LastReset: time.Now(),
		},
		LastOptimized:    time.Now(),
		OptimizerEnabled: true,
	}
}

// Initialize ABE Manager
func (abe *AttributeBasedEncryptionManager) Initialize() {
	abe.mutex.Lock()
	defer abe.mutex.Unlock()

	// Create default access structures and policies
	abe.createDefaultAccessStructures()
	abe.createDefaultEncryptionPolicies()
	abe.initializeDefaultUserAttributes()

	// Start background processes
	go abe.attributeMaintenanceLoop()
	go abe.policyOptimizationLoop()
	go abe.revocationCheckLoop()

	fmt.Printf("[ABE] Attribute-Based Encryption initialized for node %s\n", abe.nodeID[:8])
	fmt.Printf("[ABE] Configuration: %d max attrs/user, %s cache timeout, multi-auth: %t\n",
		abe.config.MaxAttributesPerUser, abe.config.PolicyCacheTimeout, abe.config.RequireMultiAuth)
}

// Create default access structures
func (abe *AttributeBasedEncryptionManager) createDefaultAccessStructures() {
	structures := []*AccessStructure{
		{
			StructureID:   generateID(),
			PolicyFormula: "(role:admin OR role:superadmin) AND department:security",
			RequiredAttrs: []string{"role", "department"},
			PolicyType:    "boolean",
			MinThreshold:  2,
			MaxUsers:      10,
			CreatedAt:     time.Now(),
			CreatedBy:     "system",
			IsActive:      true,
		},
		{
			StructureID:   generateID(),
			PolicyFormula: "clearance:secret AND (department:engineering OR department:research)",
			RequiredAttrs: []string{"clearance", "department"},
			PolicyType:    "boolean",
			MinThreshold:  2,
			MaxUsers:      50,
			CreatedAt:     time.Now(),
			CreatedBy:     "system",
			IsActive:      true,
		},
		{
			StructureID:   generateID(),
			PolicyFormula: "role:user AND department:finance AND clearance:confidential",
			RequiredAttrs: []string{"role", "department", "clearance"},
			PolicyType:    "threshold",
			MinThreshold:  3,
			MaxUsers:      25,
			TimeRestriction: &TimeRestriction{
				AllowedHours: []int{9, 10, 11, 12, 13, 14, 15, 16, 17},
				AllowedDays:  []string{"monday", "tuesday", "wednesday", "thursday", "friday"},
				TimeZone:     "UTC",
				IsActive:     true,
			},
			CreatedAt: time.Now(),
			CreatedBy: "system",
			IsActive:  true,
		},
	}

	for _, structure := range structures {
		abe.accessStructures[structure.StructureID] = structure
	}

	fmt.Printf("[ABE] Created %d default access structures\n", len(structures))
}

// Create default encryption policies
func (abe *AttributeBasedEncryptionManager) createDefaultEncryptionPolicies() {
	policies := []*EncryptionPolicy{
		{
			PolicyID:        generateID(),
			Name:            "High Security Policy",
			AccessStructure: abe.getAccessStructureByFormula("(role:admin OR role:superadmin) AND department:security"),
			EncryptionAlg:   "AES-256-GCM",
			KeySize:         256,
			Attributes:      []string{"role:admin", "department:security"},
			DataClass:       "highly_confidential",
			ComplianceReqs:  []string{"SOX", "PCI-DSS"},
			CreatedAt:       time.Now(),
			CreatedBy:       "system",
			IsActive:        true,
		},
		{
			PolicyID:        generateID(),
			Name:            "Research Data Policy",
			AccessStructure: abe.getAccessStructureByFormula("clearance:secret AND (department:engineering OR department:research)"),
			EncryptionAlg:   "AES-256-GCM",
			KeySize:         256,
			Attributes:      []string{"clearance:secret", "department:engineering"},
			DataClass:       "confidential",
			ComplianceReqs:  []string{"GDPR"},
			CreatedAt:       time.Now(),
			CreatedBy:       "system",
			IsActive:        true,
		},
		{
			PolicyID:        generateID(),
			Name:            "Financial Data Policy",
			AccessStructure: abe.getAccessStructureByFormula("role:user AND department:finance AND clearance:confidential"),
			EncryptionAlg:   "AES-256-GCM",
			KeySize:         256,
			Attributes:      []string{"role:user", "department:finance", "clearance:confidential"},
			DataClass:       "financial",
			ComplianceReqs:  []string{"SOX", "GDPR"},
			CreatedAt:       time.Now(),
			CreatedBy:       "system",
			IsActive:        true,
		},
	}

	for _, policy := range policies {
		abe.encryptionPolicies[policy.PolicyID] = policy
	}

	fmt.Printf("[ABE] Created %d default encryption policies\n", len(policies))
}

// Initialize default user attributes for demo
func (abe *AttributeBasedEncryptionManager) initializeDefaultUserAttributes() {
	// Create attributes for testuser
	testUserAttrs := &UserAttributeSet{
		UserID:           "testuser", // This should match your test user ID
		Attributes:       make(map[string]*UserAttribute),
		AttributeCerts:   make(map[string]*AttributeCert),
		LastUpdated:      time.Now(),
		ExpirationTime:   time.Now().Add(365 * 24 * time.Hour),
		RevocationStatus: "valid",
		TrustScore:       0.85,
	}

	// Add sample attributes
	attributes := []*UserAttribute{
		{
			AttrID:     generateID(),
			AttrName:   "role",
			AttrValue:  "user",
			AttrType:   "role",
			Authority:  abe.attributeAuthority.AuthorityID,
			IssueDate:  time.Now(),
			IsVerified: true,
		},
		{
			AttrID:     generateID(),
			AttrName:   "department",
			AttrValue:  "engineering",
			AttrType:   "department",
			Authority:  abe.attributeAuthority.AuthorityID,
			IssueDate:  time.Now(),
			IsVerified: true,
		},
		{
			AttrID:     generateID(),
			AttrName:   "clearance",
			AttrValue:  "confidential",
			AttrType:   "clearance",
			Authority:  abe.attributeAuthority.AuthorityID,
			IssueDate:  time.Now(),
			IsVerified: true,
		},
		{
			AttrID:     generateID(),
			AttrName:   "location",
			AttrValue:  "headquarters",
			AttrType:   "location",
			Authority:  abe.attributeAuthority.AuthorityID,
			IssueDate:  time.Now(),
			IsVerified: true,
		},
	}

	for _, attr := range attributes {
		testUserAttrs.Attributes[attr.AttrName] = attr
	}

	abe.userAttributes["testuser"] = testUserAttrs

	fmt.Printf("[ABE] Initialized attributes for demo user with %d attributes\n", len(attributes))
}

// EncryptWithABE encrypts data using attribute-based encryption
func (abe *AttributeBasedEncryptionManager) EncryptWithABE(data []byte, policyID string, createdBy string) (*ABEEncryptedData, error) {
	abe.mutex.Lock()
	defer abe.mutex.Unlock()

	// Get encryption policy
	policy, exists := abe.encryptionPolicies[policyID]
	if !exists {
		return nil, fmt.Errorf("encryption policy not found: %s", policyID)
	}

	if !policy.IsActive {
		return nil, fmt.Errorf("encryption policy is inactive: %s", policyID)
	}

	// Generate encryption key
	encKey := make([]byte, policy.KeySize/8) // Convert bits to bytes
	if _, err := rand.Read(encKey); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %v", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	// Generate nonce
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Encrypt data
	encryptedData := gcm.Seal(nil, nonce, data, nil)

	// Calculate data hash
	hash := sha256.Sum256(data)
	dataHash := fmt.Sprintf("%x", hash)

	// Create ABE encrypted data structure
	abeData := &ABEEncryptedData{
		EncryptedData:   encryptedData,
		PolicyID:        policyID,
		AccessStructure: policy.AccessStructure,
		EncryptionKey:   encKey, // In real ABE, this would be encrypted with the access structure
		Algorithm:       policy.EncryptionAlg,
		Nonce:           nonce,
		CreatedAt:       time.Now(),
		CreatedBy:       createdBy,
		DataHash:        dataHash,
	}

	// Log encryption event
	if abe.server.auditLogger != nil {
		abe.server.auditLogger.LogEvent(
			"abe_encryption",
			createdBy,
			policyID,
			"encrypt_data",
			"success",
			map[string]interface{}{
				"policy_id":      policyID,
				"data_size":      len(data),
				"encryption_alg": policy.EncryptionAlg,
				"access_formula": policy.AccessStructure.PolicyFormula,
			},
		)
	}

	fmt.Printf("[ABE] Data encrypted with policy %s, size: %d bytes\n", policyID, len(data))

	return abeData, nil
}

// DecryptWithABE decrypts data using attribute-based encryption
func (abe *AttributeBasedEncryptionManager) DecryptWithABE(abeData *ABEEncryptedData, userID string) ([]byte, error) {
	abe.mutex.Lock()
	defer abe.mutex.Unlock()

	startTime := time.Now()

	// Create access request
	requestID := generateID()
	accessReq := &AccessRequest{
		RequestID:   requestID,
		UserID:      userID,
		ResourceID:  abeData.PolicyID,
		PolicyID:    abeData.PolicyID,
		RequestTime: startTime,
		AuditTrail:  make([]string, 0),
	}

	// Get user attributes
	userAttrs, exists := abe.userAttributes[userID]
	if !exists {
		accessReq.Success = false
		accessReq.FailureReason = "user attributes not found"
		abe.accessRequests[requestID] = accessReq
		return nil, fmt.Errorf("user attributes not found for user: %s", userID)
	}

	// Extract user attribute names for policy evaluation
	userAttrNames := make([]string, 0)
	for attrName, attr := range userAttrs.Attributes {
		if attr.IsVerified {
			userAttrNames = append(userAttrNames, fmt.Sprintf("%s:%s", attrName, attr.AttrValue))
		}
	}
	accessReq.UserAttrs = userAttrNames

	// Evaluate access policy
	policyResult, err := abe.evaluateAccessPolicy(abeData.AccessStructure, userAttrNames, userID)
	if err != nil {
		accessReq.Success = false
		accessReq.FailureReason = fmt.Sprintf("policy evaluation failed: %v", err)
		accessReq.ProcessingTime = time.Since(startTime)
		abe.accessRequests[requestID] = accessReq
		return nil, fmt.Errorf("policy evaluation failed: %v", err)
	}

	accessReq.PolicyResult = policyResult

	if !policyResult.Satisfied {
		accessReq.Success = false
		accessReq.FailureReason = "access policy not satisfied"
		accessReq.ProcessingTime = time.Since(startTime)
		abe.accessRequests[requestID] = accessReq

		// Log access denial
		if abe.server.auditLogger != nil {
			abe.server.auditLogger.LogEvent(
				"abe_access_denied",
				userID,
				abeData.PolicyID,
				"decrypt_attempt",
				"denied",
				map[string]interface{}{
					"request_id":     requestID,
					"missing_attrs":  policyResult.MissingAttrs,
					"matched_attrs":  policyResult.MatchedAttrs,
					"policy_formula": abeData.AccessStructure.PolicyFormula,
				},
			)
		}

		return nil, fmt.Errorf("access denied: missing attributes %v", policyResult.MissingAttrs)
	}

	// Check time restrictions if present
	if abeData.AccessStructure.TimeRestriction != nil && abeData.AccessStructure.TimeRestriction.IsActive {
		if !abe.checkTimeRestrictions(abeData.AccessStructure.TimeRestriction) {
			accessReq.Success = false
			accessReq.FailureReason = "time restrictions not satisfied"
			accessReq.ProcessingTime = time.Since(startTime)
			abe.accessRequests[requestID] = accessReq
			return nil, fmt.Errorf("access denied: outside allowed time window")
		}
	}

	accessReq.DecryptionAttempt = true

	// Perform decryption
	block, err := aes.NewCipher(abeData.EncryptionKey)
	if err != nil {
		accessReq.Success = false
		accessReq.FailureReason = "cipher creation failed"
		accessReq.ProcessingTime = time.Since(startTime)
		abe.accessRequests[requestID] = accessReq
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		accessReq.Success = false
		accessReq.FailureReason = "GCM creation failed"
		accessReq.ProcessingTime = time.Since(startTime)
		abe.accessRequests[requestID] = accessReq
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	decryptedData, err := gcm.Open(nil, abeData.Nonce, abeData.EncryptedData, nil)
	if err != nil {
		accessReq.Success = false
		accessReq.FailureReason = "decryption failed"
		accessReq.ProcessingTime = time.Since(startTime)
		abe.accessRequests[requestID] = accessReq
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	// Verify data integrity
	hash := sha256.Sum256(decryptedData)
	dataHash := fmt.Sprintf("%x", hash)
	if dataHash != abeData.DataHash {
		accessReq.Success = false
		accessReq.FailureReason = "data integrity check failed"
		accessReq.ProcessingTime = time.Since(startTime)
		abe.accessRequests[requestID] = accessReq
		return nil, fmt.Errorf("data integrity check failed")
	}

	accessReq.Success = true
	accessReq.ProcessingTime = time.Since(startTime)
	abe.accessRequests[requestID] = accessReq

	// Log successful access
	if abe.server.auditLogger != nil {
		abe.server.auditLogger.LogEvent(
			"abe_access_granted",
			userID,
			abeData.PolicyID,
			"decrypt_success",
			"success",
			map[string]interface{}{
				"request_id":      requestID,
				"matched_attrs":   policyResult.MatchedAttrs,
				"policy_formula":  abeData.AccessStructure.PolicyFormula,
				"processing_time": accessReq.ProcessingTime.String(),
				"data_size":       len(decryptedData),
			},
		)
	}

	fmt.Printf("[ABE] Data decrypted successfully for user %s, processing time: %v\n",
		userID, accessReq.ProcessingTime)

	return decryptedData, nil
}

// Evaluate access policy against user attributes
func (abe *AttributeBasedEncryptionManager) evaluateAccessPolicy(accessStructure *AccessStructure, userAttrs []string, userID string) (*PolicyResult, error) {
	startTime := time.Now()

	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s:%v", accessStructure.StructureID, userID, userAttrs)
	if abe.config.EnablePolicyCache {
		if cached, exists := abe.policyEngine.EvaluationCache[cacheKey]; exists {
			// Check if cache is still valid
			if time.Since(cached.EvaluatedAt) < abe.config.PolicyCacheTimeout {
				cached.CacheHit = true
				return cached, nil
			}
		}
	}

	result := &PolicyResult{
		ResultID:       generateID(),
		PolicyID:       accessStructure.StructureID,
		UserID:         userID,
		MatchedAttrs:   make([]string, 0),
		MissingAttrs:   make([]string, 0),
		EvaluationTime: time.Since(startTime),
		CacheHit:       false,
	}

	// Convert user attributes to map for easier lookup
	userAttrMap := make(map[string]bool)
	for _, attr := range userAttrs {
		userAttrMap[attr] = true
	}

	// Evaluate based on policy type
	switch accessStructure.PolicyType {
	case "boolean":
		result.Satisfied = abe.evaluateBooleanFormula(accessStructure.PolicyFormula, userAttrMap, result)
	case "threshold":
		result.Satisfied = abe.evaluateThresholdPolicy(accessStructure, userAttrMap, result)
	default:
		return nil, fmt.Errorf("unsupported policy type: %s", accessStructure.PolicyType)
	}

	// Calculate satisfaction score
	if len(accessStructure.RequiredAttrs) > 0 {
		result.Score = float64(len(result.MatchedAttrs)) / float64(len(accessStructure.RequiredAttrs))
	}

	// Generate explanation
	if result.Satisfied {
		result.Explanation = fmt.Sprintf("Policy satisfied with %d/%d required attributes",
			len(result.MatchedAttrs), len(accessStructure.RequiredAttrs))
	} else {
		result.Explanation = fmt.Sprintf("Policy not satisfied, missing: %v", result.MissingAttrs)
	}

	result.EvaluationTime = time.Since(startTime)
    result.EvaluatedAt = time.Now()
	// Cache result if enabled
	if abe.config.EnablePolicyCache {
		abe.policyEngine.EvaluationCache[cacheKey] = result
	}

	// Update statistics
	abe.policyEngine.Statistics.TotalEvaluations++
	if result.Satisfied {
		abe.policyEngine.Statistics.SuccessfulAccess++
	} else {
		abe.policyEngine.Statistics.DeniedAccess++
	}

	return result, nil
}

// Evaluate boolean formula (simplified implementation)
func (abe *AttributeBasedEncryptionManager) evaluateBooleanFormula(formula string, userAttrs map[string]bool, result *PolicyResult) bool {
	// Simplified boolean evaluation - in production this would use a proper parser

	satisfied := true
	andTerms := strings.Split(formula, " AND ")

	for _, andTerm := range andTerms {
		termSatisfied := false
		orTerms := strings.Split(andTerm, " OR ")

		for _, orTerm := range orTerms {
			orTerm = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(orTerm, "(", ""), ")", ""))
			if userAttrs[orTerm] {
				result.MatchedAttrs = append(result.MatchedAttrs, orTerm)
				termSatisfied = true
				break
			}
		}

		if !termSatisfied {
			satisfied = false
			// Add missing terms to result
			for _, orTerm := range orTerms {
				orTerm = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(orTerm, "(", ""), ")", ""))
				if !contains(result.MissingAttrs, orTerm) {
					result.MissingAttrs = append(result.MissingAttrs, orTerm)
				}
			}
		}
	}

	return satisfied
}

// Evaluate threshold policy
func (abe *AttributeBasedEncryptionManager) evaluateThresholdPolicy(accessStructure *AccessStructure, userAttrs map[string]bool, result *PolicyResult) bool {
	matchCount := 0

	for _, requiredAttr := range accessStructure.RequiredAttrs {
		found := false
		for userAttr := range userAttrs {
			if strings.Contains(userAttr, requiredAttr) {
				result.MatchedAttrs = append(result.MatchedAttrs, userAttr)
				matchCount++
				found = true
				break
			}
		}
		if !found {
			result.MissingAttrs = append(result.MissingAttrs, requiredAttr)
		}
	}

	return matchCount >= accessStructure.MinThreshold
}

// Check time restrictions
func (abe *AttributeBasedEncryptionManager) checkTimeRestrictions(restriction *TimeRestriction) bool {
	now := time.Now()

	// Check if current time is within allowed hours
	currentHour := now.Hour()
	hourAllowed := false
	for _, allowedHour := range restriction.AllowedHours {
		if currentHour == allowedHour {
			hourAllowed = true
			break
		}
	}

	if !hourAllowed {
		return false
	}

	// Check if current day is allowed
	currentDay := strings.ToLower(now.Weekday().String())
	dayAllowed := false
	for _, allowedDay := range restriction.AllowedDays {
		if currentDay == allowedDay {
			dayAllowed = true
			break
		}
	}

	return dayAllowed
}

// Helper functions
func (abe *AttributeBasedEncryptionManager) getAccessStructureByFormula(formula string) *AccessStructure {
	for _, structure := range abe.accessStructures {
		if structure.PolicyFormula == formula {
			return structure
		}
	}
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Background maintenance loops
func (abe *AttributeBasedEncryptionManager) attributeMaintenanceLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		abe.performAttributeMaintenance()
	}
}

func (abe *AttributeBasedEncryptionManager) performAttributeMaintenance() {
	abe.mutex.Lock()
	defer abe.mutex.Unlock()

	expiredAttrs := 0

	// Check for expired attributes
	for _, userAttrs := range abe.userAttributes {
		for _, attr := range userAttrs.Attributes {
			if attr.ExpirationDate != nil && time.Now().After(*attr.ExpirationDate) {
				attr.IsVerified = false
				expiredAttrs++
			}
		}
	}

	if expiredAttrs > 0 {
		fmt.Printf("[ABE] Attribute maintenance: %d attributes expired\n", expiredAttrs)
	}
}

func (abe *AttributeBasedEncryptionManager) policyOptimizationLoop() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		abe.optimizePolicyCache()
	}
}

func (abe *AttributeBasedEncryptionManager) optimizePolicyCache() {
	abe.mutex.Lock()
	defer abe.mutex.Unlock()

	// Clear old cache entries
	cutoff := time.Now().Add(-abe.config.PolicyCacheTimeout)
	removed := 0

	for key, result := range abe.policyEngine.EvaluationCache {
		if result.EvaluatedAt.Before(cutoff) {
			delete(abe.policyEngine.EvaluationCache, key)
			removed++
		}
	}

	if removed > 0 {
		fmt.Printf("[ABE] Policy cache optimization: removed %d expired entries\n", removed)
	}

	abe.policyEngine.LastOptimized = time.Now()
}

func (abe *AttributeBasedEncryptionManager) revocationCheckLoop() {
	ticker := time.NewTicker(abe.config.RevocationCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Printf("[ABE] Performing revocation checks\n")
		// Implement revocation checking logic
	}
}

// Get ABE status
func (abe *AttributeBasedEncryptionManager) GetABEStatus() map[string]interface{} {
	abe.mutex.RLock()
	defer abe.mutex.RUnlock()

	activeUsers := 0
	for _, userAttrs := range abe.userAttributes {
		if userAttrs.RevocationStatus == "valid" {
			activeUsers++
		}
	}

	totalAttributes := 0
	for _, userAttrs := range abe.userAttributes {
		totalAttributes += len(userAttrs.Attributes)
	}

	return map[string]interface{}{
		"abe_manager_status":        "operational",
		"attribute_authority":       abe.attributeAuthority.Name,
		"total_access_structures":   len(abe.accessStructures),
		"total_encryption_policies": len(abe.encryptionPolicies),
		"active_users":              activeUsers,
		"total_attributes":          totalAttributes,
		"total_access_requests":     len(abe.accessRequests),
		"policy_cache_entries":      len(abe.policyEngine.EvaluationCache),
		"cache_hit_rate":            abe.policyEngine.Statistics.CacheHitRate,
		"total_evaluations":         abe.policyEngine.Statistics.TotalEvaluations,
		"successful_access":         abe.policyEngine.Statistics.SuccessfulAccess,
		"denied_access":             abe.policyEngine.Statistics.DeniedAccess,
		"policy_language":           abe.policyEngine.PolicyLanguage,
		"multi_authority_required":  abe.config.RequireMultiAuth,
		"audit_all_access":          abe.config.AuditAllAccess,
		"last_optimization":         abe.policyEngine.LastOptimized.Format(time.RFC3339),
	}
}
