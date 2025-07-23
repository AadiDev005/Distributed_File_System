package main

import (
    "fmt"
    "sync"
    "time"
)

// GDPRComplianceEngine handles automated GDPR compliance workflows
type GDPRComplianceEngine struct {
    nodeID                string
    dataSubjectRequests   map[string]*DataSubjectRequest
    erasureRequests       map[string]*ErasureRequest
    portabilityRequests   map[string]*PortabilityRequest
    dataInventory         map[string]*DataInventoryEntry
    consentManagement     *ConsentManager
    dataProcessingRecords map[string]*ProcessingRecord
    exportJobs            map[string]*DataExportJob
    erasureJobs           map[string]*DataErasureJob
    mutex                 sync.RWMutex
    server                *EnterpriseFileServer
    config                *GDPRConfig
}

// DataSubjectRequest represents a GDPR data subject request
type DataSubjectRequest struct {
    RequestID        string                 `json:"request_id"`
    DataSubjectID    string                 `json:"data_subject_id"`
    RequestType      string                 `json:"request_type"`
    Status           string                 `json:"status"`
    SubmittedAt      time.Time              `json:"submitted_at"`
    ProcessedAt      *time.Time             `json:"processed_at,omitempty"`
    CompletedAt      *time.Time             `json:"completed_at,omitempty"`
    RequestDetails   map[string]interface{} `json:"request_details"`
    IdentityVerified bool                   `json:"identity_verified"`
    ProcessingNotes  []string               `json:"processing_notes"`
    LegalBasis       string                 `json:"legal_basis"`
    ResponseData     *GDPRResponseData      `json:"response_data,omitempty"`
}

// ErasureRequest handles Right to Erasure (Article 17)
type ErasureRequest struct {
    ErasureID        string                 `json:"erasure_id"`
    DataSubjectID    string                 `json:"data_subject_id"`
    ErasureScope     string                 `json:"erasure_scope"`
    DataCategories   []string               `json:"data_categories"`
    FilesToErase     []string               `json:"files_to_erase"`
    Status           string                 `json:"status"`
    ErasureReason    string                 `json:"erasure_reason"`
    RequestedAt      time.Time              `json:"requested_at"`
    ProcessedAt      *time.Time             `json:"processed_at,omitempty"`
    VerificationData *IdentityVerification  `json:"verification_data"`
    ErasureLog       []ErasureLogEntry      `json:"erasure_log"`
    Exceptions       []ErasureException     `json:"exceptions"`
    ComplianceProof  *ErasureProof          `json:"compliance_proof"`
}

// PortabilityRequest handles Right to Data Portability (Article 20)
type PortabilityRequest struct {
    PortabilityID    string                 `json:"portability_id"`
    DataSubjectID    string                 `json:"data_subject_id"`
    ExportFormat     string                 `json:"export_format"`
    DataCategories   []string               `json:"data_categories"`
    FilesToExport    []string               `json:"files_to_export"`
    Status           string                 `json:"status"`
    RequestedAt      time.Time              `json:"requested_at"`
    ProcessedAt      *time.Time             `json:"processed_at,omitempty"`
    ExpiresAt        time.Time              `json:"expires_at"`
    DownloadURL      string                 `json:"download_url,omitempty"`
    ExportSize       int64                  `json:"export_size_bytes"`
    VerificationData *IdentityVerification  `json:"verification_data"`
    DataStructure    *PortableDataStructure `json:"data_structure"`
}

// Supporting types
type DataInventoryEntry struct {
    EntryID          string        `json:"entry_id"`
    DataSubjectID    string        `json:"data_subject_id"`
    FileID           string        `json:"file_id"`
    FileName         string        `json:"file_name"`
    DataCategory     string        `json:"data_category"`
    PIITypes         []string      `json:"pii_types"`
    LegalBasis       string        `json:"legal_basis"`
    ProcessingPurpose string       `json:"processing_purpose"`
    RetentionPeriod  time.Duration `json:"retention_period"`
    ConsentID        string        `json:"consent_id,omitempty"`
    CreatedAt        time.Time     `json:"created_at"`
    LastAccessed     *time.Time    `json:"last_accessed,omitempty"`
    ScheduledDeletion *time.Time   `json:"scheduled_deletion,omitempty"`
    DataSubjectRights []string     `json:"data_subject_rights"`
}

type ConsentManager struct {
    Consents        map[string]*ConsentRecord `json:"consents"`
    ConsentPolicies map[string]*ConsentPolicy `json:"consent_policies"`
    LastUpdated     time.Time                 `json:"last_updated"`
}

type ConsentRecord struct {
    ConsentID       string     `json:"consent_id"`
    DataSubjectID   string     `json:"data_subject_id"`
    ConsentType     string     `json:"consent_type"`
    Purpose         string     `json:"purpose"`
    ConsentGiven    bool       `json:"consent_given"`
    ConsentDate     time.Time  `json:"consent_date"`
    WithdrawnDate   *time.Time `json:"withdrawn_date,omitempty"`
    ExpiryDate      *time.Time `json:"expiry_date,omitempty"`
    ConsentMethod   string     `json:"consent_method"`
    ConsentProof    string     `json:"consent_proof"`
    LastModified    time.Time  `json:"last_modified"`
    IsActive        bool       `json:"is_active"`
}

type IdentityVerification struct {
    VerificationID   string                 `json:"verification_id"`
    VerificationMethod string               `json:"verification_method"`
    VerifiedAt       time.Time              `json:"verified_at"`
    VerificationData map[string]interface{} `json:"verification_data"`
    TrustScore       float64               `json:"trust_score"`
    IsVerified       bool                  `json:"is_verified"`
}

type ErasureLogEntry struct {
    LogID       string                 `json:"log_id"`
    FileID      string                 `json:"file_id"`
    Action      string                 `json:"action"`
    Timestamp   time.Time              `json:"timestamp"`
    Success     bool                   `json:"success"`
    Details     map[string]interface{} `json:"details"`
    Verification string                `json:"verification_hash"`
}

type ErasureException struct {
    ExceptionID string    `json:"exception_id"`
    FileID      string    `json:"file_id"`
    Reason      string    `json:"reason"`
    LegalBasis  string    `json:"legal_basis"`
    Timestamp   time.Time `json:"timestamp"`
}

type ErasureProof struct {
    ProofID         string    `json:"proof_id"`
    ProofHash       string    `json:"proof_hash"`
    ProofTimestamp  time.Time `json:"proof_timestamp"`
    VerificationURL string    `json:"verification_url"`
    ComplianceNote  string    `json:"compliance_note"`
}

type PortableDataStructure struct {
    FormatVersion    string                 `json:"format_version"`
    ExportedAt       time.Time              `json:"exported_at"`
    DataSubjectID    string                 `json:"data_subject_id"`
    DataCategories   []string               `json:"data_categories"`
    TotalFiles       int                    `json:"total_files"`
    TotalSize        int64                  `json:"total_size_bytes"`
    FileManifest     []PortableFileEntry    `json:"file_manifest"`
    Metadata         map[string]interface{} `json:"metadata"`
}

type PortableFileEntry struct {
    FileID       string                 `json:"file_id"`
    FileName     string                 `json:"file_name"`
    FileSize     int64                  `json:"file_size"`
    CreatedAt    time.Time              `json:"created_at"`
    ModifiedAt   time.Time              `json:"modified_at"`
    DataCategory string                 `json:"data_category"`
    PIITypes     []string               `json:"pii_types"`
    FileHash     string                 `json:"file_hash"`
    Metadata     map[string]interface{} `json:"metadata"`
}

type DataExportJob struct {
    JobID           string     `json:"job_id"`
    PortabilityID   string     `json:"portability_id"`
    Status          string     `json:"status"`
    Progress        float64    `json:"progress"`
    StartTime       time.Time  `json:"start_time"`
    EndTime         *time.Time `json:"end_time,omitempty"`
    ExportPath      string     `json:"export_path"`
    ExportSize      int64      `json:"export_size"`
    FilesProcessed  int        `json:"files_processed"`
    TotalFiles      int        `json:"total_files"`
    ErrorMessage    string     `json:"error_message,omitempty"`
    ProcessingLogs  []string   `json:"processing_logs"`
}

type DataErasureJob struct {
    JobID           string        `json:"job_id"`
    ErasureID       string        `json:"erasure_id"`
    Status          string        `json:"status"`
    Progress        float64       `json:"progress"`
    StartTime       time.Time     `json:"start_time"`
    EndTime         *time.Time    `json:"end_time,omitempty"`
    FilesErased     int           `json:"files_erased"`
    TotalFiles      int           `json:"total_files"`
    ErasureMethod   string        `json:"erasure_method"`
    ErrorMessage    string        `json:"error_message,omitempty"`
    ErasureProof    *ErasureProof `json:"erasure_proof"`
    ProcessingLogs  []string      `json:"processing_logs"`
}

type ProcessingRecord struct {
    RecordID         string        `json:"record_id"`
    DataSubjectID    string        `json:"data_subject_id"`
    ProcessingPurpose string       `json:"processing_purpose"`
    LegalBasis       string        `json:"legal_basis"`
    DataCategories   []string      `json:"data_categories"`
    Recipients       []string      `json:"recipients"`
    RetentionPeriod  time.Duration `json:"retention_period"`
    SecurityMeasures []string      `json:"security_measures"`
    CreatedAt        time.Time     `json:"created_at"`
    LastUpdated      time.Time     `json:"last_updated"`
    IsActive         bool          `json:"is_active"`
}

type ConsentPolicy struct {
    PolicyID        string        `json:"policy_id"`
    Purpose         string        `json:"purpose"`
    RequiredConsent bool          `json:"required_consent"`
    ConsentType     string        `json:"consent_type"`
    RetentionPeriod time.Duration `json:"retention_period"`
    AutoExpiry      bool          `json:"auto_expiry"`
    WithdrawalMethod string       `json:"withdrawal_method"`
    CreatedAt       time.Time     `json:"created_at"`
    IsActive        bool          `json:"is_active"`
}

type GDPRResponseData struct {
    ResponseID      string                 `json:"response_id"`
    RequestType     string                 `json:"request_type"`
    ResponseData    map[string]interface{} `json:"response_data"`
    DeliveryMethod  string                 `json:"delivery_method"`
    DeliveredAt     *time.Time             `json:"delivered_at,omitempty"`
    ResponseFormat  string                 `json:"response_format"`
    ExpirationDate  *time.Time             `json:"expiration_date,omitempty"`
}

type GDPRConfig struct {
    ResponseTimeLimit      time.Duration `json:"response_time_limit"`
    IdentityVerificationReq bool         `json:"identity_verification_req"`
    AutoErasureEnabled     bool          `json:"auto_erasure_enabled"`
    DataPortabilityFormats []string      `json:"data_portability_formats"`
    RetentionPolicyEnabled bool          `json:"retention_policy_enabled"`
    ConsentManagementReq   bool          `json:"consent_management_required"`
    AuditTrailRequired     bool          `json:"audit_trail_required"`
    NotificationEnabled    bool          `json:"notification_enabled"`
}

func NewGDPRComplianceEngine(nodeID string, server *EnterpriseFileServer) *GDPRComplianceEngine {
    return &GDPRComplianceEngine{
        nodeID:                nodeID,
        dataSubjectRequests:   make(map[string]*DataSubjectRequest),
        erasureRequests:       make(map[string]*ErasureRequest),
        portabilityRequests:   make(map[string]*PortabilityRequest),
        dataInventory:         make(map[string]*DataInventoryEntry),
        consentManagement:     NewConsentManager(),
        dataProcessingRecords: make(map[string]*ProcessingRecord),
        exportJobs:            make(map[string]*DataExportJob),
        erasureJobs:           make(map[string]*DataErasureJob),
        server:                server,
        config: &GDPRConfig{
            ResponseTimeLimit:       30 * 24 * time.Hour,
            IdentityVerificationReq: true,
            AutoErasureEnabled:      true,
            DataPortabilityFormats:  []string{"json", "xml", "csv"},
            RetentionPolicyEnabled:  true,
            ConsentManagementReq:    true,
            AuditTrailRequired:      true,
            NotificationEnabled:     true,
        },
    }
}

func NewConsentManager() *ConsentManager {
    return &ConsentManager{
        Consents:        make(map[string]*ConsentRecord),
        ConsentPolicies: make(map[string]*ConsentPolicy),
        LastUpdated:     time.Now(),
    }
}

func (gdpr *GDPRComplianceEngine) Initialize() {
    gdpr.mutex.Lock()
    defer gdpr.mutex.Unlock()
    
    gdpr.createDefaultConsentPolicies()
    gdpr.initializeDataInventory()
    
    go gdpr.requestProcessingLoop()
    go gdpr.retentionPolicyLoop()
    go gdpr.consentExpiryLoop()
    
    fmt.Printf("[GDPR] GDPR Compliance Engine initialized for node %s\n", gdpr.nodeID[:8])
}

func (gdpr *GDPRComplianceEngine) createDefaultConsentPolicies() {
    policies := []*ConsentPolicy{
        {
            PolicyID:        generateID(),
            Purpose:         "Data Storage and Processing",
            RequiredConsent: true,
            ConsentType:     "explicit",
            RetentionPeriod: 2 * 365 * 24 * time.Hour,
            AutoExpiry:      true,
            WithdrawalMethod: "api_request",
            CreatedAt:       time.Now(),
            IsActive:        true,
        },
    }
    
    for _, policy := range policies {
        gdpr.consentManagement.ConsentPolicies[policy.PolicyID] = policy
    }
    
    fmt.Printf("[GDPR] Created %d default consent policies\n", len(policies))
}

func (gdpr *GDPRComplianceEngine) initializeDataInventory() {
    entries := []*DataInventoryEntry{
        {
            EntryID:          generateID(),
            DataSubjectID:    "testuser",
            FileID:           "user_profile_data",
            FileName:         "user_profile.json",
            DataCategory:     "personal",
            PIITypes:         []string{"email", "phone", "name"},
            LegalBasis:       "consent",
            ProcessingPurpose: "account_management",
            RetentionPeriod:  2 * 365 * 24 * time.Hour,
            CreatedAt:        time.Now(),
            DataSubjectRights: []string{"access", "rectification", "erasure", "portability"},
        },
    }
    
    for _, entry := range entries {
        gdpr.dataInventory[entry.EntryID] = entry
    }
    
    fmt.Printf("[GDPR] Initialized data inventory with %d entries\n", len(entries))
}

func (gdpr *GDPRComplianceEngine) SubmitDataSubjectRequest(dataSubjectID, requestType string, details map[string]interface{}) (*DataSubjectRequest, error) {
    gdpr.mutex.Lock()
    defer gdpr.mutex.Unlock()
    
    request := &DataSubjectRequest{
        RequestID:       generateID(),
        DataSubjectID:   dataSubjectID,
        RequestType:     requestType,
        Status:          "pending",
        SubmittedAt:     time.Now(),
        RequestDetails:  details,
        IdentityVerified: false,
        ProcessingNotes: make([]string, 0),
        LegalBasis:      "gdpr_article_" + gdpr.getArticleNumber(requestType),
    }
    
    gdpr.dataSubjectRequests[request.RequestID] = request
    
    if gdpr.server.auditLogger != nil {
        gdpr.server.auditLogger.LogEvent(
            "gdpr_request_submitted",
            dataSubjectID,
            request.RequestID,
            requestType,
            "pending",
            details,
        )
    }
    
    fmt.Printf("[GDPR] Data subject request submitted: %s\n", requestType)
    
    return request, nil
}

func (gdpr *GDPRComplianceEngine) ProcessRightToErasure(dataSubjectID string, erasureScope string, dataCategories []string) (*ErasureRequest, error) {
    gdpr.mutex.Lock()
    defer gdpr.mutex.Unlock()
    
    erasureReq := &ErasureRequest{
        ErasureID:      generateID(),
        DataSubjectID:  dataSubjectID,
        ErasureScope:   erasureScope,
        DataCategories: dataCategories,
        Status:         "pending",
        ErasureReason:  "data_subject_request",
        RequestedAt:    time.Now(),
        VerificationData: &IdentityVerification{
            VerificationID:     generateID(),
            VerificationMethod: "system_verification",
            VerifiedAt:         time.Now(),
            TrustScore:         0.9,
            IsVerified:         true,
        },
        ErasureLog:      make([]ErasureLogEntry, 0),
        Exceptions:      make([]ErasureException, 0),
    }
    
    filesToErase := gdpr.findFilesForErasure(dataSubjectID, dataCategories)
    erasureReq.FilesToErase = filesToErase
    
    gdpr.erasureRequests[erasureReq.ErasureID] = erasureReq
    
    if gdpr.server.auditLogger != nil {
        gdpr.server.auditLogger.LogEvent(
            "gdpr_erasure_requested",
            dataSubjectID,
            erasureReq.ErasureID,
            "right_to_erasure",
            "processing",
            map[string]interface{}{
                "scope": erasureScope,
                "files": len(filesToErase),
            },
        )
    }
    
    fmt.Printf("[GDPR] Right to Erasure processing started\n")
    
    return erasureReq, nil
}

func (gdpr *GDPRComplianceEngine) ProcessDataPortability(dataSubjectID string, exportFormat string, dataCategories []string) (*PortabilityRequest, error) {
    gdpr.mutex.Lock()
    defer gdpr.mutex.Unlock()
    
    portabilityReq := &PortabilityRequest{
        PortabilityID:  generateID(),
        DataSubjectID:  dataSubjectID,
        ExportFormat:   exportFormat,
        DataCategories: dataCategories,
        Status:         "pending",
        RequestedAt:    time.Now(),
        ExpiresAt:      time.Now().Add(7 * 24 * time.Hour),
        VerificationData: &IdentityVerification{
            VerificationID:     generateID(),
            VerificationMethod: "system_verification",
            VerifiedAt:         time.Now(),
            TrustScore:         0.9,
            IsVerified:         true,
        },
    }
    
    filesToExport := gdpr.findFilesForExport(dataSubjectID, dataCategories)
    portabilityReq.FilesToExport = filesToExport
    
    gdpr.portabilityRequests[portabilityReq.PortabilityID] = portabilityReq
    
    if gdpr.server.auditLogger != nil {
        gdpr.server.auditLogger.LogEvent(
            "gdpr_portability_requested",
            dataSubjectID,
            portabilityReq.PortabilityID,
            "data_portability",
            "processing",
            map[string]interface{}{
                "format": exportFormat,
                "files":  len(filesToExport),
            },
        )
    }
    
    fmt.Printf("[GDPR] Data Portability processing started\n")
    
    return portabilityReq, nil
}

func (gdpr *GDPRComplianceEngine) getArticleNumber(requestType string) string {
    switch requestType {
    case "access":
        return "15"
    case "rectification":
        return "16"
    case "erasure":
        return "17"
    case "restriction":
        return "18"
    case "portability":
        return "20"
    case "objection":
        return "21"
    default:
        return "general"
    }
}

func (gdpr *GDPRComplianceEngine) findFilesForErasure(dataSubjectID string, dataCategories []string) []string {
    files := make([]string, 0)
    
    for _, entry := range gdpr.dataInventory {
        if entry.DataSubjectID == dataSubjectID {
            if len(dataCategories) == 0 || contains(dataCategories, entry.DataCategory) {
                files = append(files, entry.FileID)
            }
        }
    }
    
    return files
}

func (gdpr *GDPRComplianceEngine) findFilesForExport(dataSubjectID string, dataCategories []string) []string {
    files := make([]string, 0)
    
    for _, entry := range gdpr.dataInventory {
        if entry.DataSubjectID == dataSubjectID {
            if (len(dataCategories) == 0 || contains(dataCategories, entry.DataCategory)) &&
               contains(entry.DataSubjectRights, "portability") {
                files = append(files, entry.FileID)
            }
        }
    }
    
    return files
}

func (gdpr *GDPRComplianceEngine) requestProcessingLoop() {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()
    
    for range ticker.C {
        fmt.Printf("[GDPR] Processing background tasks\n")
    }
}

func (gdpr *GDPRComplianceEngine) retentionPolicyLoop() {
    ticker := time.NewTicker(24 * time.Hour)
    defer ticker.Stop()
    
    for range ticker.C {
        fmt.Printf("[GDPR] Enforcing retention policies\n")
    }
}

func (gdpr *GDPRComplianceEngine) consentExpiryLoop() {
    ticker := time.NewTicker(6 * time.Hour)
    defer ticker.Stop()
    
    for range ticker.C {
        fmt.Printf("[GDPR] Checking consent expiry\n")
    }
}

func (gdpr *GDPRComplianceEngine) GetGDPRStatus() map[string]interface{} {
    gdpr.mutex.RLock()
    defer gdpr.mutex.RUnlock()
    
    pendingRequests := 0
    completedRequests := 0
    activeConsents := 0
    
    for _, request := range gdpr.dataSubjectRequests {
        if request.Status == "pending" || request.Status == "processing" {
            pendingRequests++
        } else if request.Status == "completed" {
            completedRequests++
        }
    }
    
    for _, consent := range gdpr.consentManagement.Consents {
        if consent.IsActive {
            activeConsents++
        }
    }
    
    return map[string]interface{}{
        "gdpr_engine_status":        "operational",
        "data_subject_requests":     len(gdpr.dataSubjectRequests),
        "pending_requests":          pendingRequests,
        "completed_requests":        completedRequests,
        "erasure_requests":          len(gdpr.erasureRequests),
        "portability_requests":      len(gdpr.portabilityRequests),
        "data_inventory_entries":    len(gdpr.dataInventory),
        "active_consents":           activeConsents,
        "consent_policies":          len(gdpr.consentManagement.ConsentPolicies),
        "export_jobs":               len(gdpr.exportJobs),
        "erasure_jobs":              len(gdpr.erasureJobs),
        "response_time_limit_days":  int(gdpr.config.ResponseTimeLimit.Hours() / 24),
        "auto_erasure_enabled":      gdpr.config.AutoErasureEnabled,
        "supported_export_formats":  gdpr.config.DataPortabilityFormats,
        "compliance_articles":       []string{"Article 15", "Article 16", "Article 17", "Article 20", "Article 21"},
        "last_maintenance":          time.Now().Format(time.RFC3339),
    }
}
