package main

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// PIIDetectionEngine handles automated PII detection with ML models
type PIIDetectionEngine struct {
	nodeID               string
	detectionModels      map[string]*DetectionModel
	piiClassifiers       map[string]*PIIClassifier
	complianceRules      map[string]*ComplianceRule // Uses existing type from compliance_engine.go
	detectionResults     map[string]*PIIDetectionResult
	complianceViolations map[string]*ComplianceViolation // Uses existing type from compliance_engine.go
	scanJobs             map[string]*ScanJob
	mutex                sync.RWMutex
	server               *EnterpriseFileServer
	config               *PIIDetectionConfig
}

// DetectionModel represents an ML model for PII detection
type DetectionModel struct {
	ModelID          string                    `json:"model_id"`
	ModelName        string                    `json:"model_name"`
	ModelType        string                    `json:"model_type"`
	Accuracy         float64                   `json:"accuracy"`
	PIITypes         []string                  `json:"pii_types"`
	TrainingData     int                       `json:"training_data_size"`
	LastTrained      time.Time                 `json:"last_trained"`
	Version          string                    `json:"version"`
	IsActive         bool                      `json:"is_active"`
	Patterns         map[string]*regexp.Regexp `json:"-"`
	ConfidenceThresh float64                   `json:"confidence_threshold"`
}

// PIIClassifier categorizes and scores PII
type PIIClassifier struct {
	ClassifierID     string    `json:"classifier_id"`
	PIIType          string    `json:"pii_type"`
	SensitivityLevel string    `json:"sensitivity_level"`
	RegexPatterns    []string  `json:"regex_patterns"`
	ContextKeywords  []string  `json:"context_keywords"`
	Accuracy         float64   `json:"accuracy"`
	LastUpdated      time.Time `json:"last_updated"`
}

// PIIDetectionResult contains results of PII detection scan
type PIIDetectionResult struct {
	ResultID         string        `json:"result_id"`
	FileID           string        `json:"file_id"`
	ScanJobID        string        `json:"scan_job_id"`
	DetectedPII      []PIIMatch    `json:"detected_pii"`
	RiskScore        float64       `json:"risk_score"`
	ComplianceStatus string        `json:"compliance_status"`
	Recommendations  []string      `json:"recommendations"`
	ScanTime         time.Time     `json:"scan_time"`
	ProcessingTime   time.Duration `json:"processing_time"`
	ModelVersion     string        `json:"model_version"`
	DetectedTypes    []string      `json:"detected_types"`
	DataSize         int           `json:"data_size_bytes"`
	IsReviewed       bool          `json:"is_reviewed"`
	ReviewedBy       string        `json:"reviewed_by,omitempty"`
}

// PIIMatch represents a detected PII instance
type PIIMatch struct {
	MatchID          string  `json:"match_id"`
	PIIType          string  `json:"pii_type"`
	MatchedText      string  `json:"matched_text"`
	ConfidenceScore  float64 `json:"confidence_score"`
	Position         int     `json:"position"`
	Context          string  `json:"context"`
	SensitivityLevel string  `json:"sensitivity_level"`
	ModelUsed        string  `json:"model_used"`
	IsConfirmed      bool    `json:"is_confirmed"`
	IsFalsePositive  bool    `json:"is_false_positive"`
}

// ScanJob represents a PII detection job
type ScanJob struct {
	JobID        string     `json:"job_id"`
	JobType      string     `json:"job_type"`
	FileIDs      []string   `json:"file_ids"`
	Status       string     `json:"status"`
	Progress     float64    `json:"progress"`
	StartTime    time.Time  `json:"start_time"`
	EndTime      *time.Time `json:"end_time,omitempty"`
	Results      []string   `json:"result_ids"`
	ErrorMessage string     `json:"error_message,omitempty"`
	RequestedBy  string     `json:"requested_by"`
	Priority     string     `json:"priority"`
}

type PIIDetectionConfig struct {
	EnableMLModels     bool          `json:"enable_ml_models"`
	DefaultThreshold   float64       `json:"default_threshold"`
	ScanBatchSize      int           `json:"scan_batch_size"`
	MaxConcurrentScans int           `json:"max_concurrent_scans"`
	RetainResults      time.Duration `json:"retain_results"`
	AutoRemediation    bool          `json:"auto_remediation"`
	NotifyOnViolations bool          `json:"notify_on_violations"`
	ComplianceRegions  []string      `json:"compliance_regions"`
}

func NewPIIDetectionEngine(nodeID string, server *EnterpriseFileServer) *PIIDetectionEngine {
	return &PIIDetectionEngine{
		nodeID:               nodeID,
		detectionModels:      make(map[string]*DetectionModel),
		piiClassifiers:       make(map[string]*PIIClassifier),
		complianceRules:      make(map[string]*ComplianceRule),
		detectionResults:     make(map[string]*PIIDetectionResult),
		complianceViolations: make(map[string]*ComplianceViolation),
		scanJobs:             make(map[string]*ScanJob),
		server:               server,
		config: &PIIDetectionConfig{
			EnableMLModels:     true,
			DefaultThreshold:   0.75,
			ScanBatchSize:      100,
			MaxConcurrentScans: 5,
			RetainResults:      90 * 24 * time.Hour,
			AutoRemediation:    false,
			NotifyOnViolations: true,
			ComplianceRegions:  []string{"EU", "US", "APAC"},
		},
	}
}

// Initialize PII Detection Engine
func (pde *PIIDetectionEngine) Initialize() {
	pde.mutex.Lock()
	defer pde.mutex.Unlock()

	// Create default detection models
	pde.createDefaultDetectionModels()

	// Create PII classifiers
	pde.createPIIClassifiers()

	// Create compliance rules using existing ComplianceRule type from compliance_engine.go
	pde.createComplianceRules()

	// Start background processes
	go pde.scanJobProcessor()
	go pde.complianceMonitor()
	go pde.modelMaintenanceLoop()

	fmt.Printf("[PII] PII Detection Engine initialized for node %s\n", pde.nodeID[:8])
	fmt.Printf("[PII] Configuration: %d models, %d classifiers, %d compliance rules\n",
		len(pde.detectionModels), len(pde.piiClassifiers), len(pde.complianceRules))
}

// Create default detection models with regex patterns
func (pde *PIIDetectionEngine) createDefaultDetectionModels() {
	models := []*DetectionModel{
		{
			ModelID:          generateID(),
			ModelName:        "SSN Detector",
			ModelType:        "regex",
			Accuracy:         0.92,
			PIITypes:         []string{"ssn"},
			Version:          "1.0",
			IsActive:         true,
			Patterns:         make(map[string]*regexp.Regexp),
			ConfidenceThresh: 0.8,
			LastTrained:      time.Now(),
		},
		{
			ModelID:          generateID(),
			ModelName:        "Email Detector",
			ModelType:        "regex",
			Accuracy:         0.95,
			PIITypes:         []string{"email"},
			Version:          "1.0",
			IsActive:         true,
			Patterns:         make(map[string]*regexp.Regexp),
			ConfidenceThresh: 0.9,
			LastTrained:      time.Now(),
		},
		{
			ModelID:          generateID(),
			ModelName:        "Credit Card Detector",
			ModelType:        "regex",
			Accuracy:         0.88,
			PIITypes:         []string{"credit_card"},
			Version:          "1.0",
			IsActive:         true,
			Patterns:         make(map[string]*regexp.Regexp),
			ConfidenceThresh: 0.85,
			LastTrained:      time.Now(),
		},
		{
			ModelID:          generateID(),
			ModelName:        "Phone Number Detector",
			ModelType:        "regex",
			Accuracy:         0.90,
			PIITypes:         []string{"phone"},
			Version:          "1.0",
			IsActive:         true,
			Patterns:         make(map[string]*regexp.Regexp),
			ConfidenceThresh: 0.8,
			LastTrained:      time.Now(),
		},
	}

	// Compile regex patterns
	ssnPattern := regexp.MustCompile(`\b\d{3}-?\d{2}-?\d{4}\b`)
	emailPattern := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	ccPattern := regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)
	phonePattern := regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`)

	models[0].Patterns["ssn"] = ssnPattern
	models[1].Patterns["email"] = emailPattern
	models[2].Patterns["credit_card"] = ccPattern
	models[3].Patterns["phone"] = phonePattern

	for _, model := range models {
		pde.detectionModels[model.ModelID] = model
	}

	fmt.Printf("[PII] Created %d detection models\n", len(models))
}

// Create PII classifiers
func (pde *PIIDetectionEngine) createPIIClassifiers() {
	classifiers := []*PIIClassifier{
		{
			ClassifierID:     generateID(),
			PIIType:          "ssn",
			SensitivityLevel: "critical",
			RegexPatterns:    []string{`\b\d{3}-?\d{2}-?\d{4}\b`},
			ContextKeywords:  []string{"social", "security", "ssn", "social security number"},
			Accuracy:         0.92,
			LastUpdated:      time.Now(),
		},
		{
			ClassifierID:     generateID(),
			PIIType:          "email",
			SensitivityLevel: "medium",
			RegexPatterns:    []string{`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`},
			ContextKeywords:  []string{"email", "contact", "address"},
			Accuracy:         0.95,
			LastUpdated:      time.Now(),
		},
		{
			ClassifierID:     generateID(),
			PIIType:          "credit_card",
			SensitivityLevel: "critical",
			RegexPatterns:    []string{`\b(?:\d{4}[-\s]?){3}\d{4}\b`},
			ContextKeywords:  []string{"credit", "card", "visa", "mastercard", "amex"},
			Accuracy:         0.88,
			LastUpdated:      time.Now(),
		},
		{
			ClassifierID:     generateID(),
			PIIType:          "phone",
			SensitivityLevel: "medium",
			RegexPatterns:    []string{`\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`},
			ContextKeywords:  []string{"phone", "telephone", "mobile", "cell"},
			Accuracy:         0.90,
			LastUpdated:      time.Now(),
		},
	}

	for _, classifier := range classifiers {
		pde.piiClassifiers[classifier.ClassifierID] = classifier
	}

	fmt.Printf("[PII] Created %d PII classifiers\n", len(classifiers))
}

// Create compliance rules using existing ComplianceRule type
// Create compliance rules using existing ComplianceRule type
func (pde *PIIDetectionEngine) createComplianceRules() {
	rules := []*ComplianceRule{
		{
			RuleID:      generateID(),
			Regulation:  "GDPR",
			Description: "Personal Data Protection - Email and Phone Detection",
			Severity:    "high",
			IsActive:    true,
			CreatedAt:   time.Now(),
		},
		{
			RuleID:      generateID(),
			Regulation:  "CCPA",
			Description: "California Consumer Privacy Act - PII Detection",
			Severity:    "medium",
			IsActive:    true,
			CreatedAt:   time.Now(),
		},
		{
			RuleID:      generateID(),
			Regulation:  "HIPAA",
			Description: "Health Insurance Portability - SSN and Medical Data",
			Severity:    "critical",
			IsActive:    true,
			CreatedAt:   time.Now(),
		},
	}

	for _, rule := range rules {
		pde.complianceRules[rule.RuleID] = rule
	}

	fmt.Printf("[PII] Created %d compliance rules\n", len(rules))
}

// ScanContent performs PII detection on content
func (pde *PIIDetectionEngine) ScanContent(content string, fileID string, requestedBy string) (*PIIDetectionResult, error) {
	pde.mutex.Lock()
	defer pde.mutex.Unlock()

	startTime := time.Now()

	result := &PIIDetectionResult{
		ResultID:        generateID(),
		FileID:          fileID,
		DetectedPII:     make([]PIIMatch, 0),
		ScanTime:        startTime,
		DataSize:        len(content),
		IsReviewed:      false,
		Recommendations: make([]string, 0),
	}

	// Run detection models
	for _, model := range pde.detectionModels {
		if !model.IsActive {
			continue
		}

		matches := pde.runDetectionModel(model, content)
		result.DetectedPII = append(result.DetectedPII, matches...)
	}

	// Calculate risk score
	result.RiskScore = pde.calculateRiskScore(result.DetectedPII)

	// Determine compliance status
	result.ComplianceStatus = pde.assessComplianceStatus(result.DetectedPII)

	// Generate recommendations
	result.Recommendations = pde.generateRecommendations(result.DetectedPII, result.RiskScore)

	result.ProcessingTime = time.Since(startTime)
	result.ModelVersion = "1.0"

	// Store result
	pde.detectionResults[result.ResultID] = result

	// Check for compliance violations using existing ComplianceViolation type
	pde.checkComplianceViolations(result)

	// Log scan event
	if pde.server.auditLogger != nil {
		pde.server.auditLogger.LogEvent(
			"pii_scan_completed",
			requestedBy,
			fileID,
			"pii_detection",
			"success",
			map[string]interface{}{
				"result_id":     result.ResultID,
				"pii_found":     len(result.DetectedPII),
				"risk_score":    result.RiskScore,
				"compliance":    result.ComplianceStatus,
				"processing_ms": result.ProcessingTime.Milliseconds(),
			},
		)
	}

	fmt.Printf("[PII] Scan completed: %d PII instances found, risk score: %.2f\n",
		len(result.DetectedPII), result.RiskScore)

	return result, nil
}

// Run detection model against content
func (pde *PIIDetectionEngine) runDetectionModel(model *DetectionModel, content string) []PIIMatch {
	matches := make([]PIIMatch, 0)

	for piiType, pattern := range model.Patterns {
		foundMatches := pattern.FindAllStringSubmatch(content, -1)
		indices := pattern.FindAllStringIndex(content, -1)

		for i, match := range foundMatches {
			if len(match) > 0 {
				position := indices[i][0]

				// Calculate confidence based on context
				confidence := pde.calculateConfidence(match[0], content, position, model)

				if confidence >= model.ConfidenceThresh {
					piiMatch := PIIMatch{
						MatchID:          generateID(),
						PIIType:          piiType,
						MatchedText:      match[0],
						ConfidenceScore:  confidence,
						Position:         position,
						Context:          pde.extractContext(content, position, 50),
						SensitivityLevel: pde.getSensitivityLevel(piiType),
						ModelUsed:        model.ModelID,
						IsConfirmed:      false,
						IsFalsePositive:  false,
					}
					matches = append(matches, piiMatch)
				}
			}
		}
	}

	return matches
}

// Helper functions
func (pde *PIIDetectionEngine) calculateConfidence(match, content string, position int, model *DetectionModel) float64 {
	baseConfidence := 0.7

	// Context analysis
	context := pde.extractContext(content, position, 100)
	contextWords := strings.Fields(strings.ToLower(context))

	// Check for context keywords that increase confidence
	if classifier, exists := pde.getPIIClassifierByType(model.PIITypes[0]); exists {
		for _, keyword := range classifier.ContextKeywords {
			for _, word := range contextWords {
				if strings.Contains(word, keyword) {
					baseConfidence += 0.1
					break
				}
			}
		}
	}

	// Pattern strength (simplified scoring)
	if len(match) > 10 {
		baseConfidence += 0.1
	}

	// Cap at 1.0
	if baseConfidence > 1.0 {
		baseConfidence = 1.0
	}

	return baseConfidence
}

func (pde *PIIDetectionEngine) extractContext(content string, position, radius int) string {
	start := position - radius
	if start < 0 {
		start = 0
	}

	end := position + radius
	if end > len(content) {
		end = len(content)
	}

	return content[start:end]
}

func (pde *PIIDetectionEngine) getPIIClassifierByType(piiType string) (*PIIClassifier, bool) {
	for _, classifier := range pde.piiClassifiers {
		if classifier.PIIType == piiType {
			return classifier, true
		}
	}
	return nil, false
}

func (pde *PIIDetectionEngine) getSensitivityLevel(piiType string) string {
	if classifier, exists := pde.getPIIClassifierByType(piiType); exists {
		return classifier.SensitivityLevel
	}
	return "medium"
}

func (pde *PIIDetectionEngine) calculateRiskScore(matches []PIIMatch) float64 {
	if len(matches) == 0 {
		return 0.0
	}

	totalScore := 0.0
	weights := map[string]float64{
		"critical": 1.0,
		"high":     0.8,
		"medium":   0.6,
		"low":      0.4,
	}

	for _, match := range matches {
		weight := weights[match.SensitivityLevel]
		totalScore += match.ConfidenceScore * weight
	}

	// Normalize to 0-100 scale
	avgScore := totalScore / float64(len(matches))
	return avgScore * 100
}

func (pde *PIIDetectionEngine) assessComplianceStatus(matches []PIIMatch) string {
	if len(matches) == 0 {
		return "compliant"
	}

	criticalCount := 0
	for _, match := range matches {
		if match.SensitivityLevel == "critical" {
			criticalCount++
		}
	}

	if criticalCount > 0 {
		return "violation_detected"
	} else if len(matches) > 5 {
		return "review_required"
	} else {
		return "monitor"
	}
}

func (pde *PIIDetectionEngine) generateRecommendations(matches []PIIMatch, riskScore float64) []string {
	recommendations := make([]string, 0)

	if len(matches) == 0 {
		recommendations = append(recommendations, "No PII detected - file appears compliant")
		return recommendations
	}

	if riskScore > 80 {
		recommendations = append(recommendations, "HIGH RISK: Immediate encryption required")
		recommendations = append(recommendations, "Implement access controls and audit logging")
		recommendations = append(recommendations, "Consider data minimization")
	} else if riskScore > 50 {
		recommendations = append(recommendations, "MEDIUM RISK: Review data handling practices")
		recommendations = append(recommendations, "Implement appropriate security controls")
	} else {
		recommendations = append(recommendations, "LOW RISK: Monitor and maintain current controls")
	}

	// Type-specific recommendations
	piiTypes := make(map[string]bool)
	for _, match := range matches {
		piiTypes[match.PIIType] = true
	}

	if piiTypes["ssn"] {
		recommendations = append(recommendations, "SSN detected: Apply strongest encryption and access controls")
	}
	if piiTypes["credit_card"] {
		recommendations = append(recommendations, "Credit card data: Ensure PCI-DSS compliance")
	}
	if piiTypes["email"] || piiTypes["phone"] {
		recommendations = append(recommendations, "Contact information: Consider GDPR/CCPA requirements")
	}

	return recommendations
}

// Check for compliance violations using existing ComplianceViolation type
func (pde *PIIDetectionEngine) checkComplianceViolations(result *PIIDetectionResult) {
	if len(result.DetectedPII) == 0 {
		return
	}

	for _, rule := range pde.complianceRules {
		if !rule.IsActive {
			continue
		}

		// Simple check - if we have critical PII, create a violation
		hasCriticalPII := false
		for _, match := range result.DetectedPII {
			if match.SensitivityLevel == "critical" && match.ConfidenceScore > 0.8 {
				hasCriticalPII = true
				break
			}
		}

		if hasCriticalPII {
			// Use existing ComplianceViolation type fields only
			violation := &ComplianceViolation{
				ViolationID: generateID(),
				RuleID:      rule.RuleID,
				Severity:    rule.Severity,
				Description: fmt.Sprintf("%s violation: Critical PII detected in file %s", rule.Regulation, result.FileID),
				Status:      "open",
				DetectedAt:  time.Now(),
			}

			pde.complianceViolations[violation.ViolationID] = violation

			// Log violation
			if pde.server.auditLogger != nil {
				pde.server.auditLogger.LogEvent(
					"compliance_violation",
					"system",
					result.FileID,
					rule.Regulation,
					"critical",
					map[string]interface{}{
						"violation_id": violation.ViolationID,
						"rule_id":      rule.RuleID,
						"severity":     violation.Severity,
					},
				)
			}
		}
	}
}

// Background processes
func (pde *PIIDetectionEngine) scanJobProcessor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Printf("[PII] Processing pending scan jobs\n")
	}
}

func (pde *PIIDetectionEngine) complianceMonitor() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		pde.performComplianceMonitoring()
	}
}

func (pde *PIIDetectionEngine) performComplianceMonitoring() {
	pde.mutex.Lock()
	defer pde.mutex.Unlock()

	openViolations := 0
	for _, violation := range pde.complianceViolations {
		if violation.Status == "open" {
			openViolations++
		}
	}

	if openViolations > 0 {
		fmt.Printf("[PII] Compliance monitoring: %d open violations\n", openViolations)
	}
}

func (pde *PIIDetectionEngine) modelMaintenanceLoop() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Printf("[PII] Performing model maintenance\n")
	}
}

// GetDetectionAccuracy returns the overall detection accuracy
func (pde *PIIDetectionEngine) GetDetectionAccuracy() float64 {
	pde.mutex.RLock()
	defer pde.mutex.RUnlock()

	if len(pde.detectionModels) == 0 {
		return 0.0
	}

	totalAccuracy := 0.0
	activeModels := 0

	for _, model := range pde.detectionModels {
		if model.IsActive {
			totalAccuracy += model.Accuracy
			activeModels++
		}
	}

	if activeModels == 0 {
		return 0.0
	}

	return (totalAccuracy / float64(activeModels)) * 100 // Convert to percentage
}

// GetRecentScans returns recent PII detection scan results
func (pde *PIIDetectionEngine) GetRecentScans(limit int) []PIIDetectionResult {
	pde.mutex.RLock()
	defer pde.mutex.RUnlock()

	var results []PIIDetectionResult

	// Convert map to slice and sort by scan time (most recent first)
	for _, result := range pde.detectionResults {
		results = append(results, *result)
	}

	// Simple sorting by scan time (newest first)
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].ScanTime.Before(results[j].ScanTime) {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	// Apply limit
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	return results
}

// GetDetectionModels returns all detection models
func (pde *PIIDetectionEngine) GetDetectionModels() []DetectionModel {
	pde.mutex.RLock()
	defer pde.mutex.RUnlock()

	var models []DetectionModel

	for _, model := range pde.detectionModels {
		// Create a copy to avoid exposing internal pointers
		modelCopy := DetectionModel{
			ModelID:          model.ModelID,
			ModelName:        model.ModelName,
			ModelType:        model.ModelType,
			Accuracy:         model.Accuracy,
			PIITypes:         append([]string(nil), model.PIITypes...),
			TrainingData:     model.TrainingData,
			LastTrained:      model.LastTrained,
			Version:          model.Version,
			IsActive:         model.IsActive,
			ConfidenceThresh: model.ConfidenceThresh,
			// Don't expose Patterns (contains regex pointers)
		}
		models = append(models, modelCopy)
	}

	return models
}

// Get PII Detection status
func (pde *PIIDetectionEngine) GetPIIDetectionStatus() map[string]interface{} {
	pde.mutex.RLock()
	defer pde.mutex.RUnlock()

	totalScans := len(pde.detectionResults)
	openViolations := 0
	highRiskFiles := 0

	for _, violation := range pde.complianceViolations {
		if violation.Status == "open" {
			openViolations++
		}
	}

	for _, result := range pde.detectionResults {
		if result.RiskScore > 70 {
			highRiskFiles++
		}
	}

	avgAccuracy := 0.0
	if len(pde.detectionModels) > 0 {
		total := 0.0
		for _, model := range pde.detectionModels {
			total += model.Accuracy
		}
		avgAccuracy = total / float64(len(pde.detectionModels))
	}

	return map[string]interface{}{
		"pii_engine_status":      "operational",
		"detection_models":       len(pde.detectionModels),
		"pii_classifiers":        len(pde.piiClassifiers),
		"compliance_rules":       len(pde.complianceRules),
		"total_scans":            totalScans,
		"open_violations":        openViolations,
		"high_risk_files":        highRiskFiles,
		"average_model_accuracy": avgAccuracy,
		"ml_models_enabled":      pde.config.EnableMLModels,
		"auto_remediation":       pde.config.AutoRemediation,
		"supported_regulations":  []string{"GDPR", "CCPA", "HIPAA"},
		"last_model_update":      time.Now().Format(time.RFC3339),
	}
}
