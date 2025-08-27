package main

import (
	"fmt"
	"log"

	"sync"
	"time"
)

// Workflow Management System for Week 29-32
type WorkflowEngine struct {
	workflows    map[string]*Workflow
	instances    map[string]*WorkflowInstance
	templates    map[string]*WorkflowTemplate
	mutex        sync.RWMutex
	server       *EnterpriseFileServer
	eventChannel chan WorkflowEvent
}

// Enums - Define these first
type WorkflowStatus string
type InstanceStatus string
type StepType string
type Priority string
type TriggerType string
type EventType string

const (
	// Workflow Status
	WorkflowActive   WorkflowStatus = "active"
	WorkflowDraft    WorkflowStatus = "draft"
	WorkflowArchived WorkflowStatus = "archived"

	// Instance Status
	InstanceRunning   InstanceStatus = "running"
	InstanceCompleted InstanceStatus = "completed"
	InstanceFailed    InstanceStatus = "failed"
	InstancePaused    InstanceStatus = "paused"
	InstanceCancelled InstanceStatus = "cancelled"

	// Step Types
	StepManual    StepType = "manual"
	StepAutomated StepType = "automated"
	StepApproval  StepType = "approval"
	// StepCondition  StepType = "condition"
	StepDocument    StepType = "document"
	StepEmail       StepType = "email"
	StepIntegration StepType = "integration"

	// Priority
	PriorityLow      Priority = "low"
	PriorityMedium   Priority = "medium"
	PriorityHigh     Priority = "high"
	PriorityCritical Priority = "critical"

	// Trigger Types
	TriggerManual   TriggerType = "manual"
	TriggerSchedule TriggerType = "schedule"
	TriggerDocument TriggerType = "document"
	TriggerEmail    TriggerType = "email"
	TriggerWebhook  TriggerType = "webhook"

	// Event Types
	EventStarted   EventType = "started"
	EventCompleted EventType = "completed"
	EventFailed    EventType = "failed"
	EventAssigned  EventType = "assigned"
	EventApproved  EventType = "approved"
	EventRejected  EventType = "rejected"
	EventCommented EventType = "commented"
)

// Supporting structs
type StepCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

type StepAssignment struct {
	UserID   string `json:"user_id"`
	Role     string `json:"role"`
	Required bool   `json:"required"`
}

type TriggerCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

type RetryPolicy struct {
	MaxRetries int           `json:"max_retries"`
	Delay      time.Duration `json:"delay"`
	Backoff    string        `json:"backoff"`
}

// Main workflow structs
type Workflow struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Steps       []WorkflowStep         `json:"steps"`
	Triggers    []WorkflowTrigger      `json:"triggers"`
	Variables   map[string]interface{} `json:"variables"`
	Status      WorkflowStatus         `json:"status"`
	CreatedBy   string                 `json:"created_by"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Category    string                 `json:"category"`
	Tags        []string               `json:"tags"`
}

type WorkflowStep struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         StepType               `json:"type"`
	Action       string                 `json:"action"`
	Conditions   []StepCondition        `json:"conditions"`
	Assignments  []StepAssignment       `json:"assignments"`
	DueDate      *time.Time             `json:"due_date,omitempty"`
	Priority     Priority               `json:"priority"`
	Dependencies []string               `json:"dependencies"`
	Parallel     bool                   `json:"parallel"`
	RetryPolicy  *RetryPolicy           `json:"retry_policy,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type WorkflowInstance struct {
	ID             string                 `json:"id"`
	WorkflowID     string                 `json:"workflow_id"`
	Status         InstanceStatus         `json:"status"`
	CurrentStep    string                 `json:"current_step"`
	CompletedSteps []string               `json:"completed_steps"`
	Variables      map[string]interface{} `json:"variables"`
	StartedAt      time.Time              `json:"started_at"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty"`
	StartedBy      string                 `json:"started_by"`
	AssignedUsers  []string               `json:"assigned_users"`
	History        []WorkflowEvent        `json:"history"`
	DocumentRefs   []string               `json:"document_refs"`
}

type WorkflowTemplate struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Industry    string    `json:"industry"`
	UseCase     string    `json:"use_case"`
	Template    *Workflow `json:"template"`
	CreatedAt   time.Time `json:"created_at"`
}

type WorkflowEvent struct {
	ID          string                 `json:"id"`
	InstanceID  string                 `json:"instance_id"`
	StepID      string                 `json:"step_id"`
	Type        EventType              `json:"type"`
	Description string                 `json:"description"`
	UserID      string                 `json:"user_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Data        map[string]interface{} `json:"data"`
}

type WorkflowTrigger struct {
	Type       TriggerType            `json:"type"`
	Event      string                 `json:"event"`
	Conditions []TriggerCondition     `json:"conditions"`
	Enabled    bool                   `json:"enabled"`
	Config     map[string]interface{} `json:"config"`
}

func NewWorkflowEngine(server *EnterpriseFileServer) *WorkflowEngine {
	we := &WorkflowEngine{
		workflows:    make(map[string]*Workflow),
		instances:    make(map[string]*WorkflowInstance),
		templates:    make(map[string]*WorkflowTemplate),
		server:       server,
		eventChannel: make(chan WorkflowEvent, 100),
	}

	// Initialize default templates
	we.initializeDefaultTemplates()

	// Start event processor
	go we.processEvents()

	return we
}

func (we *WorkflowEngine) initializeDefaultTemplates() {
	// Document Review Template
	documentReviewTemplate := &WorkflowTemplate{
		ID:          "template-doc-review",
		Name:        "Document Review & Approval",
		Category:    "document-management",
		Description: "Standard document review and approval workflow",
		Industry:    "general",
		UseCase:     "document-approval",
		CreatedAt:   time.Now(),
		Template: &Workflow{
			ID:          "doc-review-template",
			Name:        "Document Review & Approval",
			Description: "Multi-stage document review with approval gates",
			Steps: []WorkflowStep{
				{
					ID:       "step-1",
					Name:     "Initial Review",
					Type:     StepManual,
					Action:   "review-document",
					Priority: PriorityMedium,
					Assignments: []StepAssignment{
						{Role: "reviewer", Required: true},
					},
				},
				{
					ID:           "step-2",
					Name:         "Management Approval",
					Type:         StepApproval,
					Action:       "approve-document",
					Priority:     PriorityHigh,
					Dependencies: []string{"step-1"},
					Assignments: []StepAssignment{
						{Role: "manager", Required: true},
					},
				},
			},
			Status:    WorkflowActive,
			CreatedAt: time.Now(),
		},
	}

	we.templates[documentReviewTemplate.ID] = documentReviewTemplate

	log.Printf("📋 Initialized %d workflow templates", len(we.templates))
}

func (we *WorkflowEngine) CreateWorkflow(workflow *Workflow) error {
	we.mutex.Lock()
	defer we.mutex.Unlock()

	workflow.ID = fmt.Sprintf("wf-%d", time.Now().Unix())
	workflow.CreatedAt = time.Now()
	workflow.UpdatedAt = time.Now()
	workflow.Status = WorkflowDraft

	we.workflows[workflow.ID] = workflow

	log.Printf("📋 Created workflow: %s (%s)", workflow.Name, workflow.ID)
	return nil
}

func (we *WorkflowEngine) StartWorkflow(workflowID, userID string, variables map[string]interface{}) (*WorkflowInstance, error) {
	we.mutex.RLock()
	workflow, exists := we.workflows[workflowID]
	we.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("workflow %s not found", workflowID)
	}

	instance := &WorkflowInstance{
		ID:             fmt.Sprintf("wi-%d", time.Now().Unix()),
		WorkflowID:     workflowID,
		Status:         InstanceRunning,
		Variables:      variables,
		StartedAt:      time.Now(),
		StartedBy:      userID,
		AssignedUsers:  []string{userID},
		History:        []WorkflowEvent{},
		DocumentRefs:   []string{},
		CompletedSteps: []string{},
	}

	// Find first step
	if len(workflow.Steps) > 0 {
		instance.CurrentStep = workflow.Steps[0].ID
	}

	we.mutex.Lock()
	we.instances[instance.ID] = instance
	we.mutex.Unlock()

	log.Printf("🚀 Started workflow instance: %s for workflow: %s", instance.ID, workflowID)
	return instance, nil
}

func (we *WorkflowEngine) GetWorkflowStatus() map[string]interface{} {
	we.mutex.RLock()
	defer we.mutex.RUnlock()

	return map[string]interface{}{
		"status":              "operational",
		"total_workflows":     len(we.workflows),
		"total_instances":     len(we.instances),
		"available_templates": len(we.templates),
		"last_activity":       time.Now(),
	}
}

func (we *WorkflowEngine) GetTemplates() []*WorkflowTemplate {
	we.mutex.RLock()
	defer we.mutex.RUnlock()

	templates := make([]*WorkflowTemplate, 0, len(we.templates))
	for _, template := range we.templates {
		templates = append(templates, template)
	}
	return templates
}

func (we *WorkflowEngine) processEvents() {
	for event := range we.eventChannel {
		log.Printf("📨 Processing workflow event: %s", event.Type)

		// Audit logging
		if we.server.auditLogger != nil {
			we.server.auditLogger.LogEvent(
				"workflow_event",
				event.UserID,
				event.InstanceID,
				string(event.Type),
				"success",
				map[string]interface{}{
					"event_id": event.ID,
					"step_id":  event.StepID,
					"data":     event.Data,
				},
			)
		}
	}
}

// API Handlers
