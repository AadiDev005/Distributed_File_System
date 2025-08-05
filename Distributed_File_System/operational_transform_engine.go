package main

import (
	"fmt"
	"sync"
	"time"
)

// Operation represents a single document operation
type Operation struct {
	Type      string    `json:"type"` // "insert", "delete", "retain"
	Position  int       `json:"position"`
	Content   string    `json:"content,omitempty"`
	Length    int       `json:"length,omitempty"`
	Author    string    `json:"author"`
	Timestamp time.Time `json:"timestamp"`
	Version   int       `json:"version"`
	ID        string    `json:"id"`
}

// OperationTransform handles conflict resolution
type OperationTransform struct {
	mutex sync.RWMutex
}

// Transform two concurrent operations using Operational Transform algorithm
func (ot *OperationTransform) Transform(op1, op2 Operation) (Operation, Operation) {
	ot.mutex.Lock()
	defer ot.mutex.Unlock()

	transformed1, transformed2 := op1, op2

	switch {
	case op1.Type == "insert" && op2.Type == "insert":
		if op1.Position <= op2.Position {
			transformed2.Position += len(op1.Content)
		} else {
			transformed1.Position += len(op2.Content)
		}

	case op1.Type == "delete" && op2.Type == "insert":
		if op1.Position < op2.Position {
			transformed2.Position -= op1.Length
		} else if op1.Position >= op2.Position {
			transformed1.Position += len(op2.Content)
		}

	case op1.Type == "insert" && op2.Type == "delete":
		if op2.Position < op1.Position {
			transformed1.Position -= op2.Length
		} else if op2.Position >= op1.Position {
			transformed2.Position += len(op1.Content)
		}

	case op1.Type == "delete" && op2.Type == "delete":
		if op1.Position < op2.Position {
			transformed2.Position -= op1.Length
		} else if op2.Position < op1.Position {
			transformed1.Position -= op2.Length
		} else {
			// Overlapping deletes - merge them
			if op1.Position == op2.Position {
				transformed1.Length = maxInt(op1.Length, op2.Length)
				transformed2.Length = 0 // Nullify second operation
			}
		}
	}

	return transformed1, transformed2
}

// ApplyOperation applies an operation to document content
func (ot *OperationTransform) ApplyOperation(content string, op Operation) (string, error) {
	switch op.Type {
	case "insert":
		if op.Position < 0 || op.Position > len(content) {
			return content, fmt.Errorf("invalid insert position: %d", op.Position)
		}
		return content[:op.Position] + op.Content + content[op.Position:], nil

	case "delete":
		if op.Position < 0 || op.Position >= len(content) {
			return content, fmt.Errorf("invalid delete position: %d", op.Position)
		}
		end := op.Position + op.Length
		if end > len(content) {
			end = len(content)
		}
		return content[:op.Position] + content[end:], nil

	case "retain":
		return content, nil // No change for retain operations

	default:
		return content, fmt.Errorf("unknown operation type: %s", op.Type)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
