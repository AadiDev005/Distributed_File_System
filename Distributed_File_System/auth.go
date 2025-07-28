package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type UserRole int

const (
	RoleUser UserRole = iota
	RoleAdmin
	RoleSuperAdmin
)

type User struct {
	ID           string
	Username     string
	Email        string
	PasswordHash string
	Role         UserRole
	CreatedAt    time.Time
	LastLoginAt  time.Time
	IsActive     bool
}

type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type AuthManager struct {
	users    map[string]*User
	sessions map[string]*Session
	mutex    sync.RWMutex
}

func NewAuthManager() *AuthManager {
	return &AuthManager{
		users:    make(map[string]*User),
		sessions: make(map[string]*Session),
	}
}

func (am *AuthManager) CreateUser(username, password string, role UserRole) (*User, error) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Check if user exists
	for _, user := range am.users {
		if user.Username == username {
			return nil, errors.New("user already exists")
		}
	}

	userID := generateID()
	passwordHash := am.hashPassword(password)

	user := &User{
		ID:           userID,
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now(),
		IsActive:     true,
	}

	am.users[userID] = user
	return user, nil
}

func (am *AuthManager) Login(username, password string) (*Session, error) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	var user *User
	for _, u := range am.users {
		if u.Username == username && u.IsActive {
			user = u
			break
		}
	}

	if user == nil {
		return nil, errors.New("invalid credentials")
	}

	if !am.verifyPassword(password, user.PasswordHash) {
		return nil, errors.New("invalid credentials")
	}

	sessionID := generateID()
	session := &Session{
		ID:        sessionID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(8 * time.Hour), // 8-hour sessions
		CreatedAt: time.Now(),
	}

	am.sessions[sessionID] = session
	user.LastLoginAt = time.Now()

	return session, nil
}

func (am *AuthManager) ValidateSession(sessionID string) (*User, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	session, exists := am.sessions[sessionID]
	if !exists || time.Now().After(session.ExpiresAt) {
		return nil, errors.New("invalid or expired session")
	}

	user, exists := am.users[session.UserID]
	if !exists || !user.IsActive {
		return nil, errors.New("user not found or inactive")
	}

	return user, nil
}

func (am *AuthManager) Logout(sessionID string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	delete(am.sessions, sessionID)
	return nil
}

func (am *AuthManager) hashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

func (am *AuthManager) verifyPassword(password, hash string) bool {
	return am.hashPassword(password) == hash
}

func (am *AuthManager) GetUser(userID string) (*User, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	user, exists := am.users[userID]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user, nil
}
