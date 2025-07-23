package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// AuthManager handles authentication
type AuthManager struct {
	logger        *logging.Logger
	jwtSecret     []byte
	tokenExpiry   time.Duration
	refreshExpiry time.Duration
	users         map[string]*User
	sessions      map[string]*Session
	mu            sync.RWMutex
}

// User represents a system user
type User struct {
	ID           string                 `json:"id"`
	Username     string                 `json:"username"`
	Email        string                 `json:"email"`
	PasswordHash string                 `json:"-"`
	Roles        []string               `json:"roles"`
	Enabled      bool                   `json:"enabled"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Session represents an active user session
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastAccess   time.Time `json:"last_access"`
}

// Claims represents JWT claims
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(logger *logging.Logger, jwtSecret string) *AuthManager {
	secret := []byte(jwtSecret)
	if len(secret) == 0 {
		// Generate random secret if not provided
		secret = make([]byte, 32)
		rand.Read(secret)
		logger.Warn("No JWT secret provided, using randomly generated secret")
	}

	am := &AuthManager{
		logger:        logger,
		jwtSecret:     secret,
		tokenExpiry:   15 * time.Minute,
		refreshExpiry: 7 * 24 * time.Hour,
		users:         make(map[string]*User),
		sessions:      make(map[string]*Session),
	}

	// Create default admin user
	am.createDefaultUsers()

	// Start session cleanup
	go am.cleanupSessions()

	return am
}

// Authenticate validates credentials and returns a token
func (am *AuthManager) Authenticate(ctx context.Context, req *framework.AuthenticationRequest) (*framework.AuthenticationResponse, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Extract credentials based on method
	var username, password string
	switch req.Method {
	case "password":
		username, _ = req.Credentials["username"].(string)
		password, _ = req.Credentials["password"].(string)
	default:
		return nil, fmt.Errorf("unsupported authentication method: %s", req.Method)
	}

	// Find user
	var user *User
	for _, u := range am.users {
		if u.Username == username {
			user = u
			break
		}
	}

	if user == nil {
		return &framework.AuthenticationResponse{
			Success: false,
		}, nil
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return &framework.AuthenticationResponse{
			Success: false,
		}, nil
	}

	// Check if user is enabled
	if !user.Enabled {
		return &framework.AuthenticationResponse{
			Success: false,
		}, nil
	}

	// Generate tokens
	token, expiresAt, err := am.generateToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	refreshToken := am.generateRefreshToken()

	// Create session
	session := &Session{
		ID:           generateID(),
		UserID:       user.ID,
		Token:        token,
		RefreshToken: refreshToken,
		CreatedAt:    time.Now(),
		ExpiresAt:    expiresAt,
		LastAccess:   time.Now(),
	}

	am.sessions[session.ID] = session

	return &framework.AuthenticationResponse{
		Success:   true,
		Token:     token,
		ExpiresAt: expiresAt,
		UserInfo: map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"roles":    user.Roles,
		},
	}, nil
}

// RefreshToken refreshes an authentication token
func (am *AuthManager) RefreshToken(ctx context.Context, req *framework.RefreshTokenRequest) (*framework.RefreshTokenResponse, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Find session by refresh token
	var session *Session
	for _, s := range am.sessions {
		if s.RefreshToken == req.Token {
			session = s
			break
		}
	}

	if session == nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Check if session is expired
	if time.Now().After(session.CreatedAt.Add(am.refreshExpiry)) {
		delete(am.sessions, session.ID)
		return nil, fmt.Errorf("refresh token expired")
	}

	// Get user
	user := am.users[session.UserID]
	if user == nil || !user.Enabled {
		delete(am.sessions, session.ID)
		return nil, fmt.Errorf("user not found or disabled")
	}

	// Generate new token
	token, expiresAt, err := am.generateToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Update session
	session.Token = token
	session.ExpiresAt = expiresAt
	session.LastAccess = time.Now()

	return &framework.RefreshTokenResponse{
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// RevokeToken revokes an authentication token
func (am *AuthManager) RevokeToken(ctx context.Context, req *framework.RevokeTokenRequest) (*framework.RevokeTokenResponse, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Find and remove session
	for id, session := range am.sessions {
		if session.Token == req.Token {
			delete(am.sessions, id)
			return &framework.RevokeTokenResponse{
				Success: true,
				Message: "token revoked",
			}, nil
		}
	}

	return &framework.RevokeTokenResponse{
		Success: false,
		Message: "token not found",
	}, nil
}

// ValidateToken validates a JWT token
func (am *AuthManager) ValidateToken(token string) (*Claims, error) {
	claims := &Claims{}
	
	jwtToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return am.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !jwtToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// GetUser retrieves user information
func (am *AuthManager) GetUser(ctx context.Context, req *framework.GetUserRequest) (*framework.GetUserResponse, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	user, exists := am.users[req.UserID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	return &framework.GetUserResponse{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Roles:    user.Roles,
		Metadata: user.Metadata,
	}, nil
}

// CreateUser creates a new user
func (am *AuthManager) CreateUser(username, email, password string, roles []string) (*User, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Check if username already exists
	for _, u := range am.users {
		if u.Username == username {
			return nil, fmt.Errorf("username already exists")
		}
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &User{
		ID:           generateID(),
		Username:     username,
		Email:        email,
		PasswordHash: string(hash),
		Roles:        roles,
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	am.users[user.ID] = user
	am.logger.Info("User created", "username", username, "roles", roles)

	return user, nil
}

// UpdateUserRoles updates a user's roles
func (am *AuthManager) UpdateUserRoles(userID string, roles []string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, exists := am.users[userID]
	if !exists {
		return fmt.Errorf("user not found")
	}

	user.Roles = roles
	user.UpdatedAt = time.Now()

	am.logger.Info("User roles updated", "user_id", userID, "roles", roles)
	return nil
}

// DisableUser disables a user account
func (am *AuthManager) DisableUser(userID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, exists := am.users[userID]
	if !exists {
		return fmt.Errorf("user not found")
	}

	user.Enabled = false
	user.UpdatedAt = time.Now()

	// Revoke all user sessions
	for id, session := range am.sessions {
		if session.UserID == userID {
			delete(am.sessions, id)
		}
	}

	am.logger.Info("User disabled", "user_id", userID)
	return nil
}

// Helper methods

func (am *AuthManager) generateToken(user *User) (string, time.Time, error) {
	expiresAt := time.Now().Add(am.tokenExpiry)
	
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Roles:    user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "afdp-policy-framework",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(am.jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}

func (am *AuthManager) generateRefreshToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (am *AuthManager) createDefaultUsers() {
	// Create admin user
	adminPassword := "admin123" // In production, this would be from secure config
	am.CreateUser("admin", "admin@afdp.local", adminPassword, []string{"admin", "user"})

	// Create service account
	am.CreateUser("service", "service@afdp.local", generatePassword(), []string{"service"})
}

func (am *AuthManager) cleanupSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		am.mu.Lock()
		now := time.Now()
		for id, session := range am.sessions {
			if now.After(session.ExpiresAt) {
				delete(am.sessions, id)
			}
		}
		am.mu.Unlock()
	}
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generatePassword() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}