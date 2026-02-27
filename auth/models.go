package auth

import "time"

type publicUser struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Username      string    `json:"username,omitempty"`
	Name          string    `json:"name"`
	EmailVerified bool      `json:"emailVerified"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type publicSession struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	IPAddress string    `json:"ipAddress,omitempty"`
	UserAgent string    `json:"userAgent,omitempty"`
}

type sessionEnvelope struct {
	Session *publicSession `json:"session"`
	User    *publicUser    `json:"user"`
}

type signUpEmailRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type signInEmailRequest struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	RememberMe    bool   `json:"rememberMe"`
	TwoFactorCode string `json:"twoFactorCode,omitempty"`
}

type okResponse struct {
	Status  string `json:"status"`
	AppName string `json:"appName"`
}
