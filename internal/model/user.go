package model

import "time"

// User is an authenticated principal. Certs are a shared inventory across all
// users; Role gates whether a user may mutate that inventory.
type User struct {
	ID           int64     `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"` // never serialized
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

// IsAdmin reports whether the user may perform write operations.
func (u *User) IsAdmin() bool { return u.Role == "admin" }

// APIToken is a long-lived bearer credential for automation. Only its hash is
// stored; Plaintext is populated only at creation time, for one-time display.
type APIToken struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"user_id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Plaintext  string     `json:"plaintext,omitempty"`
}
