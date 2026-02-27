package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents an identity synced from Keycloak or local auth
type User struct {
	ID         uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Email      string    `gorm:"uniqueIndex;not null" json:"email"`
	FullName   string    `gorm:"not null" json:"full_name"`
	Department string    `json:"department"`
	Role       string    `gorm:"default:'Standard'" json:"role"` // Standard, Dev, Admin, SecOps, Guest
	Status     string    `gorm:"default:'Active'" json:"status"` // Active, Suspended
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	// Associations
	Devices []Device `gorm:"foreignKey:OwnerID" json:"devices,omitempty"`
}

// BeforeCreate hook for UUID generation
func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return
}
