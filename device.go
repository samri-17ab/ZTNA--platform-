package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Device represents a physical endpoint trying to access the network (laptop, IoT, etc.)
type Device struct {
	ID         uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	MACAddress string     `gorm:"uniqueIndex;not null" json:"mac_address"` // e.g., '00:1A:2B:3C:4D:5E'
	OwnerID    *uuid.UUID `gorm:"type:uuid;index" json:"owner_id"`         // Nullable (e.g. IoT devices rarely have "owners")
	DeviceType string     `gorm:"not null" json:"device_type"`             // 'Laptop', 'Mobile', 'Printer', 'IoT'

	// Posture & Compliance Status (Module 2 & 3)
	LastRiskScore int       `gorm:"default:100" json:"last_risk_score"`        // 0 = Perfect, 100 = Unknown/Untrusted
	PostureStatus string    `gorm:"default:'Untrusted'" json:"posture_status"` // 'Compliant', 'Non-Compliant', 'Untrusted'
	OSVersion     string    `json:"os_version"`
	LastSeenAt    time.Time `json:"last_seen_at"`

	// Lifecycle
	ExpiresAt *time.Time `json:"expires_at"` // Useful for bringing in BYOD/Contractors temporarily
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`

	// Associations
	Owner User `gorm:"foreignKey:OwnerID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;" json:"owner,omitempty"`
}

// BeforeCreate hook
func (d *Device) BeforeCreate(tx *gorm.DB) (err error) {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	return
}
