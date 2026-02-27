package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuditLog captures every access decision made by the system (Module 8)
type AuditLog struct {
	ID        uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	EventType string    `gorm:"index;not null" json:"event_type"` // 'auth_success', 'auth_reject', 'posture_degraded', 'quarantine'

	// Context at time of event
	MACAddress string     `gorm:"index;not null" json:"mac_address"`
	UserID     *uuid.UUID `gorm:"type:uuid;index" json:"user_id"`
	SwitchIP   string     `json:"switch_ip"`

	// Decision
	RiskScore   int    `json:"risk_score"`
	ActionTaken string `json:"action_taken"` // e.g. 'RESTRICT_VLAN_99'
	Reason      string `json:"reason"`

	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// BeforeCreate hook
func (a *AuditLog) BeforeCreate(tx *gorm.DB) (err error) {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return
}
