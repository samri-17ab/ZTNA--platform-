package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Policy acts as a high-level representation of rules managed in the UI
// that eventually get compiled into Rego files for OPA.
type Policy struct {
	ID          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Name        string    `gorm:"uniqueIndex;not null" json:"name"`
	Description string    `json:"description"`

	// The core logic (could be stored as raw JSON criteria or a Rego string)
	Condition string `gorm:"not null" json:"condition"`
	Action    string `gorm:"not null" json:"action"` // e.g. 'ALLOW_VLAN_10', 'DENY'

	IsActive bool `gorm:"default:true" json:"is_active"`
	Priority int  `gorm:"default:100" json:"priority"` // Evaluation order if dealing with conflicting rules

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BeforeCreate hook
func (p *Policy) BeforeCreate(tx *gorm.DB) (err error) {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return
}
