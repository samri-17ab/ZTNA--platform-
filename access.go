package handlers

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ztna-platform/api/models"
	"github.com/ztna-platform/api/services"
)

// EvaluateAccessRequest is the payload sent by Radius or the Switch
type EvaluateAccessRequest struct {
	MACAddress string `json:"mac_address"`
	SwitchIP   string `json:"switch_ip"`
	Port       string `json:"port"`
	Username   string `json:"username"` // Extracted from 802.1X
}

// EvaluateAccess is the core Module 5 Engine
func EvaluateAccess(c *fiber.Ctx) error {
	req := new(EvaluateAccessRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "bad request"})
	}

	// 1. Gather Context
	// Query DB for User Role and Department based on the incoming Username.
	var user map[string]string
	if services.DB != nil {
		var dbUser models.User
		if result := services.DB.Where("email = ? OR full_name = ?", req.Username, req.Username).First(&dbUser); result.Error == nil {
			user = map[string]string{
				"role":       dbUser.Role,
				"department": dbUser.Department,
			}
		}
	}
	
	// Fallback/Default if user not found
	if user == nil {
		user = map[string]string{
			"role":       "Guest",
			"department": "None",
		}
	}

	// Query DB for real device risk based on MAC Address
	var riskScore int = 100 // Default to max risk
	var postureStatus string = "Untrusted"
	if services.DB != nil {
		var dbDevice models.Device
		if result := services.DB.Where("mac_address = ?", req.MACAddress).First(&dbDevice); result.Error == nil {
			riskScore = dbDevice.LastRiskScore
			postureStatus = dbDevice.PostureStatus
		}
	}

	// Add environmental context (Time, Location)
	hour := time.Now().Hour()
	location := "US"
	if req.SwitchIP == "192.168.100.1" {
		location = "Internal"
	}

	contextData := map[string]interface{}{
		"user": user,
		"device": map[string]interface{}{
			"risk":    riskScore,
			"posture": postureStatus,
			"mac":     req.MACAddress,
		},
		"network": map[string]string{
			"switch": req.SwitchIP,
		},
		"context": map[string]interface{}{
			"time_of_day": hour,
			"location":    location,
		},
	}

	// 2. Call Open Policy Agent (Module 5)
	decision, err := services.QueryOPA(contextData)
	if err != nil {
		log.Printf("OPA Error: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "policy engine failure"})
	}

	// 3. Return Action to Enforcement Module (Module 6)
	// 'ALLOW_VLAN_10', 'RESTRICT_VLAN_99', 'DENY'
	return c.JSON(fiber.Map{
		"decision": decision.Action,
		"reason":   decision.Reason,
		"mac":      req.MACAddress,
	})
}
