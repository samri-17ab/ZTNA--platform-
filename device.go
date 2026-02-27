package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ztna-platform/api/models"
	"github.com/ztna-platform/api/services"
)

// DevicePosturePayload represents the telemetry sent by the Rust/Osquery agent
type DevicePosturePayload struct {
	MACAddress    string `json:"mac_address"`
	OSVersion     string `json:"os_version"`
	PatchLevel    string `json:"patch_level"` // "up_to_date", "critical_missing"
	FirewallOn    bool   `json:"firewall_on"`
	DiskEncrypted bool   `json:"disk_encrypted"`
	LastAVScan    string `json:"last_av_scan"`
}

// ReportPosture receives the payload and updates the Risk Score
func ReportPosture(c *fiber.Ctx) error {
	payload := new(DevicePosturePayload)
	if err := c.BodyParser(payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "bad payload"})
	}

	// Module 3: Dynamic Risk Scoring Evaluation
	riskScore := calculateRiskScore(payload)

	// Module 7: Continuous Monitoring trigger
	if riskScore > 80 {
		triggerRemediation(payload.MACAddress)
	}

	return c.JSON(fiber.Map{
		"message":               "Posture received",
		"mac":                   payload.MACAddress,
		"calculated_risk_score": riskScore,
	})
}

// calculateRiskScore - Heuristic evaluation
func calculateRiskScore(d *DevicePosturePayload) int {
	score := 0
	if !d.FirewallOn {
		score += 50
	}
	if !d.DiskEncrypted {
		score += 30
	}
	if d.OSVersion == "outdated" {
		score += 20
	}
	if d.PatchLevel == "critical_missing" {
		score += 40
	}
	return score // 0 is perfect, >80 is high risk/untrusted
}

func triggerRemediation(mac string) {
	// In production, this publishes to Kafka or Redis Streams
	// which then tells FreeRADIUS to send a Disconnect-Request (PoD)
	// For this platform, we enforce NAC Quarantining via the persistent DB state
	
	if services.DB == nil {
		return
	}

	var device models.Device
	if result := services.DB.Where("mac_address = ?", mac).First(&device); result.Error == nil {
		// Device found, update posture strategy to Quarantine
		device.PostureStatus = "Quarantined"
		services.DB.Save(&device)
	}
}

func GetDeviceRisk(c *fiber.Ctx) error {
	mac := c.Params("mac")
	return c.JSON(fiber.Map{"mac": mac, "risk_score": 0, "status": "Compliant"})
}

// RegisterDevice handles registering a new device to the network
func RegisterDevice(c *fiber.Ctx) error {
	type DeviceInput struct {
		MACAddress string `json:"mac_address"`
		DeviceType string `json:"device_type"`
		OwnerName  string `json:"owner_name"` // Simulating owner just for display
	}

	input := new(DeviceInput)
	if err := c.BodyParser(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Module 3: Simulated Risk Profiling
	// Instead of defaulting to 100, analyze the device type
	simulatedRisk := 50 // Default for unknown/IoT
	status := "Untrusted"

	switch input.DeviceType {
	case "Laptop":
		simulatedRisk = 10
		status = "Compliant"
	case "Mobile":
		simulatedRisk = 20
		status = "Compliant"
	case "Server":
		simulatedRisk = 5
		status = "Compliant"
	case "IoT":
		simulatedRisk = 75
		status = "Non-Compliant"
	}

	// In a real database we wouldn't just create an owner string, we'd link to user
	device := models.Device{
		MACAddress:    input.MACAddress,
		DeviceType:    input.DeviceType,
		LastRiskScore: simulatedRisk,
		PostureStatus: status,
		LastSeenAt:    time.Now(),
	}

	// If the DB is configured, save it
	if services.DB != nil {
		if result := services.DB.Create(&device); result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": result.Error.Error()})
		}
	}

	// We return the simulated owner name directly for UI purposes here just to help the frontend
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Device registered successfully",
		"device": fiber.Map{
			"id":             device.ID,
			"mac_address":    device.MACAddress,
			"device_type":    device.DeviceType,
			"owner":          input.OwnerName,
			"risk_score":     device.LastRiskScore,
			"posture_status": device.PostureStatus,
		},
	})
}

// ListDevices returns all devices registered on the network
func ListDevices(c *fiber.Ctx) error {
	var devices []models.Device

	if services.DB != nil {
		services.DB.Find(&devices)
	}

	// Format response to match frontend expectations
	response := []fiber.Map{}
	for _, d := range devices {
		response = append(response, fiber.Map{
			"mac":      d.MACAddress,
			"type":     d.DeviceType,
			"risk":     d.LastRiskScore,
			"status":   d.PostureStatus,
			"lastSeen": d.LastSeenAt.Format("15:04:05"),
			// Mock owner since we don't have deep relational loading implemented yet
			"owner": "Local User",
		})
	}

	return c.JSON(response)
}

// UpdateDevice handles editing an existing device
func UpdateDevice(c *fiber.Ctx) error {
	mac := c.Params("mac")

	type DeviceUpdate struct {
		OwnerName     string `json:"owner_name"`
		DeviceType    string `json:"device_type"`
		RiskScore     int    `json:"risk_score"`
		PostureStatus string `json:"posture_status"`
	}

	input := new(DeviceUpdate)
	if err := c.BodyParser(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	if services.DB == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database not initialized"})
	}

	var device models.Device
	if result := services.DB.Where("mac_address = ?", mac).First(&device); result.Error != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Device not found"})
	}

	// Update mutable fields (mocking owner update by just leaving the relationship out for now)
	device.DeviceType = input.DeviceType
	device.LastRiskScore = input.RiskScore
	device.PostureStatus = input.PostureStatus

	if result := services.DB.Save(&device); result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update device"})
	}

	return c.JSON(fiber.Map{
		"message": "Device updated successfully",
		"device": fiber.Map{
			"mac":      device.MACAddress,
			"type":     device.DeviceType,
			"risk":     device.LastRiskScore,
			"status":   device.PostureStatus,
			"owner":    input.OwnerName,
		},
	})
}
