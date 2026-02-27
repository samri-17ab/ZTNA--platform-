package handlers

import (
	"log"

	"github.com/gofiber/fiber/v2"
)

type NetworkEvent struct {
	EventType string `json:"event_type"` // e.g. 'auth_success', 'posture_change'
	SourceIP  string `json:"source_ip"`
	MAC       string `json:"mac"`
	Details   string `json:"details"`
}

// IngestNetworkEvent (Module 7 & 8)
func IngestNetworkEvent(c *fiber.Ctx) error {
	var event NetworkEvent
	if err := c.BodyParser(&event); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid event"})
	}

	// Pushing event to Redis Streams or Kafka for continuous monitoring analysis
	log.Printf("Network Event Logged: [%s] %s -> %s", event.EventType, event.MAC, event.Details)

	// In production, we also stream this directly to ELK via stdout JSON parsing or direct API
	return c.Status(202).JSON(fiber.Map{"status": "ingested"})
}
