package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ztna-platform/api/models"
	"github.com/ztna-platform/api/services"
)

// CreatePolicy for Admin Dashboard
func CreatePolicy(c *fiber.Ctx) error {
	type PolicyInput struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Condition   string `json:"condition"`
		Action      string `json:"action"`
		Priority    int    `json:"priority"`
	}

	input := new(PolicyInput)
	if err := c.BodyParser(input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}

	policy := models.Policy{
		Name:        input.Name,
		Description: input.Description,
		Condition:   input.Condition,
		Action:      input.Action,
		IsActive:    true,
		Priority:    input.Priority,
	}

	// Save to DB
	if services.DB != nil {
		if result := services.DB.Create(&policy); result.Error != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": result.Error.Error()})
		}
	}

	return c.Status(201).JSON(policy)
}

// ListPolicies returns all active policies
func ListPolicies(c *fiber.Ctx) error {
	var policies []models.Policy

	if services.DB != nil {
		services.DB.Order("priority asc").Find(&policies)
	}

	return c.JSON(policies)
}

// UpdatePolicy handles modifying an existing access rule
func UpdatePolicy(c *fiber.Ctx) error {
	id := c.Params("id")

	type PolicyUpdate struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Condition   string `json:"condition"`
		Action      string `json:"action"`
		Priority    int    `json:"priority"`
		IsActive    bool   `json:"is_active"`
	}

	input := new(PolicyUpdate)
	if err := c.BodyParser(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	if services.DB == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database not initialized"})
	}

	var policy models.Policy
	if result := services.DB.Where("id = ?", id).First(&policy); result.Error != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Policy not found"})
	}

	policy.Name = input.Name
	policy.Description = input.Description
	policy.Condition = input.Condition
	policy.Action = input.Action
	policy.Priority = input.Priority
	policy.IsActive = input.IsActive

	if result := services.DB.Save(&policy); result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update policy"})
	}

	return c.JSON(policy)
}
