package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// Login routes credentials to Keycloak (IdP) for token generation
func Login(c *fiber.Ctx) error {
	type LoginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	req := new(LoginRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		keycloakURL = "http://keycloak:8080"
	}

	// For a fresh Keycloak dev server, we use the default master realm and admin-cli client.
	// In production, this would point to a dedicated 'ztna' realm and securely defined client_ids.
	tokenEndpoint := keycloakURL + "/realms/master/protocol/openid-connect/token"

	data := url.Values{}
	data.Set("client_id", "admin-cli")
	data.Set("username", req.Username)
	data.Set("password", req.Password)
	data.Set("grant_type", "password")

	resp, err := http.Post(tokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "Identity Provider unreachable"})
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read IdP response"})
	}

	if resp.StatusCode != http.StatusOK {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials or IdP rejection"})
	}

	// Parse the actual OAuth2 token response
	var tokenData map[string]interface{}
	if err := json.Unmarshal(body, &tokenData); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to parse IdP token"})
	}

	return c.JSON(tokenData)
}
