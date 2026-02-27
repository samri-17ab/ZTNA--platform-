package main

import (
	"bytes"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"
)

// DevicePosturePayload mimics what an osquery/Rust agent would send
type DevicePosturePayload struct {
	MACAddress    string `json:"mac_address"`
	OSVersion     string `json:"os_version"`
	FirewallOn    bool   `json:"firewall_on"`
	DiskEncrypted bool   `json:"disk_encrypted"`
	LastAVScan    string `json:"last_av_scan"`
}

func main() {
	apiEndpoint := os.Getenv("API_ENDPOINT")
	if apiEndpoint == "" {
		apiEndpoint = "http://api:8000/api/v1/devices/posture"
	}
	macAddress := os.Getenv("MAC_ADDRESS")
	if macAddress == "" {
		macAddress = "00:1A:2B:3C:4D:5E" // standard test MAC
	}

	log.Printf("Starting ZTNA Posture Agent for MAC: %s", macAddress)
	log.Printf("Target API: %s", apiEndpoint)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sendPosture(apiEndpoint, macAddress)
		}
	}
}

func sendPosture(endpoint, mac string) {
	// Simulate varying posture health
	firewallOn := rand.Float32() > 0.2 // 80% chance firewall is on
	payload := DevicePosturePayload{
		MACAddress:    mac,
		OSVersion:     "Windows 11 Pro",
		FirewallOn:    firewallOn,
		DiskEncrypted: true,
		LastAVScan:    time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshaling payload: %v", err)
		return
	}

	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to report posture: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		log.Printf("Successfully reported posture. FirewallOn: %v", firewallOn)
	} else {
		log.Printf("API returned non-200 status: %d", resp.StatusCode)
	}
}
