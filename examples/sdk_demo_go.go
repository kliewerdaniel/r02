/*
 * QASP Go SDK Demo
 *
 * This example demonstrates how to use the QASP Go SDK to:
 * 1. Initialize and complete a QASP handshake
 * 2. Make authenticated requests to protected endpoints
 * 3. Handle session management
 */

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	qasp "github.com/kliewerdaniel/r02/sdk/go/qasp-sdk"
)

func main() {
	// Configuration
	serverURL := getEnvOrDefault("QASP_SERVER_URL", "http://localhost:8000")
	clientID := getEnvOrDefault("CLIENT_ID", "demo-client-go")

	fmt.Println("🚀 QASP Go SDK Demo")
	fmt.Println("===================")

	// Create QASP client
	fmt.Println("\n📡 Creating QASP client...")
	client, err := qasp.NewQASPClient(qasp.QASPClientOptions{
		ServerURL: serverURL,
		ClientID:  clientID,
		TenantID:  "demo",
		KEMAlg:    qasp.KEMKyber512,
		SigAlg:    qasp.SigDilithium3,
		Timeout:   30 * time.Second,
	})
	if err != nil {
		log.Fatalf("❌ Failed to create client: %v", err)
	}
	fmt.Printf("✓ Client created for server: %s\n", serverURL)

	// Step 1: Initialize handshake
	fmt.Println("\n🔐 Initializing handshake...")
	initResponse, err := client.InitHandshake()
	if err != nil {
		log.Fatalf("❌ Handshake initialization failed: %v", err)
	}
	fmt.Println("✓ Handshake initialized")
	fmt.Printf("  Session ID: %s\n", initResponse.SessionID)

	// Step 2: Complete handshake
	fmt.Println("\n🔒 Completing handshake...")
	err = client.CompleteHandshake(initResponse)
	if err != nil {
		log.Fatalf("❌ Handshake completion failed: %v", err)
	}
	fmt.Println("✓ Handshake completed")
	sessionToken := client.GetSessionToken()
	fmt.Printf("  Session Token: %s...\n", sessionToken[:min(20, len(sessionToken))])

	// Step 3: Make authenticated request
	fmt.Println("\n📤 Making authenticated request...")
	requestData := map[string]interface{}{
		"action":    "demo_request",
		"timestamp": time.Now().Format(time.RFC3339),
		"data":      map[string]string{"key": "value"},
	}

	response, err := client.MakeAuthenticatedRequest("/api/demo", requestData)
	if err != nil {
		log.Fatalf("❌ Authenticated request failed: %v", err)
	}
	fmt.Println("✓ Authenticated request successful")

	// Pretty print response
	responseJSON, _ := json.MarshalIndent(response, "", "  ")
	fmt.Printf("  Response: %s\n", string(responseJSON))

	// Step 4: End session
	fmt.Println("\n👋 Ending session...")
	err = client.EndSession()
	if err != nil {
		fmt.Printf("⚠️  Session cleanup warning: %v\n", err)
	} else {
		fmt.Println("✓ Session ended")
	}

	fmt.Println("\n🎉 Demo completed successfully!")
}

// Helper functions

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RunDemo function for testing or external calls
func RunDemo() error {
	serverURL := getEnvOrDefault("QASP_SERVER_URL", "http://localhost:8000")
	clientID := getEnvOrDefault("CLIENT_ID", "demo-client-go")

	client, err := qasp.NewQASPClient(qasp.QASPClientOptions{
		ServerURL: serverURL,
		ClientID:  clientID,
		TenantID:  "demo",
		KEMAlg:    qasp.KEMKyber512,
		SigAlg:    qasp.SigDilithium3,
		Timeout:   30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Initialize handshake
	initResponse, err := client.InitHandshake()
	if err != nil {
		return fmt.Errorf("handshake initialization failed: %w", err)
	}

	// Complete handshake
	err = client.CompleteHandshake(initResponse)
	if err != nil {
		return fmt.Errorf("handshake completion failed: %w", err)
	}

	// Make test request
	requestData := map[string]interface{}{
		"action": "demo_request",
		"data":   map[string]string{"test": "value"},
	}

	_, err = client.MakeAuthenticatedRequest("/api/demo", requestData)
	if err != nil {
		return fmt.Errorf("authenticated request failed: %w", err)
	}

	// End session
	client.EndSession()

	return nil
}
