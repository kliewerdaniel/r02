/*
 * QASP Go SDK v1.0
 *
 * Go SDK for QASP (QuantumSecureAPI Protocol) v1.0 handshake operations.
 * Implements cross-language interoperable handshake using canonical JSON format.
 *
 * Features:
 * - QASP handshake initiation and completion
 * - Canonical JSON serialization for cross-language compatibility
 * - Support for multiple PQC algorithms (Kyber, Dilithium)
 * - Session token management
 * - Concurrent-safe session handling
 */

package qasp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// PQC algorithm constants (matching server implementation)
const (
	// KEM Algorithms
	KEMKyber512  = "Kyber512"
	KEMKyber768  = "Kyber768"
	KEMKyber1024 = "Kyber1024"

	// Signature Algorithms
	SigDilithium2 = "Dilithium2"
	SigDilithium3 = "Dilithium3"
	SigDilithium5 = "Dilithium5"
)

// QASPError represents errors from QASP operations
type QASPError struct {
	Message string
	Code    string
}

func (e QASPError) Error() string {
	return fmt.Sprintf("QASP error [%s]: %s", e.Code, e.Message)
}

// QASPClient represents a QASP client instance
type QASPClient struct {
	serverURL  string
	clientID   string
	tenantID   string
	kemAlg     string
	sigAlg     string
	httpClient *http.Client

	// Session state (protected by mutex)
	mu           sync.RWMutex
	sessionToken string
	serverPubKey string
	sharedSecret []byte
}

// QASPClientOptions configures a QASP client
type QASPClientOptions struct {
	ServerURL string        // QASP server URL (e.g., "https://qasp.example.com:8000")
	ClientID  string        // Unique client identifier
	TenantID  string        // Tenant identifier (default: "default")
	KEMAlg    string        // KEM algorithm (default: Kyber512)
	SigAlg    string        // Signature algorithm (default: Dilithium3)
	Timeout   time.Duration // HTTP timeout (default: 30s)
}

// NewQASPClient creates a new QASP client instance
func NewQASPClient(opts QASPClientOptions) (*QASPClient, error) {
	if opts.ServerURL == "" {
		return nil, QASPError{Message: "ServerURL is required", Code: "CONFIG_ERROR"}
	}
	if opts.ClientID == "" {
		return nil, QASPError{Message: "ClientID is required", Code: "CONFIG_ERROR"}
	}

	tenantID := opts.TenantID
	if tenantID == "" {
		tenantID = "default"
	}

	kemAlg := opts.KEMAlg
	if kemAlg == "" {
		kemAlg = KEMKyber512
	}

	sigAlg := opts.SigAlg
	if sigAlg == "" {
		sigAlg = SigDilithium3
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Set to true for development only
			},
		},
	}

	return &QASPClient{
		serverURL:  strings.TrimRight(opts.ServerURL, "/"),
		clientID:   opts.ClientID,
		tenantID:   tenantID,
		kemAlg:     kemAlg,
		sigAlg:     sigAlg,
		httpClient: httpClient,
	}, nil
}

// HandshakeInit represents the initial handshake message
type HandshakeInit struct {
	QASPVersion string `json:"qasp_version"`
	Type        string `json:"type"`
	ClientID    string `json:"client_id"`
	TenantID    string `json:"tenant_id"`
	KEMAlg      string `json:"kem_alg"`
	SigAlg      string `json:"sig_alg"`
	Timestamp   int64  `json:"timestamp"`
	ClientNonce string `json:"client_nonce"`
}

// HandshakeResponse represents the server response to handshake init
type HandshakeResponse struct {
	SessionID       string `json:"session_id"`
	ServerPublicKey string `json:"server_public_key"`
	Challenge       string `json:"challenge"`
}

// InitHandshake initializes a QASP handshake with the server
func (c *QASPClient) InitHandshake() (*HandshakeResponse, error) {
	clientNonce, err := generateNonce(16)
	if err != nil {
		return nil, QASPError{Message: "Failed to generate nonce", Code: "CRYPTO_ERROR"}
	}

	initMsg := HandshakeInit{
		QASPVersion: "v1.0",
		Type:        "handshake_init",
		ClientID:    c.clientID,
		TenantID:    c.tenantID,
		KEMAlg:      c.kemAlg,
		SigAlg:      c.sigAlg,
		Timestamp:   time.Now().UnixMilli(),
		ClientNonce: base64.StdEncoding.EncodeToString(clientNonce),
	}

	canonicalJSON, err := canonicalJSONMarshal(initMsg)
	if err != nil {
		return nil, QASPError{Message: "Failed to marshal handshake init", Code: "JSON_ERROR"}
	}

	resp, err := c.makeRequest("POST", "/qasp/init", canonicalJSON, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, QASPError{
			Message: fmt.Sprintf("Handshake init failed: %s", string(body)),
			Code:    "HANDSHAKE_ERROR",
		}
	}

	var handshakeResp HandshakeResponse
	if err := json.NewDecoder(resp.Body).Decode(&handshakeResp); err != nil {
		return nil, QASPError{Message: "Failed to decode handshake response", Code: "JSON_ERROR"}
	}

	// Store server public key
	c.mu.Lock()
	c.serverPubKey = handshakeResp.ServerPublicKey
	c.mu.Unlock()

	return &handshakeResp, nil
}

// HandshakeComplete represents the handshake completion message
type HandshakeComplete struct {
	QASPVersion    string `json:"qasp_version"`
	Type           string `json:"type"`
	ClientID       string `json:"client_id"`
	TenantID       string `json:"tenant_id"`
	SessionID      string `json:"session_id"`
	ClientPublicKey string `json:"client_public_key"`
	ClientSignature string `json:"client_signature"`
	Timestamp      int64  `json:"timestamp"`
}

// CompleteHandshake completes the QASP handshake with server challenges
func (c *QASPClient) CompleteHandshake(serverResp *HandshakeResponse) error {
	// Generate client key pair (placeholder - replace with actual PQC implementation)
	clientKeys, err := c.generateClientKeys()
	if err != nil {
		return QASPError{Message: "Failed to generate client keys", Code: "CRYPTO_ERROR"}
	}

	completeMsg := HandshakeComplete{
		QASPVersion:     "v1.0",
		Type:            "handshake_complete",
		ClientID:        c.clientID,
		TenantID:        c.tenantID,
		SessionID:       serverResp.SessionID,
		ClientPublicKey: clientKeys.publicKey,
		ClientSignature: clientKeys.signature,
		Timestamp:       time.Now().UnixMilli(),
	}

	canonicalJSON, err := canonicalJSONMarshal(completeMsg)
	if err != nil {
		return QASPError{Message: "Failed to marshal handshake complete", Code: "JSON_ERROR"}
	}

	resp, err := c.makeRequest("POST", "/qasp/complete", canonicalJSON, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return QASPError{
			Message: fmt.Sprintf("Handshake complete failed: %s", string(body)),
			Code:    "HANDSHAKE_ERROR",
		}
	}

	var result struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return QASPError{Message: "Failed to decode handshake result", Code: "JSON_ERROR"}
	}

	// Store session token and derive shared secret
	c.mu.Lock()
	c.sessionToken = result.SessionToken
	c.sharedSecret = c.deriveSharedSecret(result)
	c.mu.Unlock()

	return nil
}

// MakeAuthenticatedRequest makes an authenticated request to a protected endpoint
func (c *QASPClient) MakeAuthenticatedRequest(endpoint string, data interface{}) (interface{}, error) {
	c.mu.RLock()
	sessionToken := c.sessionToken
	sharedSecret := c.sharedSecret
	c.mu.RUnlock()

	if sessionToken == "" {
		return nil, QASPError{Message: "No active session. Complete handshake first.", Code: "AUTH_ERROR"}
	}

	requestData := map[string]interface{}{
		"client_id":  c.clientID,
		"tenant_id":  c.tenantID,
		"timestamp":  time.Now().UnixMilli(),
		"nonce":      generateRandomHex(16),
	}

	// Merge additional data
	if data != nil {
		if dataMap, ok := data.(map[string]interface{}); ok {
			for k, v := range dataMap {
				requestData[k] = v
			}
		}
	}

	canonicalJSON, err := canonicalJSONMarshal(requestData)
	if err != nil {
		return nil, QASPError{Message: "Failed to marshal request", Code: "JSON_ERROR"}
	}

	// Sign request
	signature := c.signRequest(sharedSecret, canonicalJSON)

	headers := map[string]string{
		"Content-Type":     "application/json",
		"Authorization":    "Bearer " + sessionToken,
		"X-QASP-Signature": signature,
		"User-Agent":       "QASP-GO-SDK/1.0",
	}

	resp, err := c.makeRequest("POST", endpoint, canonicalJSON, headers)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, QASPError{
			Message: fmt.Sprintf("Request failed: %s", string(body)),
			Code:    "REQUEST_ERROR",
		}
	}

	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, QASPError{Message: "Failed to decode response", Code: "JSON_ERROR"}
	}

	return result, nil
}

// EndSession ends the current session
func (c *QASPClient) EndSession() error {
	_, err := c.MakeAuthenticatedRequest("/qasp/end", map[string]interface{}{
		"type": "session_end",
	})

	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear session state regardless of cleanup request success
	c.sessionToken = ""
	c.serverPubKey = ""
	c.sharedSecret = nil

	return err // Return error if cleanup request failed, but session is still cleared
}

// GetSessionToken returns the current session token (thread-safe)
func (c *QASPClient) GetSessionToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionToken
}

// IsAuthenticated returns whether the client has an active session
func (c *QASPClient) IsAuthenticated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionToken != ""
}

// canonicalJSONMarshal creates canonical JSON representation for cross-language interoperability
func canonicalJSONMarshal(v interface{}) ([]byte, error) {
	// Create a sorted map for canonical serialization
	var canonicalMap map[string]interface{}

	// Convert input to map if needed
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(jsonBytes, &canonicalMap); err != nil {
		return nil, err
	}

	// Create canonical JSON with sorted keys and no extra whitespace
	buffer := &bytes.Buffer{}
	buffer.WriteByte('{')

	keys := make([]string, 0, len(canonicalMap))
	for k := range canonicalMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, k := range keys {
		if i > 0 {
			buffer.WriteByte(',')
		}

		// Write key
		keyBytes, _ := json.Marshal(k)
		buffer.Write(keyBytes)
		buffer.WriteByte(':')

		// Write value
		valBytes, _ := json.Marshal(canonicalMap[k])
		buffer.Write(valBytes)
	}

	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}

// generateNonce generates a random nonce of specified length
func generateNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)
	_, err := rand.Read(nonce)
	return nonce, err
}

// generateRandomHex generates a random hexadecimal string
func generateRandomHex(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

// clientKeys represents generated client key pair
type clientKeys struct {
	publicKey string
	signature string
}

// generateClientKeys generates client key pair (placeholder - replace with actual PQC implementation)
func (c *QASPClient) generateClientKeys() (*clientKeys, error) {
	// Placeholder implementation - in real use, integrate with go-pqc or similar
	publicKeyBytes, err := generateNonce(32)
	if err != nil {
		return nil, err
	}

	signatureBytes, err := generateNonce(64)
	if err != nil {
		return nil, err
	}

	return &clientKeys{
		publicKey: base64.StdEncoding.EncodeToString(publicKeyBytes),
		signature: base64.StdEncoding.EncodeToString(signatureBytes),
	}, nil
}

// deriveSharedSecret derives shared secret from handshake result
func (c *QASPClient) deriveSharedSecret(result struct{ SessionToken string }) []byte {
	secretData := fmt.Sprintf("%s:%s:%d", result.SessionToken, c.clientID, time.Now().Unix())
	hash := sha256.Sum256([]byte(secretData))
	return hash[:]
}

// signRequest signs a request using HMAC-SHA256
func (c *QASPClient) signRequest(sharedSecret []byte, data []byte) string {
	hmac := hmac.New(sha256.New, sharedSecret)
	hmac.Write(data)
	return base64.StdEncoding.EncodeToString(hmac.Sum(nil))
}

// makeRequest performs an HTTP request to the server
func (c *QASPClient) makeRequest(method, path string, body []byte, headers map[string]string) (*http.Response, error) {
	url := c.serverURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "QASP-GO-SDK/1.0")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return c.httpClient.Do(req)
}
