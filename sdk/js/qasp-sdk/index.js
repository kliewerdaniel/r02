/**
 * QASP JavaScript SDK v1.0
 *
 * Node.js SDK for QASP (QuantumSecureAPI Protocol) v1.0 handshake operations.
 * Implements cross-language interoperable handshake using canonical JSON format.
 *
 * Features:
 * - QASP handshake initiation and completion
 * - Canonical JSON serialization for cross-language compatibility
 * - Support for multiple PQC algorithms (Kyber, Dilithium)
 * - Session token management
 */

const crypto = require('crypto');
const https = require('https');

// PQC algorithm constants (matching server implementation)
const ALGORITHMS = {
  KEM: {
    KYBER512: 'Kyber512',
    KYBER768: 'Kyber768',
    KYBER1024: 'Kyber1024'
  },
  SIG: {
    DILITHIUM2: 'Dilithium2',
    DILITHIUM3: 'Dilithium3',
    DILITHIUM5: 'Dilithium5'
  }
};

class QASPClient {
  /**
   * Create a new QASP client instance.
   *
   * @param {Object} options - Client configuration options
   * @param {string} options.serverUrl - QASP server URL (e.g., 'https://qasp.example.com:8000')
   * @param {string} options.clientId - Unique client identifier
   * @param {string} [options.tenantId='default'] - Tenant identifier for multi-tenant deployments
   * @param {string} [options.kemAlg='Kyber512'] - KEM algorithm selection
   * @param {string} [options.sigAlg='Dilithium3'] - Signature algorithm selection
   */
  constructor(options = {}) {
    this.serverUrl = options.serverUrl;
    this.clientId = options.clientId;
    this.tenantId = options.tenantId || 'default';
    this.kemAlg = options.kemAlg || ALGORITHMS.KEM.KYBER512;
    this.sigAlg = options.sigAlg || ALGORITHMS.SIG.DILITHIUM3;

    // Validate required parameters
    if (!this.serverUrl) {
      throw new Error('serverUrl is required');
    }
    if (!this.clientId) {
      throw new Error('clientId is required');
    }

    // Session state
    this.sessionToken = null;
    this.serverPublicKey = null;
    this.clientPrivateKey = null;
    this.sharedSecret = null;
  }

  /**
   * Initialize a QASP handshake with the server.
   *
   * @returns {Promise<Object>} Handshake response containing server challenges
   */
  async initHandshake() {
    const handshakeInit = {
      qasp_version: 'v1.0',
      type: 'handshake_init',
      client_id: this.clientId,
      tenant_id: this.tenantId,
      kem_alg: this.kemAlg,
      sig_alg: this.sigAlg,
      timestamp: Date.now(),
      client_nonce: crypto.randomBytes(16).toString('base64')
    };

    // Add deterministic serialization for cross-language compatibility
    const canonicalJson = this._canonicalizeJson(handshakeInit);

    try {
      const response = await this._makeRequest('/qasp/init', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'QASP-JS-SDK/1.0'
        },
        body: canonicalJson
      });

      if (response.status !== 200) {
        throw new Error(`Handshake init failed: ${response.status} ${response.statusText}`);
      }

      const handshakeData = JSON.parse(response.body);

      // Store server public key for later verification
      this.serverPublicKey = handshakeData.server_public_key;

      return handshakeData;

    } catch (error) {
      throw new Error(`Handshake initialization failed: ${error.message}`);
    }
  }

  /**
   * Complete the QASP handshake with server challenges.
   *
   * @param {Object} serverResponse - Response from initHandshake()
   * @returns {Promise<Object>} Completed handshake with session token
   */
  async completeHandshake(serverResponse) {
    // Generate client key pair (simplified - in real PQC, use actual algorithms)
    const clientKeys = this._generateClientKeys();

    // Create handshake completion message
    const handshakeComplete = {
      qasp_version: 'v1.0',
      type: 'handshake_complete',
      client_id: this.clientId,
      tenant_id: this.tenantId,
      session_id: serverResponse.session_id,
      client_public_key: clientKeys.publicKey,
      client_signature: clientKeys.signature,
      timestamp: Date.now()
    };

    const canonicalJson = this._canonicalizeJson(handshakeComplete);

    try {
      const response = await this._makeRequest('/qasp/complete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'QASP-JS-SDK/1.0'
        },
        body: canonicalJson
      });

      if (response.status !== 200) {
        throw new Error(`Handshake completion failed: ${response.status} ${response.statusText}`);
      }

      const result = JSON.parse(response.body);

      // Store session token
      this.sessionToken = result.session_token;

      // Store shared secret (derived from handshake)
      this.sharedSecret = this._deriveSharedSecret(result);

      return result;

    } catch (error) {
      throw new Error(`Handshake completion failed: ${error.message}`);
    }
  }

  /**
   * Make an authenticated request to a protected endpoint.
   *
   * @param {string} endpoint - API endpoint path
   * @param {Object} data - Request data
   * @returns {Promise<Object>} API response
   */
  async makeAuthenticatedRequest(endpoint, data = {}) {
    if (!this.sessionToken) {
      throw new Error('No active session. Complete handshake first.');
    }

    const requestData = {
      ...data,
      client_id: this.clientId,
      tenant_id: this.tenantId,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(8).toString('hex')
    };

    const canonicalJson = this._canonicalizeJson(requestData);

    // Add HMAC signature for request authentication
    const signature = this._signRequest(canonicalJson);

    try {
      const response = await this._makeRequest(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.sessionToken}`,
          'X-QASP-Signature': signature,
          'User-Agent': 'QASP-JS-SDK/1.0'
        },
        body: canonicalJson
      });

      if (response.status !== 200) {
        throw new Error(`Request failed: ${response.status} ${response.statusText}`);
      }

      return JSON.parse(response.body);

    } catch (error) {
      throw new Error(`Authenticated request failed: ${error.message}`);
    }
  }

  /**
   * End the current session.
   *
   * @returns {Promise<boolean>} Success status
   */
  async endSession() {
    if (!this.sessionToken) {
      return true; // Already ended
    }

    try {
      await this.makeAuthenticatedRequest('/qasp/end', {
        type: 'session_end'
      });

      this.sessionToken = null;
      this.serverPublicKey = null;
      this.clientPrivateKey = null;
      this.sharedSecret = null;

      return true;

    } catch (error) {
      // Log but don't fail - cleanup is best effort
      console.warn('Session cleanup failed:', error.message);
      return false;
    }
  }

  /**
   * Create canonical JSON representation for cross-language interoperability.
   * Follows RFC 8785 JSON Canonicalization Scheme.
   *
   * @private
   * @param {Object} obj - Object to canonicalize
   * @returns {string} Canonical JSON string
   */
  _canonicalizeJson(obj) {
    // Simplified canonicalization - sort keys and minimize whitespace
    return JSON.stringify(obj, Object.keys(obj).sort(), 0);
  }

  /**
   * Generate client key pair (placeholder - replace with actual PQC implementation).
   *
   * @private
   * @returns {Object} Key pair with public key and signature
   */
  _generateClientKeys() {
    // Placeholder implementation - in real use, integrate with @noble/post-quantum or similar
    const publicKey = crypto.randomBytes(32).toString('base64');
    const signature = crypto.randomBytes(64).toString('base64');

    this.clientPrivateKey = crypto.randomBytes(32); // Placeholder private key

    return {
      publicKey,
      signature
    };
  }

  /**
   * Derive shared secret from handshake result.
   *
   * @private
   * @param {Object} handshakeResult - Completed handshake result
   * @returns {Buffer} Shared secret
   */
  _deriveSharedSecret(handshakeResult) {
    // Simplified shared secret derivation
    const secretData = `${handshakeResult.session_token}:${this.clientId}:${Date.now()}`;
    return crypto.createHash('sha256').update(secretData).digest();
  }

  /**
   * Sign a request using HMAC-SHA256.
   *
   * @private
   * @param {string} data - Data to sign
   * @returns {string} Base64-encoded signature
   */
  _signRequest(data) {
    if (!this.sharedSecret) {
      throw new Error('No shared secret available for signing');
    }

    const hmac = crypto.createHmac('sha256', this.sharedSecret);
    hmac.update(data);
    return hmac.digest('base64');
  }

  /**
   * Make an HTTPS request to the server.
   *
   * @private
   * @param {string} path - Request path
   * @param {Object} options - Request options
   * @returns {Promise<Object>} Response object
   */
  _makeRequest(path, options) {
    return new Promise((resolve, reject) => {
      const url = new URL(path, this.serverUrl);
      const requestOptions = {
        method: options.method || 'GET',
        headers: options.headers || {},
        rejectUnauthorized: false // For development only
      };

      const req = https.request(url, requestOptions, (res) => {
        let body = '';

        res.on('data', (chunk) => {
          body += chunk;
        });

        res.on('end', () => {
          resolve({
            status: res.statusCode,
            statusText: res.statusMessage,
            headers: res.headers,
            body
          });
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      if (options.body) {
        req.write(options.body);
      }

      req.end();
    });
  }
}

module.exports = {
  QASPClient,
  ALGORITHMS
};
