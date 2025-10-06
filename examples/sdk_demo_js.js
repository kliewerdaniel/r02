/**
 * QASP JavaScript SDK Demo
 *
 * This example demonstrates how to use the QASP JavaScript SDK to:
 * 1. Initialize and complete a QASP handshake
 * 2. Make authenticated requests to protected endpoints
 * 3. Handle session management
 */

const { QASPClient, ALGORITHMS } = require('./sdk/js/qasp-sdk/index.js');

// Configuration
const SERVER_URL = process.env.QASP_SERVER_URL || 'http://localhost:8000';
const CLIENT_ID = process.env.CLIENT_ID || 'demo-client-js';

// Demo function
async function runDemo() {
  console.log('🚀 QASP JavaScript SDK Demo');
  console.log('==============================');

  try {
    // Create QASP client
    console.log('\n📡 Creating QASP client...');
    const client = new QASPClient({
      serverUrl: SERVER_URL,
      clientId: CLIENT_ID,
      tenantId: 'demo',
      kemAlg: ALGORITHMS.KEM.KYBER512,
      sigAlg: ALGORITHMS.SIG.DILITHIUM3
    });

    console.log(`✓ Client created for server: ${SERVER_URL}`);

    // Step 1: Initialize handshake
    console.log('\n🔐 Initializing handshake...');
    const initResponse = await client.initHandshake();
    console.log('✓ Handshake initialized');
    console.log(`  Session ID: ${initResponse.session_id}`);

    // Step 2: Complete handshake
    console.log('\n🔒 Completing handshake...');
    await client.completeHandshake(initResponse);
    console.log('✓ Handshake completed');
    console.log(`  Session Token: ${client.sessionToken?.substring(0, 20)}...`);

    // Step 3: Make authenticated request
    console.log('\n📤 Making authenticated request...');
    const requestData = {
      action: 'demo_request',
      timestamp: new Date().toISOString(),
      data: { key: 'value' }
    };

    const response = await client.makeAuthenticatedRequest('/api/demo', requestData);
    console.log('✓ Authenticated request successful');
    console.log(`  Response: ${JSON.stringify(response, null, 2)}`);

    // Step 4: End session
    console.log('\n👋 Ending session...');
    await client.endSession();
    console.log('✓ Session ended');

    console.log('\n🎉 Demo completed successfully!');

  } catch (error) {
    console.error('\n❌ Demo failed:', error.message);
    if (error.response) {
      console.error('  Response status:', error.response.status);
      console.error('  Response body:', error.response.data);
    }
    process.exit(1);
  }
}

// Error handling wrapper
async function main() {
  try {
    await runDemo();
  } catch (error) {
    console.error('\n💥 Unexpected error:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

// Run demo if called directly
if (require.main === module) {
  main();
}

module.exports = { runDemo };
