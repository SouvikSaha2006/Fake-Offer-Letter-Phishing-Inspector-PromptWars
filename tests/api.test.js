/**
 * Integration Tests for API Endpoints (tests/api.test.js)
 */

import app from '../server/index.js';

let passed = 0;
let failed = 0;

function assert(condition, testName) {
  if (condition) {
    console.log(`  PASS: ${testName}`);
    passed++;
  } else {
    console.error(`  FAIL: ${testName}`);
    failed++;
  }
}

async function runApiTests() {
  console.log('====================================================');
  console.log('RUNNING API INTEGRATION TEST SUITE');
  console.log('====================================================');

  // Launch ephemeral server on random available port
  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  try {
    // 1. Test GET /api/health returns status "healthy"
    {
      const res = await fetch(`${baseUrl}/api/health`);
      assert(res.status === 200, 'GET /api/health returns HTTP 200');
      const data = await res.json();
      assert(data.status === 'healthy', 'GET /api/health returns status: "healthy"');
      assert(typeof data.timestamp === 'string', 'GET /api/health includes ISO timestamp');
    }

    // 2. Test input validation rejects empty or too short payload (< 10 chars) with HTTP 400
    {
      const res = await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: 'too short' })
      });
      assert(res.status === 400, 'Rejects short payload (< 10 chars) with HTTP 400');
      const data = await res.json();
      assert(data.error && data.error.includes('too short'), 'Provides descriptive error message for short payload');
    }

    // 3. Test input validation rejects empty object with HTTP 400
    {
      const res = await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      assert(res.status === 400, 'Rejects empty payload with HTTP 400');
    }

    // 4. Test input validation rejects oversized payload (> 20,000 chars) with HTTP 400
    {
      const hugeString = 'A'.repeat(20005);
      const res = await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: hugeString })
      });
      assert(res.status === 400, 'Rejects oversized payload (> 20,000 chars) with HTTP 400');
      const data = await res.json();
      assert(data.error && data.error.includes('maximum'), 'Provides descriptive error message for oversized payload');
    }

    // 5. Test valid payload returns HTTP 200 and complete schema
    {
      const validPayload = {
        text: `
          Dear John Doe,
          We are pleased to offer you the position of Quality Assurance Engineer at Stripe.
          Your annual base salary will be $130,000, payable semi-monthly according to standard company payroll.
          Medical, dental, and retirement benefits will be provided starting on your first day.
          Computing equipment will be shipped directly to your home by corporate IT operations.
          Please sign and return this offer letter by next Friday.
        `
      };

      const res = await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validPayload)
      });

      assert(res.status === 200, 'Valid scan payload returns HTTP 200');
      const data = await res.json();
      assert(data.success === true, 'Response returns success: true');
      assert(typeof data.threatScore === 'number', `Response contains threatScore (${data.threatScore})`);
      assert(
        ['AUTHENTIC', 'SUSPICIOUS', 'CRITICAL FRAUD'].includes(data.category),
        `Response contains valid category: ${data.category}`
      );
      assert(typeof data.metrics === 'object', 'Response contains metrics breakdown object');
      assert(typeof data.metrics.domainRisk === 'number', 'metrics contains domainRisk');
      assert(typeof data.metrics.paymentRisk === 'number', 'metrics contains paymentRisk');
      assert(typeof data.metrics.proceduralRisk === 'number', 'metrics contains proceduralRisk');
      assert(typeof data.metrics.semanticRisk === 'number', 'metrics contains semanticRisk');
      assert(Array.isArray(data.findings), 'Response contains findings array');
      assert(Array.isArray(data.remediation), 'Response contains remediation array');
    }

    // 6. Test security headers injected by helmet
    {
      const res = await fetch(`${baseUrl}/api/health`);
      assert(res.headers.get('x-content-type-options') === 'nosniff', 'Helmet sets X-Content-Type-Options: nosniff');
      assert(res.headers.has('x-frame-options'), 'Helmet sets X-Frame-Options header');
    }

  } finally {
    server.close();
  }

  console.log('====================================================');
  console.log(`API TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runApiTests().catch(err => {
  console.error('Fatal API test error:', err);
  process.exit(1);
});
