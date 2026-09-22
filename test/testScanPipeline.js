/**
 * Test Suite for Semantic Layer, Score Engine, and POST /api/scan
 */

import { calculateScamThreatIndex, computeGeminiScore, mergeItemizedEvidence, RISK_CATEGORIES } from '../server/utils/scoreEngine.js';
import { getFallbackSemantics } from '../server/services/geminiClient.js';
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

async function runTests() {
  console.log('====================================================');
  console.log('1. Testing Score Engine Mathematical Formula');
  console.log('====================================================');

  // Test 1: Mathematical formula accuracy S = min(100, 0.30*D + 0.30*P + 0.20*E + 0.20*S_gemini)
  {
    const result = calculateScamThreatIndex({
      domainRisk: 50,
      paymentRisk: 80,
      proceduralRisk: 60,
      geminiScore: 70
    });
    // Expected: 0.30*50 + 0.30*80 + 0.20*60 + 0.20*70 = 15 + 24 + 12 + 14 = 65
    assert(result.compositeScore === 65, `Composite score computes accurately (Expected 65, got ${result.compositeScore})`);
    assert(result.riskCategory === RISK_CATEGORIES.CRITICAL_FRAUD, `Category is CRITICAL FRAUD for score ${result.compositeScore}`);
  }

  // Test 2: Authentic document baseline
  {
    const result = calculateScamThreatIndex({
      domainRisk: 5,
      paymentRisk: 0,
      proceduralRisk: 0,
      geminiScore: 10
    });
    // Expected: 0.30*5 + 0.30*0 + 0.20*0 + 0.20*10 = 1.5 + 2 = 3.5 -> 4
    assert(result.compositeScore === 4, `Low risk score computed correctly (${result.compositeScore})`);
    assert(result.riskCategory === RISK_CATEGORIES.AUTHENTIC, 'Identified as AUTHENTIC');
  }

  // Test 3: Suspicious score band
  {
    const result = calculateScamThreatIndex({
      domainRisk: 40,
      paymentRisk: 30,
      proceduralRisk: 25,
      geminiScore: 35
    });
    // Expected: 0.30*40 + 0.30*30 + 0.20*25 + 0.20*35 = 12 + 9 + 5 + 7 = 33
    assert(result.compositeScore === 33, `Suspicious composite score computes accurately (${result.compositeScore})`);
    assert(result.riskCategory === RISK_CATEGORIES.SUSPICIOUS, 'Identified as SUSPICIOUS');
  }

  // Test 4: Evidence merging
  {
    const evidence = mergeItemizedEvidence({
      detectedPatterns: [{ category: 'PAYMENT', severity: 'CRITICAL', title: 'Check Scam', matchedText: 'deposit check' }],
      domainResults: [{ domain: 'scam-careers.com', ageInDays: 5, registrationDate: '2026-09-17', isFreeProvider: false }],
      deceptionFlags: [{ flag: 'Fake urgency', severity: 'HIGH', explanation: '24hr limit' }]
    });
    assert(evidence.length === 3, 'Merges all 3 evidence sources');
    assert(evidence.some(e => e.source === 'HEURISTIC' && e.severity === 'CRITICAL'), 'Contains heuristic critical tag');
    assert(evidence.some(e => e.source === 'DOMAIN' && e.type === 'NEW_DOMAIN'), 'Contains domain tag');
    assert(evidence.some(e => e.source === 'AI_SEMANTIC'), 'Contains AI semantic flag');
  }

  console.log('\n====================================================');
  console.log('2. Testing Gemini Service Fallback & Schema');
  console.log('====================================================');

  // Test 5: Fallback semantics generator
  {
    const fallback = getFallbackSemantics('You must act within 24 hours to claim your $120/hr position.', 'Test reason');
    assert(typeof fallback.urgencyScore === 'number' && fallback.urgencyScore >= 70, 'Fallback correctly identifies high urgency');
    assert(typeof fallback.salaryRealismScore === 'number' && fallback.salaryRealismScore <= 30, 'Fallback detects disproportionate pay lure');
    assert(Array.isArray(fallback.deceptionFlags) && fallback.deceptionFlags.length > 0, 'Fallback provides deception flags');
    assert(Array.isArray(fallback.remediationAdvice) && fallback.remediationAdvice.length >= 3, 'Fallback provides actionable advice');
    assert(fallback.isFallback === true, 'Flags response as fallback');
  }

  console.log('\n====================================================');
  console.log('3. Testing POST /api/scan Endpoint Integration');
  console.log('====================================================');

  // Start temporary server for testing
  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  try {
    // Test 6: Empty payload returns 400
    {
      const res = await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      assert(res.status === 400, 'Empty payload correctly returns HTTP 400');
    }

    // Test 7: Full scam document scanning
    {
      const scamPayload = {
        text: `
          Dear Candidate,
          Congratulations! You have been selected for the Data Entry Specialist role.
          We will issue you a cashier's check of $4,200. You must deposit the check into your bank account
          and purchase equipment from our approved vendor via Zelle or wire transfer.
          Your interview and onboarding coordinator is available on Telegram: @hr_fast_recruit.
          Contact us at hiring@gmail.com.
          This offer is strictly confidential and must be accepted within 24 hours.
        `,
        url: 'https://careers-google-onboarding-verify.com'
      };

      const res = await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scamPayload)
      });

      assert(res.status === 200, 'Scam scan request returns HTTP 200');
      const body = await res.json();
      assert(body.success === true, 'Response indicates success: true');
      assert(typeof body.scamThreatIndex === 'number', `Composite Scam Threat Index is present (${body.scamThreatIndex})`);
      assert(body.riskCategory === 'CRITICAL FRAUD', `Risk category is CRITICAL FRAUD (Category: ${body.riskCategory})`);
      assert(body.heuristics.detectedPatterns.length >= 3, 'Heuristic engine flags check scam, wire transfer, and Telegram');
      assert(body.heuristics.paymentRiskScore >= 65, 'Payment risk score correctly reflects critical payment flags');
      assert(body.heuristics.proceduralRiskScore >= 50, 'Procedural risk score reflects recruitment channel anomaly');
      assert(Array.isArray(body.itemizedEvidence) && body.itemizedEvidence.length > 0, 'Unified itemized evidence tags returned');
      assert(Array.isArray(body.remediationAdvice) && body.remediationAdvice.length > 0, 'Actionable remediation advice returned');
      assert(typeof body.semantics.urgencyScore === 'number', 'Urgency score returned in semantics');
    }

    // Test 8: Legitimate offer document scanning
    {
      const legitPayload = {
        text: `
          Dear Jane Doe,
          We are thrilled to offer you the position of Senior Frontend Developer at TechCorp.
          Your annual base salary will be $135,000, paid semi-monthly according to standard company payroll.
          Standard medical, dental, and retirement benefits will be provided.
          Company hardware will be delivered to your address prior to your start date.
          Please sign and return this document by Friday of next week.
        `
      };

      const res = await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(legitPayload)
      });

      assert(res.status === 200, 'Legitimate scan request returns HTTP 200');
      const body = await res.json();
      assert(body.scamThreatIndex < 25, `Legitimate offer scores in AUTHENTIC bracket (Score: ${body.scamThreatIndex})`);
      assert(body.riskCategory === 'AUTHENTIC', 'Legitimate offer categorized as AUTHENTIC');
      assert(body.heuristics.detectedPatterns.length === 0, 'Zero heuristic false positives on legitimate offer');
    }

  } finally {
    server.close();
  }

  console.log('\n====================================================');
  console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
