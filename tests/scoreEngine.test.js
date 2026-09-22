/**
 * Unit Tests for Scoring Engine (tests/scoreEngine.test.js)
 */

import { calculateScamThreatIndex, computeGeminiScore, mergeFindings, RISK_CATEGORIES } from '../server/utils/scoreEngine.js';

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

console.log('====================================================');
console.log('RUNNING SCORE ENGINE TEST SUITE');
console.log('====================================================');

// 1. Assert bounded score property: output is always between 0 and 100
{
  const testCases = [
    { name: 'All zeroes', input: { domainRisk: 0, paymentRisk: 0, proceduralRisk: 0, geminiScore: 0 }, expectedMin: 0, expectedMax: 0 },
    { name: 'All max 100', input: { domainRisk: 100, paymentRisk: 100, proceduralRisk: 100, geminiScore: 100 }, expectedMin: 100, expectedMax: 100 },
    { name: 'Excessive values (> 100)', input: { domainRisk: 999, paymentRisk: 500, proceduralRisk: 300, geminiScore: 400 }, expectedMin: 100, expectedMax: 100 },
    { name: 'Negative values (< 0)', input: { domainRisk: -50, paymentRisk: -100, proceduralRisk: -20, geminiScore: -30 }, expectedMin: 0, expectedMax: 0 },
    { name: 'NaN and undefined handling', input: { domainRisk: NaN, paymentRisk: undefined, proceduralRisk: null, geminiScore: 'invalid' }, expectedMin: 0, expectedMax: 0 }
  ];

  for (const tc of testCases) {
    const res = calculateScamThreatIndex(tc.input);
    assert(
      res.threatScore >= tc.expectedMin && res.threatScore <= tc.expectedMax,
      `Bounded score property: ${tc.name} produces score in [${tc.expectedMin}, ${tc.expectedMax}] (Actual: ${res.threatScore})`
    );
  }
}

// 2. Test weight distribution: 0.30 domain + 0.30 payment + 0.20 procedural + 0.20 semantic
{
  // Test uniform 50% across all four pillars:
  // Expected: 0.30*50 + 0.30*50 + 0.20*50 + 0.20*50 = 15 + 15 + 10 + 10 = 50
  const uniform = calculateScamThreatIndex({
    domainRisk: 50,
    paymentRisk: 50,
    proceduralRisk: 50,
    geminiScore: 50
  });
  assert(
    uniform.threatScore === 50,
    `Weight distribution test (50% uniform): Expected 50, got ${uniform.threatScore}`
  );
  assert(
    uniform.breakdown.weights.domain === 0.30 &&
    uniform.breakdown.weights.payment === 0.30 &&
    uniform.breakdown.weights.procedural === 0.20 &&
    uniform.breakdown.weights.semantic === 0.20,
    'Weights strictly match 0.30 domain + 0.30 payment + 0.20 procedural + 0.20 semantic'
  );

  // Test isolated domain contribution: D=100, others 0 -> 0.30*100 = 30
  const domainOnly = calculateScamThreatIndex({ domainRisk: 100, paymentRisk: 0, proceduralRisk: 0, geminiScore: 0 });
  assert(domainOnly.threatScore === 30, `Domain 100% contributes exactly 30 points (Actual: ${domainOnly.threatScore})`);

  // Test isolated procedural contribution: E=100, others 0 -> 0.20*100 = 20
  const proceduralOnly = calculateScamThreatIndex({ domainRisk: 0, paymentRisk: 0, proceduralRisk: 100, geminiScore: 0 });
  assert(proceduralOnly.threatScore === 20, `Procedural 100% contributes exactly 20 points (Actual: ${proceduralOnly.threatScore})`);

  // Test isolated semantic contribution: S=100, others 0 -> 0.20*100 = 20
  const semanticOnly = calculateScamThreatIndex({ domainRisk: 0, paymentRisk: 0, proceduralRisk: 0, geminiScore: 100 });
  assert(semanticOnly.threatScore === 20, `Semantic 100% contributes exactly 20 points (Actual: ${semanticOnly.threatScore})`);
}

// 3. Test categorization thresholds
{
  const authentic = calculateScamThreatIndex({ domainRisk: 10, paymentRisk: 0, proceduralRisk: 0, geminiScore: 10 });
  assert(authentic.category === RISK_CATEGORIES.AUTHENTIC, `Score ${authentic.threatScore} categorized as AUTHENTIC`);

  const suspicious = calculateScamThreatIndex({ domainRisk: 40, paymentRisk: 40, proceduralRisk: 30, geminiScore: 30 });
  // 0.30(40)+0.30(40)+0.20(30)+0.20(30) = 12 + 12 + 6 + 6 = 36
  assert(suspicious.category === RISK_CATEGORIES.SUSPICIOUS, `Score ${suspicious.threatScore} categorized as SUSPICIOUS`);

  const critical = calculateScamThreatIndex({ domainRisk: 90, paymentRisk: 90, proceduralRisk: 70, geminiScore: 80 });
  assert(critical.category === RISK_CATEGORIES.CRITICAL_FRAUD, `Score ${critical.threatScore} categorized as CRITICAL FRAUD`);
}

// 4. Test structured findings schema format
{
  const findings = mergeFindings({
    detectedPatterns: [{ title: 'Check Scam', severity: 'CRITICAL', weight: 95, matchedText: 'deposit check', explanation: 'Fake check fraud' }],
    domainResults: [{ domain: 'fake.com', ageInDays: 3, registrationDate: '2026-09-19', isFreeProvider: false }],
    deceptionFlags: [{ flag: 'Fake Urgency', severity: 'HIGH', explanation: '24hr pressure' }]
  });

  assert(findings.length === 3, 'Merges findings from all layers');
  for (const f of findings) {
    assert(
      typeof f.flag === 'string' &&
      typeof f.severity === 'string' &&
      f.weight !== undefined &&
      typeof f.explanation === 'string',
      `Finding contains { flag, severity, weight, explanation }: ${f.flag}`
    );
  }
}

console.log('====================================================');
console.log(`SCORE ENGINE TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log('====================================================');

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
