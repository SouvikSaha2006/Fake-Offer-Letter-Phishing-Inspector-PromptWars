/**
 * Unit Tests for Heuristic Engine (tests/heuristics.test.js)
 */

import { scanHeuristics } from '../server/services/heuristicEngine.js';

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
console.log('RUNNING HEURISTICS TEST SUITE');
console.log('====================================================');

// 1. Assert cashier check + equipment purchase schemes return payment risk >= 90
{
  const checkScamSample = `
    Congratulations on your selection for the Operations role.
    We will issue you a cashier's check of $3,800. You are required to deposit this check
    into your personal checking account and purchase home office workstation equipment
    from our approved vendor.
  `;
  const result = scanHeuristics(checkScamSample);
  assert(
    result.detectedPatterns.some(p => p.id === 'CHECK_EQUIPMENT_SCAM'),
    'Detects cashier check and equipment purchase scheme pattern'
  );
  assert(
    result.paymentRiskScore >= 90,
    `Assert cashier check + equipment purchase scheme returns payment risk >= 90 (Actual: ${result.paymentRiskScore})`
  );
}

// 2. Assert cryptocurrency demands return flags
{
  const cryptoSample = `
    To finalize your contractor enrollment, you must make a security deposit of $500 in Bitcoin (BTC)
    or USDT to our corporate crypto wallet address: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F.
  `;
  const result = scanHeuristics(cryptoSample);
  assert(
    result.detectedPatterns.some(p => p.id === 'CRYPTOCURRENCY_DEMAND'),
    'Assert cryptocurrency prompt returns cryptocurrency flag'
  );
  assert(
    result.paymentRiskScore >= 75,
    `Payment risk score reflects crypto demand (Actual: ${result.paymentRiskScore})`
  );
}

// 3. Assert Zelle / wire transfer prompts return flags
{
  const zelleSample = `
    Please send your onboarding processing deposit of $350 via Zelle or Western Union wire transfer
    to our designated logistics coordinator.
  `;
  const result = scanHeuristics(zelleSample);
  assert(
    result.detectedPatterns.some(p => p.id === 'WIRE_TRANSFER_DEMAND'),
    'Assert Zelle / wire transfer prompt returns wire transfer flag'
  );
  assert(
    result.paymentRiskScore >= 65,
    `Payment risk score reflects wire transfer flag (Actual: ${result.paymentRiskScore})`
  );
}

// 4. Assert advance fee / processing deposit prompt returns flags
{
  const advanceFeeSample = `
    Candidate must pay a refundable training fee and background check fee of $200
    prior to receiving official employment verification.
  `;
  const result = scanHeuristics(advanceFeeSample);
  assert(
    result.detectedPatterns.some(p => p.id === 'ADVANCE_FEE_DEMAND'),
    'Assert advance fee prompt returns advance fee flag'
  );
}

// 5. Assert standard compensation text returns 0 payment flags
{
  const legitimateCorporateSample = `
    Dear Alex Morgan,
    We are thrilled to offer you the position of Senior DevOps Engineer at Acme Global.
    Your starting base salary will be $155,000 USD per year, payable semi-monthly in accordance
    with our standard corporate payroll schedule via direct deposit.
    Standard medical, vision, dental benefits, and a 401(k) retirement plan with 5% company match
    will commence on your first day of employment.
    All required computing hardware will be configured by corporate IT and delivered to your home.
  `;
  const result = scanHeuristics(legitimateCorporateSample);
  const paymentFlags = result.detectedPatterns.filter(p => p.category === 'PAYMENT');
  assert(
    paymentFlags.length === 0,
    'Assert standard compensation text returns 0 payment flags'
  );
  assert(
    result.paymentRiskScore === 0,
    'Payment risk score is strictly 0 on standard compensation text'
  );
  assert(
    result.proceduralRiskScore === 0,
    'Procedural risk score is strictly 0 on standard compensation text'
  );
}

// 6. Assert scores are bounded to [0, 100]
{
  const multiScamSample = `
    Cashier's check deposit equipment purchase from approved vendor.
    Also wire transfer via Western Union, Zelle, Venmo.
    Also pay with Bitcoin BTC and USDT crypto wallet.
    Also pay advance application fee and background fee.
  `;
  const result = scanHeuristics(multiScamSample);
  assert(
    result.paymentRiskScore <= 100 && result.paymentRiskScore >= 0,
    `Assert payment risk score is bounded within [0, 100] (Actual: ${result.paymentRiskScore})`
  );
}

console.log('====================================================');
console.log(`HEURISTICS TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log('====================================================');

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
