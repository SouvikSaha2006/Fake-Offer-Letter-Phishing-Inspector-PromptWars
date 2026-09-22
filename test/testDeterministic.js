/**
 * Deterministic Analysis Layer Test Suite
 * Tests heuristicEngine and domainChecker modules across various scam scenarios and edge cases.
 */

import { scanHeuristics } from '../server/services/heuristicEngine.js';
import { 
  extractDomains, 
  cleanDomain, 
  isValidDomain, 
  checkDomain, 
  checkDomainsInText, 
  FREE_EMAIL_PROVIDERS 
} from '../server/services/domainChecker.js';

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
  console.log('1. Testing Heuristic Engine (Regex Scanners)');
  console.log('====================================================');

  // Test 1: Fake check + equipment scam
  {
    const text = `Congratulations on your selection! We will send you a cashier's check of $3,500. You are required to deposit the check into your bank account immediately, and purchase workstation equipment from our approved vendor.`;
    const res = scanHeuristics(text);
    assert(res.detectedPatterns.some(p => p.id === 'CHECK_EQUIPMENT_SCAM'), 'Detects cashier check & equipment purchase scheme');
    assert(res.paymentRiskScore >= 65, `Payment risk score reflects critical check scam (Score: ${res.paymentRiskScore})`);
  }

  // Test 2: Wire transfer / P2P payment
  {
    const text = `To expedite your paperwork, please send a wire transfer or pay via Zelle to our onboarding agent. Western Union is also accepted.`;
    const res = scanHeuristics(text);
    assert(res.detectedPatterns.some(p => p.id === 'WIRE_TRANSFER_DEMAND'), 'Detects wire transfer, Zelle, and Western Union red flags');
    assert(res.paymentRiskScore >= 45, `Payment risk score reflects wire transfer flags (Score: ${res.paymentRiskScore})`);
  }

  // Test 3: Cryptocurrency demands
  {
    const text = `As part of our decentralized setup, candidates must make a deposit using Bitcoin (BTC) or USDT to our corporate crypto wallet address: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F.`;
    const res = scanHeuristics(text);
    assert(res.detectedPatterns.some(p => p.id === 'CRYPTOCURRENCY_DEMAND'), 'Detects crypto deposit and wallet address demands');
    assert(res.paymentRiskScore >= 60, `Payment risk score reflects cryptocurrency scam (Score: ${res.paymentRiskScore})`);
  }

  // Test 4: Advance fees & processing deposits
  {
    const text = `You must pay a refundable training fee and background check fee of $250 prior to your start date.`;
    const res = scanHeuristics(text);
    assert(res.detectedPatterns.some(p => p.id === 'ADVANCE_FEE_DEMAND'), 'Detects advance fee & refundable deposit demand');
    assert(res.paymentRiskScore >= 55, `Payment risk score reflects advance fee (Score: ${res.paymentRiskScore})`);
  }

  // Test 5: Recruitment channel anomaly (Telegram / WhatsApp)
  {
    const text = `The hiring manager will conduct your interview on Telegram. Please message @HR_Google_Recruiter on Telegram to begin your screening.`;
    const res = scanHeuristics(text);
    assert(res.detectedPatterns.some(p => p.id === 'RECRUITMENT_CHANNEL_ANOMALY'), 'Detects Telegram interview recruitment anomaly');
    assert(res.proceduralRiskScore >= 50, `Procedural risk score reflects messaging channel anomaly (Score: ${res.proceduralRiskScore})`);
  }

  // Test 6: Urgency & high-pressure deadline
  {
    const text = `This offer is strictly confidential. You must sign and return this offer letter within 24 hours or the position will be given to another candidate.`;
    const res = scanHeuristics(text);
    assert(res.detectedPatterns.some(p => p.id === 'URGENCY_PRESSURE_TACTIC'), 'Detects 24-hour urgency pressure tactic');
    assert(res.proceduralRiskScore >= 25, `Procedural risk score reflects urgency tactic (Score: ${res.proceduralRiskScore})`);
  }

  // Test 7: Clean legitimate offer letter (Negative Control)
  {
    const text = `Dear Candidate, We are pleased to offer you the position of Software Engineer at Acme Corp. Your starting annual salary will be $120,000, payable semi-monthly according to standard company payroll. Medical, dental, and vision insurance will commence on your first day. All computing hardware will be configured by our IT department and shipped to your residence free of charge. Please review the enclosed offer letter and return a signed copy by next Friday.`;
    const res = scanHeuristics(text);
    assert(res.detectedPatterns.length === 0, 'No false positive patterns triggered on legitimate offer letter');
    assert(res.paymentRiskScore === 0, 'Payment risk score is 0 on legitimate offer');
    assert(res.proceduralRiskScore === 0, 'Procedural risk score is 0 on legitimate offer');
  }

  // Test 8: Edge cases: empty, null, undefined
  {
    assert(scanHeuristics('').detectedPatterns.length === 0, 'Handles empty string safely');
    assert(scanHeuristics(null).detectedPatterns.length === 0, 'Handles null safely');
    assert(scanHeuristics(undefined).detectedPatterns.length === 0, 'Handles undefined safely');
    assert(scanHeuristics(12345).detectedPatterns.length === 0, 'Handles non-string safely');
  }

  console.log('\n====================================================');
  console.log('2. Testing Domain Checker (Extraction & Analysis)');
  console.log('====================================================');

  // Test 9: Domain extraction
  {
    const sample = `
      Official Contact: recruitment-team@microsoft-verify.com
      Portal: https://secure.amazon-careers-portal.net/login?ref=offer
      Alternate: hr.google.job@gmail.com
      Support link: www.apple-tech-verify.org/support,
    `;
    const extracted = extractDomains(sample);
    assert(extracted.includes('microsoft-verify.com'), 'Extracts domain from email');
    assert(extracted.includes('secure.amazon-careers-portal.net'), 'Extracts subdomain from URL');
    assert(extracted.includes('gmail.com'), 'Extracts free email provider domain');
    assert(extracted.includes('apple-tech-verify.org'), 'Extracts domain with stripped www and punctuation');
  }

  // Test 10: Clean and validate domain helpers
  {
    assert(cleanDomain('WWW.GOOGLE.COM/') === 'google.com', 'Cleans www, uppercase, and trailing slash');
    assert(isValidDomain('google.com'), 'Validates valid domain');
    assert(!isValidDomain('localhost'), 'Rejects localhost');
    assert(!isValidDomain('192.168.1.1'), 'Rejects IP address');
    assert(!isValidDomain('resume.pdf'), 'Rejects document filename as domain');
  }

  // Test 11: Free provider detection
  {
    const gmailCheck = await checkDomain('gmail.com');
    assert(gmailCheck.isFreeProvider === true, 'Identifies gmail.com as free email provider');
    assert(gmailCheck.riskScore === 70, 'Free provider receives high risk score for corporate communication');

    const protonCheck = await checkDomain('proton.me');
    assert(protonCheck.isFreeProvider === true, 'Identifies proton.me as free provider');
  }

  // Test 12: RDAP query on established domain
  {
    console.log('  Testing live RDAP query for google.com...');
    const googleCheck = await checkDomain('google.com');
    assert(googleCheck.status === 'active', 'google.com status is active');
    assert(googleCheck.isFreeProvider === false, 'google.com is not a free email provider');
    assert(typeof googleCheck.ageInDays === 'number' && googleCheck.ageInDays > 365, `google.com age in days is established (> 365 days, actual: ${googleCheck.ageInDays})`);
    assert(googleCheck.riskScore <= 10, `Established domain gets low risk score (Score: ${googleCheck.riskScore})`);
  }

  // Test 13: RDAP query graceful handling of invalid / non-existent domain
  {
    console.log('  Testing graceful error/timeout handling on non-existent domain...');
    const fakeDomain = 'phishguard-definitely-fake-domain-9923847293847.com';
    const fakeCheck = await checkDomain(fakeDomain, 3000);
    assert(['not_found', 'error', 'timeout', 'lookup_failed'].includes(fakeCheck.status), `Gracefully handles non-existent domain (Status: ${fakeCheck.status})`);
    assert(typeof fakeCheck.riskScore === 'number', 'Returns numeric riskScore without crashing');
  }

  // Test 14: checkDomainsInText integration
  {
    const textWithDomains = `Please send your resume to recruiter@gmail.com and visit https://google.com for more info.`;
    const report = await checkDomainsInText(textWithDomains);
    assert(report.extractedDomains.length >= 2, 'Extracts both domains from text');
    assert(report.results.some(r => r.domain === 'gmail.com'), 'Results contain gmail.com check');
    assert(report.results.some(r => r.domain === 'google.com'), 'Results contain google.com check');
    assert(report.overallDomainRiskScore >= 70, 'Overall domain risk reflects highest risk item (gmail.com free provider)');
  }

  console.log('\n====================================================');
  console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
