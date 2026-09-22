/**
 * Scam Threat Index Scoring Engine for PhishGuard Inspector
 * Computes bounded Scam Threat Index formula:
 * S = min(100, 0.30 * D + 0.30 * P + 0.20 * E + 0.20 * S_gemini)
 */

export const RISK_CATEGORIES = {
  AUTHENTIC: 'AUTHENTIC',
  SUSPICIOUS: 'SUSPICIOUS',
  CRITICAL_FRAUD: 'CRITICAL FRAUD'
};

/**
 * Computes semantic deception score (S_gemini) from Gemini metrics
 * @param {object} semanticReport
 * @returns {number} - Bounded integer 0 to 100
 */
export function computeGeminiScore(semanticReport) {
  if (!semanticReport || typeof semanticReport !== 'object') return 0;

  const urgency = typeof semanticReport.urgencyScore === 'number' ? semanticReport.urgencyScore : 0;
  const salaryRealism = typeof semanticReport.salaryRealismScore === 'number' ? semanticReport.salaryRealismScore : 70;
  const salaryDeception = Math.max(0, 100 - salaryRealism);

  let flagScore = 0;
  if (Array.isArray(semanticReport.deceptionFlags)) {
    for (const flag of semanticReport.deceptionFlags) {
      if (flag.severity === 'CRITICAL') flagScore += 35;
      else if (flag.severity === 'HIGH') flagScore += 25;
      else if (flag.severity === 'MEDIUM') flagScore += 15;
      else flagScore += 5;
    }
  }

  const sGemini = 0.35 * urgency + 0.35 * salaryDeception + 0.30 * Math.min(100, flagScore);
  return Math.min(100, Math.max(0, Math.round(sGemini)));
}

/**
 * Merges and standardizes itemized evidence tags into findings format
 * @param {object} params
 * @param {Array} [params.detectedPatterns=[]]
 * @param {Array} [params.domainResults=[]]
 * @param {Array} [params.deceptionFlags=[]]
 * @returns {Array<{ flag: string, severity: string, weight: number|string, explanation: string, source: string, type: string, title: string, detail: string }>}
 */
export function mergeFindings({ detectedPatterns = [], domainResults = [], deceptionFlags = [] }) {
  const findings = [];

  // 1. Heuristic pattern triggers
  for (const p of detectedPatterns) {
    findings.push({
      flag: p.title,
      severity: p.severity || 'HIGH',
      weight: p.weight ? `+${p.weight} PTS` : '+35 PTS',
      explanation: p.matchedText ? `Triggered: "${p.matchedText}". ${p.explanation}` : p.explanation,
      source: 'HEURISTIC',
      type: p.category || 'PATTERN',
      title: p.title,
      detail: p.matchedText || p.snippet || p.explanation
    });
  }

  // 2. Domain verification triggers
  for (const dom of domainResults) {
    if (dom.isFreeProvider) {
      findings.push({
        flag: `Free Email Domain: ${dom.domain}`,
        severity: 'HIGH',
        weight: '+70 PTS',
        explanation: 'Official recruitment communication conducted via consumer free email provider rather than verified corporate domain.',
        source: 'DOMAIN',
        type: 'FREE_PROVIDER',
        title: `Free Email Domain: ${dom.domain}`,
        detail: dom.details || 'Free consumer email provider masquerading as corporate domain'
      });
    } else if (dom.ageInDays !== null && dom.ageInDays < 30) {
      const severity = dom.ageInDays < 14 ? 'CRITICAL' : 'HIGH';
      findings.push({
        flag: `Newly Registered Domain: ${dom.domain}`,
        severity,
        weight: dom.ageInDays < 14 ? '+95 PTS' : '+85 PTS',
        explanation: `Domain was created only ${dom.ageInDays} days ago (${dom.registrationDate}), strongly indicating disposable infrastructure.`,
        source: 'DOMAIN',
        type: 'NEW_DOMAIN',
        title: `Newly Registered Domain: ${dom.domain}`,
        detail: `Domain was registered ${dom.ageInDays} days ago (${dom.registrationDate})`
      });
    } else if (dom.status === 'not_found') {
      findings.push({
        flag: `Unregistered Domain: ${dom.domain}`,
        severity: 'HIGH',
        weight: '+55 PTS',
        explanation: 'Domain has no active registration record in ICANN RDAP registry.',
        source: 'DOMAIN',
        type: 'UNREGISTERED_DOMAIN',
        title: `Unregistered Domain: ${dom.domain}`,
        detail: 'Domain registration record not found in RDAP registry'
      });
    }
  }

  // 3. AI Semantic deception flags
  for (const f of deceptionFlags) {
    findings.push({
      flag: f.flag,
      severity: f.severity || 'MEDIUM',
      weight: f.severity === 'CRITICAL' ? '+35 PTS' : f.severity === 'HIGH' ? '+25 PTS' : '+15 PTS',
      explanation: f.explanation,
      source: 'AI_SEMANTIC',
      type: 'DECEPTION_FLAG',
      title: f.flag,
      detail: f.explanation
    });
  }

  return findings;
}

/**
 * Calculates Scam Threat Index S ∈ [0, 100] and structured assessment
 * Mathematical Formula:
 * S = min(100, 0.30 * D + 0.30 * P + 0.20 * E + 0.20 * S_gemini)
 * 
 * @param {object} components
 * @param {number} [components.domainRisk=0] - D ∈ [0, 100]
 * @param {number} [components.paymentRisk=0] - P ∈ [0, 100]
 * @param {number} [components.proceduralRisk=0] - E ∈ [0, 100]
 * @param {number|object} [components.geminiScore=0] - S_gemini ∈ [0, 100] or semanticReport
 * @param {object} [components.rawAnalysis={}] - Artifacts for findings synthesis
 * @returns {{ threatScore: number, compositeScore: number, scamThreatIndex: number, category: string, riskCategory: string, metrics: object, breakdown: object, findings: Array, itemizedEvidence: Array, remediation: Array }}
 */
export function calculateScamThreatIndex({
  domainRisk = 0,
  paymentRisk = 0,
  proceduralRisk = 0,
  geminiScore = 0,
  rawAnalysis = {}
}) {
  // Enforce strictly bounded inputs [0, 100]
  const D = Math.max(0, Math.min(100, Number(domainRisk) || 0));
  const P = Math.max(0, Math.min(100, Number(paymentRisk) || 0));
  const E = Math.max(0, Math.min(100, Number(proceduralRisk) || 0));
  
  const S_gemini = typeof geminiScore === 'object' && geminiScore !== null
    ? computeGeminiScore(geminiScore)
    : Math.max(0, Math.min(100, Number(geminiScore) || 0));

  // Mathematical composite formula: S = min(100, 0.30 * D + 0.30 * P + 0.20 * E + 0.20 * S_gemini)
  const rawComposite = (0.30 * D) + (0.30 * P) + (0.20 * E) + (0.20 * S_gemini);
  let score = Math.min(100, Math.max(0, Math.round(rawComposite)));

  // Elevate if critical payment scam is definitively detected
  if (P >= 90 && score < 70) {
    score = Math.max(score, 75);
  }

  // Determine Category: AUTHENTIC (0–29), SUSPICIOUS (30–69), CRITICAL FRAUD (70–100)
  let category = RISK_CATEGORIES.AUTHENTIC;
  if (score >= 70) {
    category = RISK_CATEGORIES.CRITICAL_FRAUD;
  } else if (score >= 30) {
    category = RISK_CATEGORIES.SUSPICIOUS;
  } else {
    category = RISK_CATEGORIES.AUTHENTIC;
  }

  const findings = mergeFindings({
    detectedPatterns: rawAnalysis.detectedPatterns || [],
    domainResults: rawAnalysis.domainResults || [],
    deceptionFlags: rawAnalysis.deceptionFlags || []
  });

  const defaultRemediation = [
    'Verify the offer by contacting the hiring company directly through their official public website or switchboard.',
    'Never deposit cashier checks or forward funds to third-party equipment vendors.',
    'Confirm recruiter credentials independently on professional platforms like LinkedIn.'
  ];

  const remediation = Array.isArray(rawAnalysis.remediationAdvice) && rawAnalysis.remediationAdvice.length > 0
    ? rawAnalysis.remediationAdvice
    : defaultRemediation;

  const metrics = {
    domainRisk: D,
    paymentRisk: P,
    proceduralRisk: E,
    semanticRisk: S_gemini
  };

  const breakdown = {
    ...metrics,
    geminiRisk: S_gemini,
    weights: {
      domain: 0.30,
      payment: 0.30,
      procedural: 0.20,
      semantic: 0.20
    }
  };

  return {
    threatScore: score,
    compositeScore: score,       // Backward compatibility
    scamThreatIndex: score,      // Backward compatibility
    category,
    riskCategory: category,      // Backward compatibility
    metrics,
    breakdown,
    findings,
    itemizedEvidence: findings,  // Backward compatibility
    remediation,
    remediationAdvice: remediation // Backward compatibility
  };
}

export default {
  calculateScamThreatIndex,
  computeGeminiScore,
  mergeFindings,
  mergeItemizedEvidence: mergeFindings,
  RISK_CATEGORIES
};
