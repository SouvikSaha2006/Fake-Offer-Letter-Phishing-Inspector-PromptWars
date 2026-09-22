/**
 * Scam Threat Index Scoring Engine for PhishGuard Inspector
 * Implements the mathematical composite risk formula:
 * S = min(100, 0.30 * D + 0.30 * P + 0.20 * E + 0.20 * S_gemini)
 */

export const RISK_CATEGORIES = {
  AUTHENTIC: 'AUTHENTIC',
  SUSPICIOUS: 'SUSPICIOUS',
  CRITICAL_FRAUD: 'CRITICAL FRAUD'
};

/**
 * Computes model risk score (S_gemini) from Gemini semantic metrics
 * @param {object} semanticReport
 * @returns {number} - 0 to 100
 */
export function computeGeminiScore(semanticReport) {
  if (!semanticReport) return 0;

  const urgency = typeof semanticReport.urgencyScore === 'number' ? semanticReport.urgencyScore : 0;
  // If salaryRealism is low (e.g. 10), deception is high (90)
  const salaryRealism = typeof semanticReport.salaryRealismScore === 'number' ? semanticReport.salaryRealismScore : 70;
  const salaryDeception = Math.max(0, 100 - salaryRealism);

  // Score severity of flags
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
 * Merges itemized evidence tags from heuristic, domain, and AI analyses
 * @param {object} params
 * @param {Array} [params.detectedPatterns=[]]
 * @param {Array} [params.domainResults=[]]
 * @param {Array} [params.deceptionFlags=[]]
 * @returns {Array} - Unified array of evidence tags
 */
export function mergeItemizedEvidence({ detectedPatterns = [], domainResults = [], deceptionFlags = [] }) {
  const evidence = [];

  // 1. Heuristic pattern triggers
  for (const pattern of detectedPatterns) {
    evidence.push({
      source: 'HEURISTIC',
      type: pattern.category || 'PATTERN',
      severity: pattern.severity || 'HIGH',
      title: pattern.title,
      detail: pattern.matchedText || pattern.snippet || pattern.explanation
    });
  }

  // 2. Domain verification evidence
  for (const domain of domainResults) {
    if (domain.isFreeProvider) {
      evidence.push({
        source: 'DOMAIN',
        type: 'FREE_PROVIDER',
        severity: 'HIGH',
        title: `Free Email Domain: ${domain.domain}`,
        detail: domain.details || 'Official communication conducted from consumer free email provider'
      });
    } else if (domain.ageInDays !== null && domain.ageInDays < 30) {
      evidence.push({
        source: 'DOMAIN',
        type: 'NEW_DOMAIN',
        severity: domain.ageInDays < 14 ? 'CRITICAL' : 'HIGH',
        title: `Newly Registered Domain: ${domain.domain}`,
        detail: `Domain was created only ${domain.ageInDays} days ago (${domain.registrationDate})`
      });
    } else if (domain.status === 'not_found') {
      evidence.push({
        source: 'DOMAIN',
        type: 'UNREGISTERED_DOMAIN',
        severity: 'HIGH',
        title: `Unregistered Domain: ${domain.domain}`,
        detail: 'Domain has no active RDAP registry record'
      });
    }
  }

  // 3. AI Semantic deception flags
  for (const flag of deceptionFlags) {
    evidence.push({
      source: 'AI_SEMANTIC',
      type: 'DECEPTION_FLAG',
      severity: flag.severity || 'MEDIUM',
      title: flag.flag,
      detail: flag.explanation
    });
  }

  return evidence;
}

/**
 * Calculates Scam Threat Index S ∈ [0, 100] and risk category
 * Formula: S = min(100, 0.30 * D + 0.30 * P + 0.20 * E + 0.20 * S_gemini)
 * @param {object} components
 * @param {number} components.domainRisk - D ∈ [0, 100]
 * @param {number} components.paymentRisk - P ∈ [0, 100]
 * @param {number} components.proceduralRisk - E ∈ [0, 100]
 * @param {number|object} components.geminiScore - S_gemini ∈ [0, 100] or semanticReport object
 * @param {object} [components.rawAnalysis={}] - Analysis artifacts for evidence aggregation
 * @returns {{ compositeScore: number, riskCategory: string, breakdown: object, itemizedEvidence: Array }}
 */
export function calculateScamThreatIndex({
  domainRisk = 0,
  paymentRisk = 0,
  proceduralRisk = 0,
  geminiScore = 0,
  rawAnalysis = {}
}) {
  const D = Math.max(0, Math.min(100, Number(domainRisk) || 0));
  const P = Math.max(0, Math.min(100, Number(paymentRisk) || 0));
  const E = Math.max(0, Math.min(100, Number(proceduralRisk) || 0));
  
  const S_gemini = typeof geminiScore === 'object' && geminiScore !== null
    ? computeGeminiScore(geminiScore)
    : Math.max(0, Math.min(100, Number(geminiScore) || 0));

  // S = min(100, 0.30 * D + 0.30 * P + 0.20 * E + 0.20 * S_gemini)
  const rawComposite = 0.30 * D + 0.30 * P + 0.20 * E + 0.20 * S_gemini;
  let compositeScore = Math.min(100, Math.max(0, Math.round(rawComposite)));

  // If a critical payment scam (e.g. check deposit scam) is definitively detected, ensure minimum elevated threshold
  if (P >= 65 && compositeScore < 60) {
    compositeScore = Math.max(compositeScore, 65);
  }

  // Determine Category: AUTHENTIC, SUSPICIOUS, CRITICAL FRAUD
  let riskCategory = RISK_CATEGORIES.AUTHENTIC;
  if (compositeScore >= 60) {
    riskCategory = RISK_CATEGORIES.CRITICAL_FRAUD;
  } else if (compositeScore >= 25) {
    riskCategory = RISK_CATEGORIES.SUSPICIOUS;
  } else {
    riskCategory = RISK_CATEGORIES.AUTHENTIC;
  }

  const itemizedEvidence = mergeItemizedEvidence({
    detectedPatterns: rawAnalysis.detectedPatterns || [],
    domainResults: rawAnalysis.domainResults || [],
    deceptionFlags: rawAnalysis.deceptionFlags || []
  });

  return {
    compositeScore,
    riskCategory,
    breakdown: {
      domainRisk: D,
      paymentRisk: P,
      proceduralRisk: E,
      geminiRisk: S_gemini,
      weights: {
        domain: 0.30,
        payment: 0.30,
        procedural: 0.20,
        gemini: 0.20
      }
    },
    itemizedEvidence
  };
}

export default {
  calculateScamThreatIndex,
  computeGeminiScore,
  mergeItemizedEvidence,
  RISK_CATEGORIES
};
