/**
 * Gemini Semantic Analysis Service for PhishGuard Inspector
 * Uses @google/genai with gemini-1.5-flash and strict JSON schema validation
 * to evaluate document semantics, urgency, salary realism, and deception flags.
 */

import { GoogleGenAI, Type } from '@google/genai';
import dotenv from 'dotenv';

dotenv.config();

const CANDIDATE_MODELS = [
  process.env.GEMINI_MODEL || 'gemini-flash-latest',
  'gemini-3.6-flash',
  'gemini-2.5-flash-lite',
  'gemini-1.5-flash'
];

// Strict JSON schema for forensic semantic analysis
export const SEMANTIC_ANALYSIS_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    urgencyScore: {
      type: Type.INTEGER,
      description: 'Psychological pressure and artificial urgency score from 0 (relaxed/standard) to 100 (extreme coercive pressure).'
    },
    salaryRealismScore: {
      type: Type.INTEGER,
      description: 'Realism of compensation and benefits relative to job duties from 0 (completely absurd/unrealistic lure) to 100 (realistic market standard).'
    },
    deceptionFlags: {
      type: Type.ARRAY,
      description: 'Identified deceptive tactics, vague responsibilities, unusual grammar, or impersonation signs.',
      items: {
        type: Type.OBJECT,
        properties: {
          flag: { 
            type: Type.STRING, 
            description: 'Short name or category of the deception flag' 
          },
          severity: { 
            type: Type.STRING, 
            enum: ['INFO', 'MEDIUM', 'HIGH', 'CRITICAL'],
            description: 'Severity level of the deceptive indicator'
          },
          explanation: { 
            type: Type.STRING, 
            description: 'Detailed explanation of why this is suspicious' 
          }
        },
        required: ['flag', 'severity', 'explanation']
      }
    },
    remediationAdvice: {
      type: Type.ARRAY,
      description: 'Prioritized actionable guidance for the applicant to protect themselves and verify the opportunity.',
      items: {
        type: Type.STRING
      }
    }
  },
  required: ['urgencyScore', 'salaryRealismScore', 'deceptionFlags', 'remediationAdvice']
};

/**
 * Dynamic fallback semantic analysis when Gemini API is unavailable or unconfigured.
 * Evaluates semantic indicators directly from input text so threat scores remain reactive.
 * @param {string} rawText
 * @param {string} [reason='Gemini API unavailable']
 * @returns {object}
 */
export function getFallbackSemantics(rawText = '', reason = 'Gemini API unavailable') {
  const text = typeof rawText === 'string' ? rawText : '';
  const flags = [];

  let urgency = 5;
  let salaryRealism = 85;

  // 1. Dynamic urgency detection
  if (/(?:within\s+(?:24|12|48)\s+hours|immediate(?:ly)?|urgent|offer\s+expires|act\s+now|forfeit\s+this\s+offer)/i.test(text)) {
    urgency = 80;
    flags.push({
      flag: 'High Pressure Deadline',
      severity: 'HIGH',
      explanation: 'Text contains urgency phrasing demanding immediate acceptance within an artificially short deadline.'
    });
  }

  // 2. Disproportionate compensation lure
  if (/(?:\$([5-9][0-9]|[1-9][0-9]{2,})\s*(?:\/hr|\s+per\s+hour)|\$[3-9],[0-9]{3}\s+weekly|no\s+experience.*\$[0-9]{2,})/i.test(text)) {
    salaryRealism = 20;
    flags.push({
      flag: 'Disproportionate Compensation Lure',
      severity: 'HIGH',
      explanation: 'Compensation offered appears disproportionately high for minimal requirements or entry-level roles.'
    });
  }

  // 3. Fake check / equipment schemes
  if (/(?:check|cheque)[\s\S]{0,80}?(?:deposit|vendor|equipment|materials)/i.test(text)) {
    flags.push({
      flag: 'Advance Check & Equipment Anomaly',
      severity: 'CRITICAL',
      explanation: 'Document instructs candidate to deposit an advance check and transfer funds to a third-party vendor.'
    });
  }

  // 4. Consumer chat recruitment
  if (/(?:telegram|whatsapp|signal)[\s\S]{0,60}?(?:interview|contact|hr|manager|message)/i.test(text)) {
    flags.push({
      flag: 'Unverified Chat Platform Recruitment',
      severity: 'HIGH',
      explanation: 'Formal employment screening conducted via consumer messaging app rather than corporate email or enterprise ATS.'
    });
  }

  // 5. Irreversible payments / crypto
  if (/(?:zelle|venmo|cash\s?app|western\s+union|bitcoin|btc|usdt|crypto)/i.test(text)) {
    flags.push({
      flag: 'Irreversible P2P / Crypto Payment Request',
      severity: 'CRITICAL',
      explanation: 'Communication requests funds via peer-to-peer applications or cryptocurrency.'
    });
  }

  const advice = [
    'Verify the offer by contacting the hiring company directly through contact details on their official public website.',
    'Never deposit advance checks or forward funds to third-party equipment vendors.',
    'Confirm recruiter credentials independently on professional platforms like LinkedIn.'
  ];

  return {
    urgencyScore: urgency,
    salaryRealismScore: salaryRealism,
    deceptionFlags: flags,
    remediationAdvice: advice,
    isFallback: true,
    fallbackReason: reason
  };
}

/**
 * Performs semantic forensic analysis of document text using Gemini
 * @param {string} rawText - Document text to analyze
 * @returns {Promise<{ urgencyScore: number, salaryRealismScore: number, deceptionFlags: Array, remediationAdvice: string[] }>}
 */
export async function analyzeDocumentSemantics(rawText) {
  if (!rawText || typeof rawText !== 'string' || !rawText.trim()) {
    return getFallbackSemantics('', 'Empty or invalid input text');
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey.trim() === '') {
    return getFallbackSemantics(rawText, 'GEMINI_API_KEY is not configured in environment');
  }

  try {
    const ai = new GoogleGenAI({ apiKey });

    const prompt = `You are PhishGuard, a Senior Cybersecurity and Employment Fraud Forensic Investigator.
Analyze the following job offer letter, recruitment email, or interview communication for deception, manipulation, and phishing tactics.

Evaluate specifically:
1. Urgency Score (0 to 100): High score if candidate is pressured with short artificial deadlines (e.g. 24h expiration, immediate sign). Low score if normal professional deliberation time is provided.
2. Salary Realism Score (0 to 100): Realism of compensation. A score near 0 means wildly inflated, unrealistic pay meant as bait (e.g. $80/hr data entry, $150k no experience). A score near 100 means standard, realistic industry rate.
3. Deception Flags: Specific red flags such as generic greeting, lack of job responsibilities, odd corporate email domains, unusual syntax, or fake equipment purchasing.
4. Remediation Advice: 3-5 concrete, actionable steps the recipient must take immediately.

Text to inspect:
---
${rawText.slice(0, 15000)}
---`;

    let responseText = null;
    let lastError = null;

    for (const modelName of CANDIDATE_MODELS) {
      try {
        const response = await ai.models.generateContent({
          model: modelName,
          contents: prompt,
          config: {
            responseMimeType: 'application/json',
            responseSchema: SEMANTIC_ANALYSIS_SCHEMA,
            temperature: 0.1
          }
        });

        if (response && response.text) {
          responseText = response.text;
          break;
        }
      } catch (modelErr) {
        lastError = modelErr;
        // If 404 or unsupported model, try next candidate model
        if (modelErr.message?.includes('404') || modelErr.message?.includes('not found')) {
          continue;
        }
        throw modelErr;
      }
    }

    if (!responseText) {
      throw lastError || new Error('All Gemini candidate models failed to return content');
    }

    const parsed = JSON.parse(responseText);

    return {
      urgencyScore: typeof parsed.urgencyScore === 'number' ? Math.max(0, Math.min(100, Math.round(parsed.urgencyScore))) : 0,
      salaryRealismScore: typeof parsed.salaryRealismScore === 'number' ? Math.max(0, Math.min(100, Math.round(parsed.salaryRealismScore))) : 50,
      deceptionFlags: Array.isArray(parsed.deceptionFlags) ? parsed.deceptionFlags : [],
      remediationAdvice: Array.isArray(parsed.remediationAdvice) ? parsed.remediationAdvice : [],
      isFallback: false
    };

  } catch (error) {
    console.error('[Gemini Service] Analysis error, using fallback semantics:', error.message);
    return getFallbackSemantics(rawText, error.message);
  }
}

export default {
  analyzeDocumentSemantics,
  getFallbackSemantics,
  SEMANTIC_ANALYSIS_SCHEMA
};
