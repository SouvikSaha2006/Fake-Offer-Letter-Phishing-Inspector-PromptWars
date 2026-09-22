/**
 * Gemini Semantic Analysis Service for PhishGuard Inspector
 * Uses @google/genai with gemini-1.5-flash and strict JSON schema validation
 * to evaluate document semantics, urgency, salary realism, and deception flags.
 */

import { GoogleGenAI, Type } from '@google/genai';
import dotenv from 'dotenv';

dotenv.config();

const MODEL_NAME = 'gemini-1.5-flash';

// Strict JSON schema for forensic semantic analysis
const SEMANTIC_ANALYSIS_SCHEMA = {
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
 * Fallback semantic analysis when Gemini API is unavailable or unconfigured
 * @param {string} rawText
 * @param {string} [reason='API Key not provided or network failure']
 * @returns {object}
 */
export function getFallbackSemantics(rawText, reason = 'Gemini API unavailable') {
  const flags = [];
  let urgency = 10;
  let salaryRealism = 70;

  // Basic fallback heuristics
  if (/(?:within\s+24\s+hours|immediately|urgent|offer\s+expires)/i.test(rawText)) {
    urgency = 75;
    flags.push({
      flag: 'High Pressure Deadline',
      severity: 'HIGH',
      explanation: 'Text contains urgency phrasing demanding immediate acceptance.'
    });
  }

  if (/(?:\$1[0-9]{2,}\/hr|\$5000\s+weekly|no\s+experience.*\$[0-9]{2,})/i.test(rawText)) {
    salaryRealism = 25;
    flags.push({
      flag: 'Disproportionate Compensation',
      severity: 'MEDIUM',
      explanation: 'Compensation offered appears disproportionately high for entry-level or minimal interview requirements.'
    });
  }

  return {
    urgencyScore: urgency,
    salaryRealismScore: salaryRealism,
    deceptionFlags: flags,
    remediationAdvice: [
      'Contact the hiring company directly using contact info from their official website, not links in this document.',
      'Never send funds, purchase supplies from designated vendors, or deposit cashier checks from prospective employers.',
      'Verify the recruiter identity independently on LinkedIn and ensure communication originated from corporate domain emails.'
    ],
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

    const response = await ai.models.generateContent({
      model: MODEL_NAME,
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: SEMANTIC_ANALYSIS_SCHEMA,
        temperature: 0.1
      }
    });

    const responseText = response.text;
    if (!responseText) {
      throw new Error('Gemini returned an empty response');
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
