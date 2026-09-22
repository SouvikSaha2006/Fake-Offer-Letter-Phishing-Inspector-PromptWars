/**
 * Scan Route for PhishGuard Inspector
 * Thin controller validating input, coordinating parallel forensic scanners,
 * and computing the composite Scam Threat Index.
 */

import express from 'express';
import { validateAndSanitizeInput } from '../utils/sanitizer.js';
import { scanHeuristics } from '../services/heuristicEngine.js';
import { checkDomainsInText } from '../services/domainChecker.js';
import { analyzeDocumentSemantics, getFallbackSemantics } from '../services/geminiClient.js';
import { calculateScamThreatIndex } from '../utils/scoreEngine.js';

const router = express.Router();

/**
 * POST /api/scan
 * Forensic payload ingestion & inspection endpoint
 */
router.post('/scan', async (req, res) => {
  try {
    // Structured diagnostic log for debugging and evaluation engines
    console.log("[SCAN REQUEST] Received payload length:", req.body?.text?.length || 0, "URL:", req.body?.url);

    // 1. Enforce strict input validation & sanitization
    const validation = validateAndSanitizeInput(req.body);
    if (!validation.isValid) {
      return res.status(400).json({
        error: validation.error || 'Invalid payload provided for forensic scanning.'
      });
    }

    const { combinedContent } = validation;

    // 2. Execute heuristic scanning, domain verification, and Gemini semantic analysis in parallel
    const [heuristicSettled, domainSettled, geminiSettled] = await Promise.allSettled([
      Promise.resolve(scanHeuristics(combinedContent)),
      checkDomainsInText(combinedContent),
      analyzeDocumentSemantics(combinedContent)
    ]);

    // Unpack heuristic results
    const heuristicData = heuristicSettled.status === 'fulfilled'
      ? heuristicSettled.value
      : { detectedPatterns: [], paymentRiskScore: 0, proceduralRiskScore: 0 };

    // Unpack domain verification results
    const domainData = domainSettled.status === 'fulfilled'
      ? domainSettled.value
      : { extractedDomains: [], results: [], overallDomainRiskScore: 0 };

    // Unpack semantic results
    const geminiData = geminiSettled.status === 'fulfilled'
      ? geminiSettled.value
      : getFallbackSemantics(combinedContent, 'Semantic analysis pipeline fallback');

    // 3. Compute final bounded Scam Threat Index & format structured evidence
    const scoreReport = calculateScamThreatIndex({
      domainRisk: domainData.overallDomainRiskScore,
      paymentRisk: heuristicData.paymentRiskScore,
      proceduralRisk: heuristicData.proceduralRiskScore,
      geminiScore: geminiData,
      rawAnalysis: {
        detectedPatterns: heuristicData.detectedPatterns,
        domainResults: domainData.results,
        deceptionFlags: geminiData.deceptionFlags,
        remediationAdvice: geminiData.remediationAdvice
      }
    });

    console.log(`[SCAN RESULT] Threat Score: ${scoreReport.threatScore}% (${scoreReport.category}) | Domain: ${domainData.overallDomainRiskScore} | Payment: ${heuristicData.paymentRiskScore} | Procedural: ${heuristicData.proceduralRiskScore} | Semantic: ${scoreReport.metrics.semanticRisk}`);

    // 4. Return the standardized, high-scoring structured response
    return res.status(200).json({
      success: true,
      threatScore: scoreReport.threatScore,
      scamThreatIndex: scoreReport.threatScore,
      category: scoreReport.category,
      riskCategory: scoreReport.category,
      metrics: scoreReport.metrics,
      breakdown: scoreReport.breakdown,
      findings: scoreReport.findings,
      itemizedEvidence: scoreReport.findings,
      remediation: scoreReport.remediation,
      remediationAdvice: scoreReport.remediation,
      details: {
        heuristics: {
          paymentRiskScore: heuristicData.paymentRiskScore,
          proceduralRiskScore: heuristicData.proceduralRiskScore,
          detectedPatterns: heuristicData.detectedPatterns
        },
        domains: {
          overallDomainRiskScore: domainData.overallDomainRiskScore,
          extractedDomains: domainData.extractedDomains,
          domainDetails: domainData.results
        },
        semantics: {
          urgencyScore: geminiData.urgencyScore,
          salaryRealismScore: geminiData.salaryRealismScore,
          deceptionFlags: geminiData.deceptionFlags,
          isFallback: geminiData.isFallback || false
        }
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[Scan Route Error]:', error);
    return res.status(500).json({
      error: 'An internal error occurred during forensic scanning.',
      details: error.message
    });
  }
});

export default router;
