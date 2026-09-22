/**
 * Scan Route for PhishGuard Inspector
 * Unified endpoint running heuristic, domain, and semantic checks concurrently.
 */

import express from 'express';
import { scanHeuristics } from '../services/heuristicEngine.js';
import { checkDomainsInText } from '../services/domainChecker.js';
import { analyzeDocumentSemantics, getFallbackSemantics } from '../services/geminiClient.js';
import { calculateScamThreatIndex } from '../utils/scoreEngine.js';

const router = express.Router();

/**
 * POST /api/scan
 * Accepts: { text: string, url?: string }
 * Returns: Comprehensive forensic analysis report and composite Scam Threat Index
 */
router.post('/scan', async (req, res) => {
  try {
    const { text = '', url = '' } = req.body || {};

    const rawContent = [text, url].filter(Boolean).join('\n\n').trim();

    if (!rawContent) {
      return res.status(400).json({
        error: 'Invalid input. Please provide document text or a URL to inspect.'
      });
    }

    // Run heuristic scanning, domain verification, and Gemini semantic analysis concurrently
    const [heuristicSettled, domainSettled, geminiSettled] = await Promise.allSettled([
      Promise.resolve(scanHeuristics(rawContent)),
      checkDomainsInText(rawContent),
      analyzeDocumentSemantics(rawContent)
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
      : getFallbackSemantics(rawContent, 'Semantic analysis pipeline error');

    // Compute composite threat score and itemized evidence
    const scoreReport = calculateScamThreatIndex({
      domainRisk: domainData.overallDomainRiskScore,
      paymentRisk: heuristicData.paymentRiskScore,
      proceduralRisk: heuristicData.proceduralRiskScore,
      geminiScore: geminiData,
      rawAnalysis: {
        detectedPatterns: heuristicData.detectedPatterns,
        domainResults: domainData.results,
        deceptionFlags: geminiData.deceptionFlags
      }
    });

    return res.status(200).json({
      success: true,
      scamThreatIndex: scoreReport.compositeScore,
      riskCategory: scoreReport.riskCategory,
      breakdown: scoreReport.breakdown,
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
      },
      itemizedEvidence: scoreReport.itemizedEvidence,
      remediationAdvice: geminiData.remediationAdvice,
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
