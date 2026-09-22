/**
 * Heuristic Engine for PhishGuard Inspector
 * Deterministic regex scanner for detecting payment, deposit, and recruitment anomalies.
 * Enforces zero-hallucination detection of high-risk employment fraud indicators.
 */

export const RISK_LEVELS = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW'
};

const PATTERN_RULES = [
  // 1. Cashier check / check deposit + equipment purchase schemes (Weight: 95)
  {
    id: 'CHECK_EQUIPMENT_SCAM',
    category: 'PAYMENT',
    severity: RISK_LEVELS.CRITICAL,
    weight: 95,
    title: 'Fake Check & Equipment Purchase Scheme',
    explanation: 'Legitimate employers provide equipment directly or pay vendors directly. Sending a check and demanding the candidate deposit it to purchase equipment or refund the remainder is a definitive fake check fraud signature.',
    patterns: [
      /(?:cashier(?:'s)?\s+check|certified\s+check|paper\s+check|cheque|e-?check)[\s\S]{0,140}?(?:deposit|equipment|office\s+setup|supplies|vendor|hardware|workstation|laptop|materials)/i,
      /(?:deposit|clear)[\s\S]{0,120}?(?:check|cheque)[\s\S]{0,120}?(?:forward|send|wire|transfer|buy|purchase|vendor|refund)/i,
      /(?:send|mail|issue|deliver)[\s\S]{0,50}?(?:you\s+)?(?:a\s+)?(?:check|cheque)[\s\S]{0,90}?(?:buy|purchase|pay|order)[\s\S]{0,90}?(?:equipment|supplies|materials|software|laptop|vendor)/i,
      /(?:approved|accredited|designated|official)\s+vendor[\s\S]{0,90}?(?:check|equipment|supplies|purchase|order)/i,
      /(?:home\s+office|workstation)[\s\S]{0,70}?(?:funds?|allowance)[\s\S]{0,70}?(?:check|cheque|wire)/i
    ]
  },

  // 2. Cryptocurrency demands (Weight: 80)
  {
    id: 'CRYPTOCURRENCY_DEMAND',
    category: 'PAYMENT',
    severity: RISK_LEVELS.CRITICAL,
    weight: 80,
    title: 'Cryptocurrency Demand or Wallet Deposit',
    explanation: 'Legitimate employers never demand job applicants or employees to deposit, send, or convert company funds into cryptocurrency (Bitcoin, USDT, Ethereum) or use Bitcoin ATMs.',
    patterns: [
      /\b(?:Bitcoin|BTC|Ethereum|ETH|USDT|Tether|Binance\s+USD|BUSD|Solana|SOL|Dogecoin)\b/i,
      /\b(?:crypto(?:currency)?|crypto\s+wallet|crypto\s+deposit|crypto\s+address|blockchain\s+transfer|bitcoin\s+atm|bitcoin\s+kiosk|seed\s+phrase|private\s+key)\b/i,
      /\b(?:wallet\s+address[:\s]+[0-9a-zA-Z]{26,45}|0x[a-fA-F0-9]{40})\b/i,
      /(?:deposit|transfer|send|pay)\s+(?:via|with|in)\s+(?:crypto|bitcoin|usdt|digital\s+currency)/i
    ]
  },

  // 3. Advance payment / application fees / processing deposits (Weight: 75)
  {
    id: 'ADVANCE_FEE_DEMAND',
    category: 'PAYMENT',
    severity: RISK_LEVELS.CRITICAL,
    weight: 75,
    title: 'Upfront Fee or Processing Deposit Required',
    explanation: 'Legitimate employers never require candidates to pay application fees, background check fees, training fees, or refundable deposits prior to or as a condition of employment.',
    patterns: [
      /(?:application|processing|registration|enrollment|onboarding|training|background\s+check|verification|orientation)\s+fee/i,
      /(?:refundable\s+deposit|security\s+deposit|equipment\s+deposit|clearance\s+fee|stamp\s+duty\s+fee|visa\s+(?:processing\s+)?fee)/i,
      /(?:pay|deposit|transfer|send)\s+(?:\$|USD|EUR|GBP|INR|CAD|AUD|\b\d+\s*(?:dollars|usd|euros))\s+(?:before|prior\s+to|for\s+your|in\s+order\s+to)\s+(?:start|equipment|dispatch|training|onboarding|offer|background)/i,
      /(?:candidate|applicant|employee)\s+must\s+(?:pay|bear|cover|deposit|transfer|fund)\s+(?:the\s+cost|the\s+fee|\$|\d+)/i,
      /(?:purchase|buy)\s+(?:your\s+own|the)\s+(?:software\s+license|tools|training\s+kit|id\s+card|uniform)\s+(?:first|in\s+advance|upfront)/i
    ]
  },

  // 4. Wire transfers & P2P payment requests (Weight: 65)
  {
    id: 'WIRE_TRANSFER_DEMAND',
    category: 'PAYMENT',
    severity: RISK_LEVELS.HIGH,
    weight: 65,
    title: 'Irreversible Wire Transfer or P2P Payment Demand',
    explanation: 'Demanding payments via peer-to-peer apps (Zelle, Venmo, Cash App, Western Union, MoneyGram) indicates fraud because transactions are irreversible and bypass corporate accounting channels.',
    patterns: [
      /\b(?:Western\s+Union|MoneyGram|Zelle|Venmo|Cash\s?App|Revolut)\b/i,
      /\b(?:wire\s+transfer|direct\s+wire|bank-to-bank\s+wire|interbank\s+wire)\b/i,
      /\bPayPal\s+(?:friends\s+and\s+family|personal\s+(?:transfer|payment))\b/i,
      /(?:transfer|send|wire)\s+funds?\s+(?:via|through|using)\s+(?:wire|zelle|venmo|cashapp|moneygram)/i
    ]
  },

  // 5. Recruitment channel anomalies (Weight: 50)
  {
    id: 'RECRUITMENT_CHANNEL_ANOMALY',
    category: 'PROCEDURAL',
    severity: RISK_LEVELS.HIGH,
    weight: 50,
    title: 'Suspicious Messaging Platform Recruitment',
    explanation: 'Recruitment and formal interviews conducted strictly over consumer chat applications (Telegram, WhatsApp, Signal) without company-domain email, corporate ATS, or verified video interviews is a primary recruitment scam indicator.',
    patterns: [
      /(?:interview|contact|reach|connect|message|chat|hr|recruiter)[\s\S]{0,60}?(?:telegram|whatsapp|signal|viber|skype\s+chat|wechat|discord)/i,
      /(?:telegram|whatsapp|signal|viber|skype\s+chat|wechat|discord)[\s\S]{0,60}?(?:interview|contact|screening|assessment|offer|hiring\s+manager)/i,
      /(?:download|install)\s+(?:telegram|signal|whatsapp)\s+(?:for|to\s+conduct|to\s+begin)\s+(?:the\s+)?(?:interview|screening)/i,
      /(?:telegram|whatsapp)\s+(?:handle|username|number)\s*[:@]/i,
      /\b(?:t\.me\/[a-zA-Z0-9_]+|wa\.me\/[0-9]+)\b/i
    ]
  },

  // 6. Urgency and high-pressure tactics (Weight: 30)
  {
    id: 'URGENCY_PRESSURE_TACTIC',
    category: 'PROCEDURAL',
    severity: RISK_LEVELS.MEDIUM,
    weight: 30,
    title: 'Artificial Urgency or Coercive Deadline',
    explanation: 'Fraudsters manufacture urgent deadlines (e.g. 24 hours to sign or deposit money) to prevent victims from conducting independent verification.',
    patterns: [
      /(?:must\s+be\s+signed|sign\s+and\s+return|valid\s+only|offer\s+expires|immediate\s+acceptance|act\s+immediately)\s+(?:within|in)\s+(?:24|12|48|2|3|4|6)\s*(?:hours|hrs)/i,
      /(?:strictly\s+confidential|do\s+not\s+disclose|keep\s+this\s+confidential\s+until).*?(?:offer|job|process)/i,
      /(?:first\s+come\s+first\s+served|limited\s+slots\s+available\s+today)/i
    ]
  },

  // 7. Premature sensitive financial data exploitation (Weight: 50)
  {
    id: 'SENSITIVE_DATA_EXPLOITATION',
    category: 'PROCEDURAL',
    severity: RISK_LEVELS.CRITICAL,
    weight: 50,
    title: 'Premature Financial Credential Request',
    explanation: 'Demanding online banking logins, PINs, or debit/credit card security codes during recruitment is fraudulent.',
    patterns: [
      /\b(?:bank\s+login|online\s+banking\s+password|pin\s+number|card\s+security\s+code|cvv2?)\b/i,
      /(?:two-factor|2fa|otp|verification\s+code)[\s\S]{0,40}?(?:send|provide|share|disclose)/i,
      /(?:send|provide)\s+(?:a\s+picture|photo|front\s+and\s+back)\s+of\s+your\s+(?:credit\s+card|debit\s+card)/i
    ]
  }
];

/**
 * Extracts a concise matched context snippet around the regex match
 * @param {string} text - The input text
 * @param {RegExpMatchArray} match - The regex match result
 * @returns {string} - Cleaned context snippet
 */
function extractSnippet(text, match) {
  if (!match || typeof match.index !== 'number') return '';
  const matchLength = match[0].length;
  const start = Math.max(0, match.index - 40);
  const end = Math.min(text.length, match.index + matchLength + 40);
  let snippet = text.slice(start, end).replace(/\s+/g, ' ').trim();
  if (start > 0) snippet = '...' + snippet;
  if (end < text.length) snippet = snippet + '...';
  return snippet;
}

/**
 * Analyzes text using heuristic regex scanners
 * @param {string} rawText - Offer letter, email, or message body to analyze
 * @returns {{ detectedPatterns: Array, paymentRiskScore: number, proceduralRiskScore: number }}
 */
export function scanHeuristics(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    return {
      detectedPatterns: [],
      paymentRiskScore: 0,
      proceduralRiskScore: 0
    };
  }

  const detectedPatterns = [];
  let rawPaymentScore = 0;
  let rawProceduralScore = 0;

  for (const rule of PATTERN_RULES) {
    let ruleMatched = false;
    let snippet = '';
    let matchedText = '';

    for (const pattern of rule.patterns) {
      const match = rawText.match(pattern);
      if (match) {
        ruleMatched = true;
        matchedText = match[0].replace(/\s+/g, ' ').trim();
        snippet = extractSnippet(rawText, match);
        break;
      }
    }

    if (ruleMatched) {
      detectedPatterns.push({
        id: rule.id,
        category: rule.category,
        severity: rule.severity,
        weight: rule.weight,
        title: rule.title,
        matchedText: matchedText.length > 80 ? matchedText.slice(0, 77) + '...' : matchedText,
        snippet,
        explanation: rule.explanation
      });

      if (rule.category === 'PAYMENT') {
        rawPaymentScore += rule.weight;
      } else {
        rawProceduralScore += rule.weight;
      }
    }
  }

  // Normalize scores bounded to [0, 100]
  const paymentRiskScore = Math.min(100, Math.round(rawPaymentScore));
  const proceduralRiskScore = Math.min(100, Math.round(rawProceduralScore));

  return {
    detectedPatterns,
    paymentRiskScore,
    proceduralRiskScore
  };
}

export default {
  scanHeuristics,
  RISK_LEVELS
};
