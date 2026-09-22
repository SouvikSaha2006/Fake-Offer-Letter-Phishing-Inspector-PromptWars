/**
 * Domain Checker Service for PhishGuard Inspector
 * Extracts domains from text, identifies free/disposable mail providers,
 * and queries ICANN RDAP to determine domain age and risk.
 */

// Known free and disposable email domains
export const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com',
  'googlemail.com',
  'yahoo.com',
  'ymail.com',
  'rocketmail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'proton.me',
  'protonmail.com',
  'zoho.com',
  'zohomail.com',
  'mail.com',
  'gmx.com',
  'gmx.net',
  'aol.com',
  'fastmail.com',
  'tutanota.com',
  'tuta.com',
  'yandex.com',
  'mailinator.com',
  'tempmail.com',
  '10minutemail.com',
  'guerrillamail.com',
  'sharklasers.com',
  'throwawaymail.com'
]);

// Ignored non-domain extensions often captured by loose URL regexes
const IGNORED_EXTENSIONS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp',
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv', 'txt',
  'zip', 'tar', 'gz', 'mp4', 'mp3', 'json', 'xml', 'js', 'css'
]);

// In-memory cache for RDAP results to avoid redundant network hits (TTL: 1 hour)
const rdapCache = new Map();
const CACHE_TTL_MS = 60 * 60 * 1000;

/**
 * Extracts unique domain candidates from raw text (emails and URLs)
 * @param {string} text - Raw input text
 * @returns {string[]} - Array of unique normalized domain strings
 */
export function extractDomains(text) {
  if (!text || typeof text !== 'string') return [];

  const domains = new Set();

  // 1. Extract from email addresses (e.g. hr@company.com)
  const emailRegex = /\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/gi;
  let match;
  while ((match = emailRegex.exec(text)) !== null) {
    if (match[1]) {
      domains.add(cleanDomain(match[1]));
    }
  }

  // 2. Extract from URLs and links (e.g. https://careers.company.com/job/123)
  const urlRegex = /(?:https?:\/\/|www\.)([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?(?:\/[^\s)\]"'>]*)?/gi;
  while ((match = urlRegex.exec(text)) !== null) {
    if (match[1]) {
      domains.add(cleanDomain(match[1]));
    }
  }

  // Filter out invalid candidates
  return Array.from(domains).filter(isValidDomain);
}

/**
 * Normalizes and strips leading www and trailing punctuation
 * @param {string} domain
 * @returns {string}
 */
export function cleanDomain(domain) {
  return domain
    .toLowerCase()
    .replace(/^www\./i, '')
    .replace(/[.,;:!?/]+$/, '')
    .trim();
}

/**
 * Validates whether string is a plausible domain
 * @param {string} domain
 * @returns {boolean}
 */
export function isValidDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  if (domain.length < 3 || domain.length > 253) return false;
  if (!domain.includes('.')) return false;

  const parts = domain.split('.');
  const tld = parts[parts.length - 1];

  // Disregard non-TLDs or file extensions
  if (!tld || tld.length < 2 || IGNORED_EXTENSIONS.has(tld)) return false;

  // Ignore IP addresses and local domains
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain)) return false;
  if (domain.endsWith('.local') || domain === 'localhost') return false;

  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain);
}

/**
 * Calculates risk score based on domain age in days
 * @param {number|null} ageInDays
 * @returns {number} - 0 to 100
 */
function calculateAgeRiskScore(ageInDays) {
  if (ageInDays === null || ageInDays === undefined) return 30; // Unverified age
  if (ageInDays < 14) return 95;  // Extreme risk (freshly minted scam domain)
  if (ageInDays < 30) return 85;  // High risk
  if (ageInDays < 90) return 60;  // Medium-high risk
  if (ageInDays < 180) return 35; // Moderate risk
  if (ageInDays < 365) return 20; // Low-moderate risk
  return 5;                       // Established domain (> 1 year)
}

/**
 * Queries ICANN's open RDAP endpoint (https://rdap.org/domain/{domain})
 * with timeout handling and graceful fallback.
 * @param {string} domain - Domain name to inspect
 * @param {number} [timeoutMs=6500] - Request timeout in milliseconds
 * @returns {Promise<{ domain: string, ageInDays: number|null, registrationDate: string|null, isFreeProvider: boolean, riskScore: number, status: string, details: string }>}
 */
export async function checkDomain(domain, timeoutMs = 8000) {
  const normalizedDomain = cleanDomain(domain);

  // Check if it is a known free email provider
  if (FREE_EMAIL_PROVIDERS.has(normalizedDomain)) {
    return {
      domain: normalizedDomain,
      ageInDays: null,
      registrationDate: null,
      isFreeProvider: true,
      riskScore: 70, // Corporate offer letters utilizing free consumer emails is a major red flag
      status: 'free_provider',
      details: 'Free consumer email provider masquerading as corporate domain'
    };
  }

  // Check memory cache
  const cached = rdapCache.get(normalizedDomain);
  if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) {
    return { ...cached.data };
  }

  const result = {
    domain: normalizedDomain,
    ageInDays: null,
    registrationDate: null,
    isFreeProvider: false,
    riskScore: 0,
    status: 'unknown',
    details: ''
  };

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(normalizedDomain)}`, {
      method: 'GET',
      headers: {
        'User-Agent': 'PhishGuard-Inspector/1.0',
        'Accept': 'application/rdap+json'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.status === 404) {
      result.status = 'not_found';
      result.riskScore = 55;
      result.details = 'Domain registration record not found in RDAP registry';
      rdapCache.set(normalizedDomain, { data: result, cachedAt: Date.now() });
      return result;
    }

    if (!response.ok) {
      result.status = 'lookup_failed';
      result.riskScore = 20;
      result.details = `RDAP registry returned HTTP status ${response.status}`;
      return result;
    }

    const data = await response.json();
    let regDateStr = null;

    if (Array.isArray(data.events)) {
      const regEvent = data.events.find(e => 
        e.eventAction === 'registration' || 
        e.eventAction === 'registered' || 
        e.eventAction === 'created'
      );
      if (regEvent && regEvent.eventDate) {
        regDateStr = regEvent.eventDate;
      }
    }

    if (regDateStr) {
      const regTime = new Date(regDateStr).getTime();
      const now = Date.now();
      const ageDays = Math.max(0, Math.floor((now - regTime) / (1000 * 60 * 60 * 24)));

      result.ageInDays = ageDays;
      result.registrationDate = regDateStr;
      result.riskScore = calculateAgeRiskScore(ageDays);
      result.status = 'active';
      result.details = `Domain registered ${ageDays} days ago (${new Date(regDateStr).toLocaleDateString()})`;
    } else {
      result.status = 'active_no_event';
      result.riskScore = 25;
      result.details = 'Domain active but registration timestamp unavailable';
    }

    rdapCache.set(normalizedDomain, { data: result, cachedAt: Date.now() });
    return result;

  } catch (error) {
    if (error.name === 'AbortError') {
      result.status = 'timeout';
      result.riskScore = 15;
      result.details = 'RDAP registry query timed out';
    } else {
      result.status = 'error';
      result.riskScore = 15;
      result.details = error.message || 'RDAP lookup error';
    }
    // Graceful fallback - never throws
    return result;
  }
}

/**
 * Extracts and scans all domains found in raw text
 * @param {string} rawText - Text to inspect for domains
 * @returns {Promise<{ extractedDomains: string[], results: Array, overallDomainRiskScore: number }>}
 */
export async function checkDomainsInText(rawText) {
  const extractedDomains = extractDomains(rawText);

  if (extractedDomains.length === 0) {
    return {
      extractedDomains: [],
      results: [],
      overallDomainRiskScore: 0
    };
  }

  // Run RDAP checks concurrently across extracted domains (up to 5 to avoid spamming)
  const domainsToCheck = extractedDomains.slice(0, 5);
  const results = await Promise.all(domainsToCheck.map(d => checkDomain(d)));

  // Calculate overall domain risk score as the max of individual domain risk scores
  const maxRisk = results.reduce((max, r) => Math.max(max, r.riskScore || 0), 0);

  return {
    extractedDomains,
    results,
    overallDomainRiskScore: maxRisk
  };
}

export default {
  FREE_EMAIL_PROVIDERS,
  extractDomains,
  cleanDomain,
  isValidDomain,
  checkDomain,
  checkDomainsInText
};
