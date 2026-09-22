/**
 * Input Sanitization & Validation Utility for PhishGuard Inspector
 * Protects against ReDoS, injection attacks, and enforces payload constraints.
 */

export const CONSTRAINTS = {
  MIN_TEXT_LENGTH: 10,
  MAX_TEXT_LENGTH: 20000,
  MAX_URL_LENGTH: 2048
};

// Dangerous non-printable ASCII control characters (excluding \t, \n, \r) and invisible unicode
const DANGEROUS_CONTROL_CHARS_REGEX = /[\u0000-\u0008\u000B-\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200D\uFEFF]/g;

/**
 * Strips dangerous control and non-printable characters while preserving safe formatting
 * @param {string} input - Raw string input
 * @returns {string} - Cleaned string
 */
export function stripControlCharacters(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(DANGEROUS_CONTROL_CHARS_REGEX, '')
    .replace(/\r\n/g, '\n')
    .trim();
}

/**
 * Validates and sanitizes scan payload inputs
 * @param {object} payload - Incoming request body
 * @param {string} [payload.text=''] - Raw document or email text
 * @param {string} [payload.url=''] - Optional URL target
 * @returns {{ isValid: boolean, error?: string, sanitizedText: string, sanitizedUrl: string, combinedContent: string }}
 */
export function validateAndSanitizeInput(payload = {}) {
  const { text = '', url = '' } = payload || {};

  if (typeof text !== 'string' && typeof url !== 'string') {
    return {
      isValid: false,
      error: 'Invalid payload type. Expected text and/or url as strings.',
      sanitizedText: '',
      sanitizedUrl: '',
      combinedContent: ''
    };
  }

  const sanitizedText = stripControlCharacters(text);
  const sanitizedUrl = stripControlCharacters(url).slice(0, CONSTRAINTS.MAX_URL_LENGTH);

  // Validate URL format if provided
  if (sanitizedUrl) {
    try {
      new URL(sanitizedUrl);
    } catch {
      return {
        isValid: false,
        error: 'Invalid target URL format. Must include protocol (e.g. https://example.com).',
        sanitizedText,
        sanitizedUrl,
        combinedContent: ''
      };
    }
  }

  const combinedContent = [sanitizedText, sanitizedUrl].filter(Boolean).join('\n\n').trim();

  // Enforce minimum bound (10 characters)
  if (combinedContent.length < CONSTRAINTS.MIN_TEXT_LENGTH) {
    return {
      isValid: false,
      error: `Input payload too short. Minimum length is ${CONSTRAINTS.MIN_TEXT_LENGTH} characters.`,
      sanitizedText,
      sanitizedUrl,
      combinedContent
    };
  }

  // Enforce maximum bound (20,000 characters)
  if (combinedContent.length > CONSTRAINTS.MAX_TEXT_LENGTH) {
    return {
      isValid: false,
      error: `Input payload exceeds maximum allowed size of ${CONSTRAINTS.MAX_TEXT_LENGTH.toLocaleString()} characters.`,
      sanitizedText,
      sanitizedUrl,
      combinedContent
    };
  }

  return {
    isValid: true,
    sanitizedText,
    sanitizedUrl,
    combinedContent
  };
}

export default {
  stripControlCharacters,
  validateAndSanitizeInput,
  CONSTRAINTS
};
