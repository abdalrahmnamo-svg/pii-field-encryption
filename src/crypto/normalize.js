/**
 * Canonical forms used BEFORE hashing or comparing. Blind indexes are exact-match, so
 * "Alice@Example.com " and "alice@example.com" must reduce to the same string.
 */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

/** Trim + lowercase. Returns null if it does not look like an email. */
export function normalizeEmail(input) {
  if (input == null) return null
  const s = String(input).trim().toLowerCase()
  return EMAIL_RE.test(s) ? s : null
}

/**
 * Digits only (7-15, per E.164 length bounds). "+1-555-0142" and "1 (555) 0142" both
 * become "15550142". Callers must include the country code to match across formats.
 * Returns null if the result is not a plausible phone number.
 */
export function normalizePhone(input) {
  if (input == null) return null
  const digits = String(input).replace(/\D/g, '')
  return digits.length >= 7 && digits.length <= 15 ? digits : null
}
