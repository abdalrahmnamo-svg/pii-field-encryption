/** Free-text redaction: replaces emails, phone-like numbers, and (optionally) a surname. */

const EMAIL_RE = /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g
// Phone-ish: optional +, then 8-15 digits possibly separated by space/dash/().
const PHONE_RE = /(\+?\d[\d\s().-]{7,}\d)/g

function looksLikePhone(m) {
  const trimmed = String(m).trim()
  const digits = trimmed.replace(/\D/g, '')
  if (digits.length < 8) return false
  // ISO dates (2026-06-20) are not phones
  if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) return false
  if (trimmed.startsWith('+')) return true
  if (digits.length >= 10) return true
  if (/^0\d/.test(digits)) return true
  // Separators suggest a formatted phone, not a bare score or id
  return /[\s().-]/.test(trimmed) && digits.length >= 8
}

/**
 * Redact a string. When `customerName` has more than one word, every word after the
 * first (the surname parts) is replaced with [name]; the first name is kept.
 */
export function redactText(text, { customerName } = {}) {
  if (text == null) return text
  let s = String(text)
  s = s.replace(EMAIL_RE, '[email]')
  s = s.replace(PHONE_RE, (m) => (looksLikePhone(m) ? '[phone]' : m))
  if (customerName && String(customerName).trim().includes(' ')) {
    const parts = String(customerName).trim().split(/\s+/)
    for (const surname of parts.slice(1)) {
      if (surname.length >= 2) {
        s = s.replace(new RegExp(`\\b${surname.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi'), '[name]')
      }
    }
  }
  return s
}
