/**
 * Display-time masking. Runs AFTER decryption, on the way out of the API.
 *
 *   DB            -> ciphertext (useless without the key)
 *   API default   -> these masks (enough to recognise a record, not to identify a person)
 *   Admin reveal  -> plaintext
 *
 * Pure functions with no Node-only imports, so the same module can run in a browser.
 */

import { redactText } from '../redact.js'

const DOT = '•'

/** "Ada Grace Lovelace" -> "Ada G. L."; single word -> first two letters + dots. */
export function maskName(name) {
  const s = String(name ?? '').trim()
  if (!s) return null
  const parts = s.split(/\s+/)
  if (parts.length === 1) {
    const w = parts[0]
    return w.length <= 2 ? w : `${w.slice(0, 2)}${DOT.repeat(Math.min(w.length - 2, 6))}`
  }
  return [parts[0], ...parts.slice(1).map((p) => `${p.charAt(0).toUpperCase()}.`)].join(' ')
}

/** Only the last 3 digits stay visible; every other digit becomes a dot. */
export function maskPhone(phone) {
  const s = String(phone ?? '').trim()
  if (!s) return null
  const digits = s.replace(/\D/g, '')
  if (digits.length <= 4) return DOT.repeat(digits.length)
  return `${DOT.repeat(digits.length - 3)}${digits.slice(-3)}`
}

/** "customer0042@example.com" -> "cu...@example.com" (first two chars kept). */
export function maskEmail(email) {
  const s = String(email ?? '').trim()
  if (!s) return null
  if (!s.includes('@')) return DOT.repeat(3)
  const at = s.lastIndexOf('@')
  const local = s.slice(0, at)
  const domain = s.slice(at + 1)
  const head = local.slice(0, Math.min(2, Math.max(local.length - 1, 0)))
  return `${head}${DOT.repeat(Math.max(local.length - head.length, 3))}@${domain}`
}

/** Free text: strip embedded emails/phones (and surname parts of `customerName`). */
export function maskFreeText(text, { customerName } = {}) {
  if (text == null || text === '') return null
  return redactText(String(text), { customerName })
}
