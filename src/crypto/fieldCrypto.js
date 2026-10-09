/**
 * Field-level protection for personal data. Two deliberately separate primitives:
 *
 *  1. encryptField / decryptField - AES-256-GCM. Confidentiality + tamper detection.
 *     Output is non-deterministic (fresh random IV per call), so a database dump
 *     reveals nothing and equal plaintexts never produce equal ciphertexts.
 *     A caller-supplied `context` string (e.g. "customers:<id>:email") is bound in as
 *     GCM additional authenticated data, so a ciphertext copied into another column or
 *     another row fails authentication instead of decrypting.
 *
 *  2. blindIndex - HMAC-SHA256 under a SEPARATE secret. Deterministic and one-way. It is
 *     the only way to look a record up by an encrypted value: WHERE email_bidx = :hash.
 *     Equality only - no LIKE, no ranges, no sorting. Each field has its own `domain`
 *     so the same string in two different columns yields unrelated indexes.
 *
 * Key custody: both secrets come from the environment (base64, 32 bytes each) and are
 * never written to the database. Losing the encryption key makes the data unrecoverable.
 * Generate them with `npm run genkeys` (uses crypto.randomBytes).
 */

import crypto from 'node:crypto'

const ALGO = 'aes-256-gcm'
const PREFIX = 'enc:v1:'
const IV_BYTES = 12 // GCM standard
const TAG_BYTES = 16

export class CryptoNotConfiguredError extends Error {
  constructor(message) {
    super(message)
    this.name = 'CryptoNotConfiguredError'
  }
}

export class DecryptError extends Error {
  constructor(message) {
    super(message)
    this.name = 'DecryptError'
  }
}

function loadSecret(env, name) {
  const raw = env[name]
  if (!raw || !String(raw).trim()) {
    throw new CryptoNotConfiguredError(
      `${name} is not set. Run "npm run genkeys" or provide 32 random bytes, base64-encoded.`,
    )
  }
  const buf = Buffer.from(String(raw).trim(), 'base64')
  if (buf.length !== 32) {
    throw new CryptoNotConfiguredError(`${name} must decode to exactly 32 bytes (got ${buf.length}).`)
  }
  return buf
}

/**
 * Build a crypto instance from an env-like object (defaults to process.env).
 * Throws CryptoNotConfiguredError up front rather than failing on first use.
 */
export function createFieldCrypto(env = process.env) {
  const encKey = loadSecret(env, 'PII_ENC_KEY')
  const bidxKey = loadSecret(env, 'PII_BIDX_KEY')
  if (encKey.equals(bidxKey)) {
    throw new CryptoNotConfiguredError('PII_ENC_KEY and PII_BIDX_KEY must be different secrets.')
  }

  /** Encrypt one field. null / undefined / '' -> null so "no value" stays distinguishable. */
  function encryptField(plain, context = '') {
    if (plain == null) return null
    const s = String(plain)
    if (s === '') return null

    const iv = crypto.randomBytes(IV_BYTES)
    const cipher = crypto.createCipheriv(ALGO, encKey, iv)
    cipher.setAAD(Buffer.from(context, 'utf8'))
    const ct = Buffer.concat([cipher.update(s, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return PREFIX + Buffer.concat([iv, tag, ct]).toString('base64')
  }

  /** Decrypt a blob from encryptField. Throws DecryptError on tamper / wrong key / wrong context. */
  function decryptField(blob, context = '') {
    if (blob == null || blob === '') return null
    const s = String(blob)
    if (!s.startsWith(PREFIX)) {
      throw new DecryptError('Value is not an encrypted field (missing enc:v1: prefix).')
    }
    const packed = Buffer.from(s.slice(PREFIX.length), 'base64')
    if (packed.length < IV_BYTES + TAG_BYTES + 1) {
      throw new DecryptError('Encrypted field is truncated.')
    }
    const iv = packed.subarray(0, IV_BYTES)
    const tag = packed.subarray(IV_BYTES, IV_BYTES + TAG_BYTES)
    const ct = packed.subarray(IV_BYTES + TAG_BYTES)

    try {
      const decipher = crypto.createDecipheriv(ALGO, encKey, iv)
      decipher.setAAD(Buffer.from(context, 'utf8'))
      decipher.setAuthTag(tag)
      return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8')
    } catch {
      throw new DecryptError('Decryption failed: wrong key, wrong context, or the ciphertext was modified.')
    }
  }

  /**
   * Deterministic lookup key. `value` must already be normalized by the caller
   * (see normalize.js) or equal inputs will not match. Returns null for empty input.
   */
  function blindIndex(value, domain) {
    if (value == null) return null
    const s = String(value)
    if (s === '') return null
    if (!domain) throw new Error('blindIndex requires a domain.')
    // NUL separator: a domain can never be confused with a prefix of the value.
    return crypto.createHmac('sha256', bidxKey).update(`${domain}\0${s}`, 'utf8').digest('hex')
  }

  return { encryptField, decryptField, blindIndex }
}
