/**
 * Optional client-side "vault": the key is derived from a passphrase with the Web Crypto
 * API and never leaves the caller's memory. A server storing vault blobs cannot decrypt
 * them. There is no key escrow: a forgotten passphrase means the data is gone.
 *
 * Blob format: "pv1:" + base64( iv(12) || AES-256-GCM ciphertext+tag ).
 * Works unchanged in browsers and in Node (globalThis.crypto).
 */

const KDF = 'PBKDF2'
const HASH = 'SHA-256'
const ITERATIONS = 310000 // OWASP PBKDF2-HMAC-SHA256 recommendation floor
const KEY_BITS = 256
const IV_BYTES = 12
const PREFIX = 'pv1:'
const VERIFIER_PLAINTEXT = 'pii-vault-verifier-v1'

const enc = new TextEncoder()
const dec = new TextDecoder()

function subtle() {
  const s = globalThis.crypto?.subtle
  if (!s) throw new Error('Web Crypto (SubtleCrypto) is unavailable in this context.')
  return s
}

function toB64(bytes) {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

function fromB64(b64) {
  const s = atob(b64)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

export function randomSaltB64() {
  const salt = new Uint8Array(16)
  globalThis.crypto.getRandomValues(salt)
  return toB64(salt)
}

/** Derive a non-extractable AES-GCM key from passphrase + salt. */
export async function deriveKey(passphrase, saltB64, iterations = ITERATIONS) {
  const baseKey = await subtle().importKey('raw', enc.encode(passphrase), KDF, false, ['deriveKey'])
  return subtle().deriveKey(
    { name: KDF, salt: fromB64(saltB64), iterations, hash: HASH },
    baseKey,
    { name: 'AES-GCM', length: KEY_BITS },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function encryptString(key, plaintext) {
  const iv = new Uint8Array(IV_BYTES)
  globalThis.crypto.getRandomValues(iv)
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext))
  const packed = new Uint8Array(IV_BYTES + ct.byteLength)
  packed.set(iv, 0)
  packed.set(new Uint8Array(ct), IV_BYTES)
  return PREFIX + toB64(packed)
}

async function decryptString(key, blob) {
  if (typeof blob !== 'string' || !blob.startsWith(PREFIX)) throw new Error('Not a vault blob.')
  const packed = fromB64(blob.slice(PREFIX.length))
  const pt = await subtle().decrypt(
    { name: 'AES-GCM', iv: packed.subarray(0, IV_BYTES) },
    key,
    packed.subarray(IV_BYTES),
  )
  return dec.decode(pt)
}

/** Encrypt an object of fields into one blob. Empty fields are dropped. */
export async function encryptRecord(key, fields) {
  const clean = {}
  for (const [k, v] of Object.entries(fields || {})) {
    if (v != null && String(v) !== '') clean[k] = String(v)
  }
  return encryptString(key, JSON.stringify(clean))
}

/** Decrypt a blob into an object. Throws on wrong key or tampering. */
export async function decryptRecord(key, blob) {
  if (blob == null || blob === '') return {}
  return JSON.parse(await decryptString(key, blob))
}

/** Non-secret verifier so an unlock can confirm the passphrase without any server help. */
export async function makeVerifier(key) {
  return encryptString(key, VERIFIER_PLAINTEXT)
}

export async function checkVerifier(key, verifierBlob) {
  try {
    return (await decryptString(key, verifierBlob)) === VERIFIER_PLAINTEXT
  } catch {
    return false
  }
}
