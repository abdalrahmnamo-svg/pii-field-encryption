import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { createFieldCrypto, DecryptError, CryptoNotConfiguredError } from '../src/crypto/fieldCrypto.js'
import { normalizeEmail, normalizePhone } from '../src/crypto/normalize.js'

const env = (encFill, bidxFill) => ({
  PII_ENC_KEY: Buffer.alloc(32, encFill).toString('base64'),
  PII_BIDX_KEY: Buffer.alloc(32, bidxFill).toString('base64'),
})
const fc = createFieldCrypto(env(1, 2))

describe('encryption', () => {
  test('round-trips a value', () => {
    const blob = fc.encryptField('Customer 0042', 'ctx')
    assert.ok(blob.startsWith('enc:v1:'))
    assert.equal(fc.decryptField(blob, 'ctx'), 'Customer 0042')
  })

  test('round-trips unicode', () => {
    assert.equal(fc.decryptField(fc.encryptField('Zoë Ünal 日本', 'c'), 'c'), 'Zoë Ünal 日本')
  })

  test('ciphertext does not contain the plaintext', () => {
    const blob = fc.encryptField('customer0042@example.com', 'c')
    assert.ok(!blob.includes('customer0042'))
    assert.ok(!Buffer.from(blob.slice(7), 'base64').toString('latin1').includes('customer0042'))
  })

  test('is non-deterministic: same input gives different ciphertext', () => {
    const a = fc.encryptField('same value', 'c')
    const b = fc.encryptField('same value', 'c')
    assert.notEqual(a, b)
    assert.equal(fc.decryptField(a, 'c'), fc.decryptField(b, 'c'))
  })

  test('empty values stay null', () => {
    assert.equal(fc.encryptField(null), null)
    assert.equal(fc.encryptField(undefined), null)
    assert.equal(fc.encryptField(''), null)
    assert.equal(fc.decryptField(null), null)
  })

  test('tamper detection: a flipped byte fails GCM authentication', () => {
    const blob = fc.encryptField('+1-555-0142', 'c')
    const raw = Buffer.from(blob.slice('enc:v1:'.length), 'base64')
    raw[raw.length - 1] ^= 0x01 // flip one bit in the ciphertext
    assert.throws(() => fc.decryptField('enc:v1:' + raw.toString('base64'), 'c'), DecryptError)

    const raw2 = Buffer.from(blob.slice('enc:v1:'.length), 'base64')
    raw2[14] ^= 0x80 // flip a bit inside the auth tag
    assert.throws(() => fc.decryptField('enc:v1:' + raw2.toString('base64'), 'c'), DecryptError)
  })

  test('a ciphertext moved to another context (row/column) is rejected', () => {
    const blob = fc.encryptField('x@example.com', 'customers:1:email')
    assert.throws(() => fc.decryptField(blob, 'customers:1:phone'), DecryptError)
    assert.throws(() => fc.decryptField(blob, 'customers:2:email'), DecryptError)
  })

  test('the wrong key cannot decrypt', () => {
    const other = createFieldCrypto(env(3, 4))
    const blob = fc.encryptField('secret', 'c')
    assert.throws(() => other.decryptField(blob, 'c'), DecryptError)
  })

  test('rejects values without the version prefix and truncated blobs', () => {
    assert.throws(() => fc.decryptField('plaintext'), DecryptError)
    assert.throws(() => fc.decryptField('enc:v1:AAAA'), DecryptError)
  })
})

describe('configuration', () => {
  test('missing, short, or identical keys are rejected', () => {
    assert.throws(() => createFieldCrypto({}), CryptoNotConfiguredError)
    assert.throws(
      () => createFieldCrypto({ PII_ENC_KEY: 'c2hvcnQ=', PII_BIDX_KEY: env(1, 2).PII_BIDX_KEY }),
      /32 bytes/,
    )
    assert.throws(() => createFieldCrypto(env(5, 5)), /different/)
  })
})

describe('blind index', () => {
  test('is deterministic', () => {
    assert.equal(fc.blindIndex('15550142', 'customers.phone'), fc.blindIndex('15550142', 'customers.phone'))
    assert.match(fc.blindIndex('15550142', 'customers.phone'), /^[0-9a-f]{64}$/)
  })

  test('domain separation: same value in email vs phone gives different indexes', () => {
    assert.notEqual(fc.blindIndex('15550142', 'customers.email'), fc.blindIndex('15550142', 'customers.phone'))
  })

  test('different values give different indexes', () => {
    assert.notEqual(fc.blindIndex('15550142', 'd'), fc.blindIndex('15550143', 'd'))
  })

  test('depends on the secret key', () => {
    const other = createFieldCrypto(env(1, 9))
    assert.notEqual(fc.blindIndex('15550142', 'd'), other.blindIndex('15550142', 'd'))
  })

  test('empty input yields null; missing domain throws', () => {
    assert.equal(fc.blindIndex('', 'd'), null)
    assert.equal(fc.blindIndex(null, 'd'), null)
    assert.throws(() => fc.blindIndex('x'))
  })

  test('normalization makes formatting variants collide on purpose', () => {
    assert.equal(normalizePhone('+1 (555) 0142'), normalizePhone('1-555-0142'))
    assert.equal(normalizeEmail('  Customer0042@Example.COM '), 'customer0042@example.com')
    assert.equal(normalizePhone('12'), null)
    assert.equal(normalizeEmail('not-an-email'), null)
  })
})
