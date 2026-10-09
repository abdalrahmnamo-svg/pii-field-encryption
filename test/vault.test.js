import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import {
  deriveKey, encryptRecord, decryptRecord, makeVerifier, checkVerifier, randomSaltB64,
} from '../src/vault/passphraseVault.js'

const RECORD = { name: 'Customer 0042', phone: '+1-555-0142', email: 'customer0042@example.com' }

describe('passphrase vault', () => {
  test('round-trips a record', async () => {
    const key = await deriveKey('a strong passphrase', randomSaltB64())
    const blob = await encryptRecord(key, RECORD)
    assert.ok(blob.startsWith('pv1:'))
    assert.deepEqual(await decryptRecord(key, blob), RECORD)
  })

  test('blob leaks none of the plaintext and is non-deterministic', async () => {
    const key = await deriveKey('pass', randomSaltB64())
    const a = await encryptRecord(key, RECORD)
    const b = await encryptRecord(key, RECORD)
    assert.notEqual(a, b)
    for (const v of Object.values(RECORD)) assert.ok(!a.includes(v))
  })

  test('wrong passphrase or wrong salt cannot decrypt', async () => {
    const salt = randomSaltB64()
    const blob = await encryptRecord(await deriveKey('right', salt), RECORD)
    await assert.rejects(decryptRecord(await deriveKey('wrong', salt), blob))
    await assert.rejects(decryptRecord(await deriveKey('right', randomSaltB64()), blob))
  })

  test('empty fields are dropped', async () => {
    const key = await deriveKey('pass', randomSaltB64())
    const back = await decryptRecord(key, await encryptRecord(key, { name: 'X', phone: '', email: null }))
    assert.deepEqual(back, { name: 'X' })
  })

  test('verifier accepts the right passphrase and rejects the wrong one', async () => {
    const salt = randomSaltB64()
    const v = await makeVerifier(await deriveKey('correct', salt))
    assert.equal(await checkVerifier(await deriveKey('correct', salt), v), true)
    assert.equal(await checkVerifier(await deriveKey('incorrect', salt), v), false)
  })
})
