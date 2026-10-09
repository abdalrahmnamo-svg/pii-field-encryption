import { test, describe, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { createApp } from '../src/app.js'
import { createFieldCrypto } from '../src/crypto/fieldCrypto.js'
import { openDb } from '../src/store.js'

const fc = createFieldCrypto({
  PII_ENC_KEY: Buffer.alloc(32, 7).toString('base64'),
  PII_BIDX_KEY: Buffer.alloc(32, 9).toString('base64'),
})

let app
let db
let audits

beforeEach(() => {
  db = openDb(':memory:')
  audits = []
  app = createApp({ db, fc, audit: (e) => audits.push(e) })
})

const post = (body) =>
  app.request('/customers', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

const CUSTOMER = {
  name: 'Customer 0042',
  email: 'Customer0042@Example.com',
  phone: '+1-555-0142',
  notes: 'Call back on +1-555-0142 or alt42@example.com',
}

describe('customers API', () => {
  test('create -> lookup by phone -> masked read -> reveal denied -> reveal allowed', async () => {
    // create
    const created = await post(CUSTOMER)
    assert.equal(created.status, 201)
    const { id, ...view } = await created.json()
    assert.equal(view.masked, true)
    assert.ok(!view.phone.includes('555'))
    assert.ok(!view.email.includes('0042'))

    // lookup by phone, in a different format than the one stored
    const found = await app.request('/customers?phone=' + encodeURIComponent('1 (555) 0142'))
    assert.equal(found.status, 200)
    const body = await found.json()
    assert.equal(body.count, 1)
    assert.equal(body.results[0].id, id)
    assert.equal(body.results[0].phone, '•'.repeat(5) + '142')

    // masked read
    const masked = await (await app.request(`/customers/${id}`)).json()
    assert.equal(masked.name, 'Customer 0.')
    assert.equal(masked.email, 'cu' + '•'.repeat(10) + '@example.com')
    assert.equal(masked.notes, 'Call back on [phone] or [email]')
    assert.equal(masked.masked, true)

    // reveal denied without role, and with a wrong role
    assert.equal((await app.request(`/customers/${id}?reveal=1`)).status, 403)
    const wrong = await app.request(`/customers/${id}?reveal=1`, { headers: { 'x-role': 'agent' } })
    assert.equal(wrong.status, 403)
    assert.equal(audits.length, 0)

    // reveal allowed with role
    const revealed = await app.request(`/customers/${id}?reveal=1`, { headers: { 'x-role': 'admin' } })
    assert.equal(revealed.status, 200)
    const plain = await revealed.json()
    assert.equal(plain.name, 'Customer 0042')
    assert.equal(plain.email, 'customer0042@example.com') // stored normalized
    assert.equal(plain.phone, '+1-555-0142')
    assert.equal(plain.masked, false)
    assert.deepEqual(audits, [{ event: 'reveal', customerId: id }])
  })

  test('lookup by email is case- and whitespace-insensitive', async () => {
    const { id } = await (await post(CUSTOMER)).json()
    const r = await app.request('/customers?email=' + encodeURIComponent('  CUSTOMER0042@example.COM '))
    const body = await r.json()
    assert.equal(body.count, 1)
    assert.equal(body.results[0].id, id)
  })

  test('unknown phone returns an empty result, not an error', async () => {
    await post(CUSTOMER)
    const body = await (await app.request('/customers?phone=15559999999')).json()
    assert.deepEqual(body, { count: 0, results: [] })
  })

  test('the database holds ciphertext only', async () => {
    await post(CUSTOMER)
    const row = db.prepare('SELECT * FROM customers').get()
    const dump = JSON.stringify(row)
    for (const secret of ['Customer 0042', 'customer0042', '555-0142', 'alt42@example']) {
      assert.ok(!dump.includes(secret), `row leaks "${secret}"`)
    }
    assert.ok(row.name_enc.startsWith('enc:v1:'))
    assert.match(row.email_bidx, /^[0-9a-f]{64}$/)
    assert.match(row.phone_bidx, /^[0-9a-f]{64}$/)
  })

  test('a tampered stored value yields a generic 500, never garbage or details', async () => {
    const { id } = await (await post(CUSTOMER)).json()
    const row = db.prepare('SELECT name_enc FROM customers WHERE id = ?').get(id)
    const raw = Buffer.from(row.name_enc.slice(7), 'base64')
    raw[raw.length - 1] ^= 1
    db.prepare('UPDATE customers SET name_enc = ? WHERE id = ?').run('enc:v1:' + raw.toString('base64'), id)
    const r = await app.request(`/customers/${id}`)
    assert.equal(r.status, 500)
    assert.deepEqual(await r.json(), { error: 'stored data could not be decrypted' })
  })

  test('validation and not-found errors', async () => {
    assert.equal((await post({ email: 'a@example.com' })).status, 400)
    assert.equal((await post({ name: 'X', email: 'nope' })).status, 400)
    assert.equal((await post({ name: 'X', phone: '12' })).status, 400)
    const badJson = await app.request('/customers', { method: 'POST', body: '{oops' })
    assert.equal(badJson.status, 400)
    assert.equal((await app.request('/customers')).status, 400) // no listing without a filter
    assert.equal((await app.request('/customers?phone=12')).status, 400)
    assert.equal((await app.request('/customers/does-not-exist')).status, 404)
  })
})
