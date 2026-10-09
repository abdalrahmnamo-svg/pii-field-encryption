/**
 * Storage for the single `customers` table (node:sqlite). Every personal field is
 * encrypted before it reaches SQL; email and phone additionally get a blind index so
 * they can be looked up without a plaintext column.
 */

import { DatabaseSync } from 'node:sqlite'
import { randomUUID } from 'node:crypto'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { normalizeEmail, normalizePhone } from './crypto/normalize.js'

const SCHEMA = `
CREATE TABLE IF NOT EXISTS customers (
  id          TEXT PRIMARY KEY,
  name_enc    TEXT NOT NULL,
  email_enc   TEXT,
  phone_enc   TEXT,
  notes_enc   TEXT,
  email_bidx  TEXT,
  phone_bidx  TEXT,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_customers_email_bidx ON customers(email_bidx);
CREATE INDEX IF NOT EXISTS idx_customers_phone_bidx ON customers(phone_bidx);
`

/** Blind-index domains. One per field: equal strings in different fields never collide. */
export const DOMAIN = { email: 'customers.email', phone: 'customers.phone' }

export class ValidationError extends Error {
  constructor(message) {
    super(message)
    this.name = 'ValidationError'
  }
}

export function openDb(path = ':memory:') {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true })
  const db = new DatabaseSync(path)
  db.exec(SCHEMA)
  return db
}

/** AAD binds each ciphertext to its row and column. */
const ctx = (id, field) => `customers:${id}:${field}`

export function createCustomerStore(db, fc) {
  const insert = db.prepare(
    `INSERT INTO customers (id, name_enc, email_enc, phone_enc, notes_enc, email_bidx, phone_bidx, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
  const byId = db.prepare('SELECT * FROM customers WHERE id = ?')
  const byEmail = db.prepare('SELECT * FROM customers WHERE email_bidx = ? ORDER BY created_at, id')
  const byPhone = db.prepare('SELECT * FROM customers WHERE phone_bidx = ? ORDER BY created_at, id')

  function toPlain(row) {
    if (!row) return null
    return {
      id: row.id,
      name: fc.decryptField(row.name_enc, ctx(row.id, 'name')),
      email: fc.decryptField(row.email_enc, ctx(row.id, 'email')),
      phone: fc.decryptField(row.phone_enc, ctx(row.id, 'phone')),
      notes: fc.decryptField(row.notes_enc, ctx(row.id, 'notes')),
      createdAt: row.created_at,
    }
  }

  return {
    /** Validate, normalize, encrypt, index, insert. Returns the new id. */
    create({ name, email, phone, notes }, { now = new Date() } = {}) {
      if (typeof name !== 'string' || !name.trim()) throw new ValidationError('name is required')
      let emailNorm = null
      let phoneNorm = null
      if (email != null && email !== '') {
        emailNorm = normalizeEmail(email)
        if (!emailNorm) throw new ValidationError('email is not valid')
      }
      if (phone != null && phone !== '') {
        phoneNorm = normalizePhone(phone)
        if (!phoneNorm) throw new ValidationError('phone must contain 7-15 digits')
      }
      if (notes != null && typeof notes !== 'string') throw new ValidationError('notes must be a string')

      const id = randomUUID()
      insert.run(
        id,
        fc.encryptField(name.trim(), ctx(id, 'name')),
        // Email is stored normalized (what the index was built from); phone as entered.
        fc.encryptField(emailNorm, ctx(id, 'email')),
        fc.encryptField(phone != null && phone !== '' ? String(phone).trim() : null, ctx(id, 'phone')),
        fc.encryptField(notes, ctx(id, 'notes')),
        fc.blindIndex(emailNorm, DOMAIN.email),
        fc.blindIndex(phoneNorm, DOMAIN.phone),
        now.toISOString(),
      )
      return id
    },

    get: (id) => toPlain(byId.get(id)),

    /** Input is normalized exactly as on insert, then matched by HMAC. Returns plaintext records. */
    findByEmail(email) {
      const n = normalizeEmail(email)
      if (!n) throw new ValidationError('email is not valid')
      return byEmail.all(fc.blindIndex(n, DOMAIN.email)).map(toPlain)
    },

    findByPhone(phone) {
      const n = normalizePhone(phone)
      if (!n) throw new ValidationError('phone must contain 7-15 digits')
      return byPhone.all(fc.blindIndex(n, DOMAIN.phone)).map(toPlain)
    },

    clear: () => db.exec('DELETE FROM customers'),
    count: () => db.prepare('SELECT COUNT(*) AS n FROM customers').get().n,
  }
}
