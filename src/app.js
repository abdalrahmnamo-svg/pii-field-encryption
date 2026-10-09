import { Hono } from 'hono'
import { createCustomerStore, ValidationError } from './store.js'
import { DecryptError } from './crypto/fieldCrypto.js'
import { maskName, maskEmail, maskPhone, maskFreeText } from './crypto/mask.js'

function maskedView(c) {
  return {
    id: c.id,
    name: maskName(c.name),
    email: maskEmail(c.email),
    phone: maskPhone(c.phone),
    notes: maskFreeText(c.notes, { customerName: c.name }),
    createdAt: c.createdAt,
    masked: true,
  }
}

function revealedView(c) {
  return { ...c, masked: false }
}

/**
 * @param {{ db: import('node:sqlite').DatabaseSync, fc: ReturnType<typeof import('./crypto/fieldCrypto.js').createFieldCrypto>, audit?: (event: object) => void }} deps
 */
export function createApp({ db, fc, audit = () => {} }) {
  const store = createCustomerStore(db, fc)
  const app = new Hono()

  app.onError((err, c) => {
    if (err instanceof ValidationError) return c.json({ error: err.message }, 400)
    if (err instanceof DecryptError) return c.json({ error: 'stored data could not be decrypted' }, 500)
    // Never echo err.message for unknown errors: it could contain request data.
    return c.json({ error: 'internal error' }, 500)
  })

  app.post('/customers', async (c) => {
    let body
    try {
      body = await c.req.json()
    } catch {
      throw new ValidationError('body must be valid JSON')
    }
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      throw new ValidationError('body must be a JSON object')
    }
    const id = store.create(body)
    return c.json(maskedView(store.get(id)), 201)
  })

  // Lookup by blind index. Equality only; at least one filter is required (no "list all").
  app.get('/customers', (c) => {
    const { phone, email } = c.req.query()
    if (phone === undefined && email === undefined) {
      throw new ValidationError('provide ?phone= or ?email=')
    }
    const matches = phone !== undefined ? store.findByPhone(phone) : store.findByEmail(email)
    return c.json({ count: matches.length, results: matches.map(maskedView) })
  })

  app.get('/customers/:id', (c) => {
    const record = store.get(c.req.param('id'))
    if (!record) return c.json({ error: 'not found' }, 404)

    if (c.req.query('reveal') === '1') {
      // DEMO STAND-IN: a real deployment must authenticate the caller (session / JWT /
      // mTLS) and authorize the role server-side. A client-supplied header proves nothing.
      if (c.req.header('x-role') !== 'admin') {
        return c.json({ error: 'reveal requires the admin role' }, 403)
      }
      audit({ event: 'reveal', customerId: record.id })
      return c.json(revealedView(record))
    }
    return c.json(maskedView(record))
  })

  return app
}
