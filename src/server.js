import { serve } from '@hono/node-server'
import { createApp } from './app.js'
import { createFieldCrypto } from './crypto/fieldCrypto.js'
import { openDb } from './store.js'

const port = Number(process.env.PORT || 3000)
const dbPath = process.env.DB_PATH || './data/customers.db'

let fc
try {
  fc = createFieldCrypto()
} catch (err) {
  console.error(`Startup failed: ${err.message}`)
  process.exit(1)
}
const db = openDb(dbPath)
// Audit lines carry the record id only, never personal data.
const app = createApp({ db, fc, audit: (e) => console.info(JSON.stringify(e)) })

serve({ fetch: app.fetch, port, hostname: '127.0.0.1' }, (info) => {
  console.log(`listening on http://127.0.0.1:${info.port} (db: ${dbPath})`)
})
