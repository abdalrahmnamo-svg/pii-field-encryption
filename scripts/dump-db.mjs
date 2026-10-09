// Prints raw rows exactly as stored: ciphertext and blind indexes only, no keys needed.
//   node scripts/dump-db.mjs [limit]
import { DatabaseSync } from 'node:sqlite'

const dbPath = process.env.DB_PATH || './data/customers.db'
const limit = Number(process.argv[2] || 3)

const db = new DatabaseSync(dbPath, { readOnly: true })
const rows = db.prepare('SELECT * FROM customers ORDER BY created_at LIMIT ?').all(limit)
const total = db.prepare('SELECT COUNT(*) AS n FROM customers').get().n
console.log(`# ${dbPath}: showing ${rows.length} of ${total} rows`)
for (const r of rows) console.log(JSON.stringify(r, null, 2))
