// Seeds the demo database with 60 synthetic customers. Deterministic: same output every run.
// Also writes samples/customers.sample.json (the plaintext, all synthetic) for README examples.
import { writeFileSync, mkdirSync } from 'node:fs'
import { createFieldCrypto } from '../src/crypto/fieldCrypto.js'
import { openDb, createCustomerStore } from '../src/store.js'

const COUNT = 60
const dbPath = process.env.DB_PATH || './data/customers.db'

// mulberry32: tiny seeded PRNG, so the data never changes between runs.
function prng(seed) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
const rand = prng(20240601)

const TOPICS = [
  'Asked about delivery window.',
  'Prefers contact by email.',
  'Requested a callback next week.',
  'Reported a billing question.',
  'Left positive feedback.',
]
const EPOCH = Date.UTC(2024, 0, 1)

const samples = []
for (let i = 1; i <= COUNT; i++) {
  const n = String(i).padStart(4, '0')
  const line = String(i - 1).padStart(2, '0') // +1-555-0100 .. +1-555-0159 (reserved fictional range)
  const sample = {
    name: `Customer ${n}`,
    email: `customer${n}@example.com`,
    phone: `+1-555-01${line}`,
    notes: TOPICS[Math.floor(rand() * TOPICS.length)],
    createdAt: new Date(EPOCH + i * 86_400_000).toISOString(),
  }
  // Every 10th customer has contact details pasted into the notes, to show redaction.
  if (i % 10 === 0) sample.notes += ` Alt contact: alt${n}@example.com or +1-555-01${line}.`
  samples.push(sample)
}

const fc = createFieldCrypto()
const store = createCustomerStore(openDb(dbPath), fc)
store.clear()
for (const s of samples) store.create(s, { now: new Date(s.createdAt) })

mkdirSync('samples', { recursive: true })
writeFileSync('samples/customers.sample.json', JSON.stringify(samples, null, 2) + '\n')
console.log(`Seeded ${store.count()} synthetic customers into ${dbPath}`)
