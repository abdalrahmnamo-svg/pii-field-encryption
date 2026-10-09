// Generates the two required secrets with crypto.randomBytes (a CSPRNG).
//   node scripts/genkeys.mjs           -> writes .env (refuses to overwrite an existing one)
//   node scripts/genkeys.mjs --print   -> prints the two lines to stdout instead
//   node scripts/genkeys.mjs --force   -> overwrites .env
import { randomBytes } from 'node:crypto'
import { existsSync, writeFileSync } from 'node:fs'

const lines = [
  `PII_ENC_KEY=${randomBytes(32).toString('base64')}`,
  `PII_BIDX_KEY=${randomBytes(32).toString('base64')}`,
  '',
].join('\n')

const args = new Set(process.argv.slice(2))
if (args.has('--print')) {
  process.stdout.write(lines)
} else if (existsSync('.env') && !args.has('--force')) {
  console.error('.env already exists; refusing to overwrite (it may hold keys for existing data). Use --force or --print.')
  process.exit(1)
} else {
  writeFileSync('.env', lines, { mode: 0o600 })
  console.log('Wrote .env with PII_ENC_KEY and PII_BIDX_KEY. Back it up: losing PII_ENC_KEY makes stored data unrecoverable.')
}
