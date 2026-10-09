import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { maskName, maskPhone, maskEmail, maskFreeText } from '../src/crypto/mask.js'
import { redactText } from '../src/redact.js'

describe('masking', () => {
  test('name keeps first name, reduces the rest to initials', () => {
    assert.equal(maskName('Ada Grace Lovelace'), 'Ada G. L.')
    assert.equal(maskName('Customer 0042'), 'Customer 0.')
    assert.equal(maskName('Plato'), 'Pl•••')
    assert.equal(maskName(''), null)
  })

  test('phone shows only the last 3 digits', () => {
    const out = maskPhone('+1-555-0142')
    assert.equal(out, '•'.repeat(5) + '142')
    assert.ok(!out.includes('555'))
    assert.equal(maskPhone(null), null)
  })

  test('email keeps two characters and the domain', () => {
    assert.equal(maskEmail('customer0042@example.com'), 'cu' + '•'.repeat(10) + '@example.com')
    assert.ok(!maskEmail('customer0042@example.com').includes('0042'))
    assert.equal(maskEmail('a@example.com'), '•••@example.com')
  })

  test('free text strips embedded emails and phones', () => {
    const out = maskFreeText('Call +1-555-0142 or write alt@example.com')
    assert.equal(out, 'Call [phone] or write [email]')
    assert.equal(maskFreeText(''), null)
  })
})

describe('redactText', () => {
  test('keeps short numbers and ISO dates', () => {
    assert.equal(redactText('Score 5 on 2026-06-20'), 'Score 5 on 2026-06-20')
  })

  test('masks surname but keeps first name', () => {
    const out = redactText('Hello Anna Smith, welcome back Anna!', { customerName: 'Anna Smith' })
    assert.equal(out, 'Hello Anna [name], welcome back Anna!')
  })
})
