import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import cbor from 'borc'
import { Envelope, Key } from '../../src/index'

chai.use(chaiAsPromised)
const { assert } = chai

let env1, env2, buf1, buf2, str1, str2
beforeEach(() => {
  env1 = Envelope.wrap('Hello world!', { proto: 'test' })
  env2 = Envelope.wrap({ data: 'Hello world!' }, { proto: 'test' })
  buf1 = Buffer.from([130, 161, 101, 112, 114, 111, 116, 111, 100, 116, 101, 115, 116, 108, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33])
  buf2 = Buffer.from([130, 161, 101, 112, 114, 111, 116, 111, 100, 116, 101, 115, 116, 161, 100, 100, 97, 116, 97, 108, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33])
  str1 = 'oWVwcm90b2R0ZXN0.bEhlbGxvIHdvcmxkIQ'
  str2 = 'oWVwcm90b2R0ZXN0.oWRkYXRhbEhlbGxvIHdvcmxkIQ'
})

const ecKey = new Key('EC', {
  crv: 'secp256k1',
  d: Buffer.from([88, 159, 176, 120, 175, 186, 246, 14, 81, 191, 103, 182, 27, 61, 106, 68, 42, 32, 23, 42, 228, 54, 170, 109, 176, 120, 34, 196, 26, 223, 95, 201]),
  x: Buffer.from([197, 214, 24, 161, 240, 252, 2, 55, 178, 103, 45, 132, 103, 111, 208, 254, 110, 111, 91, 227, 69, 131, 238, 90, 79, 47, 112, 233, 251, 167, 92, 91]),
  y: Buffer.from([125, 175, 246, 180, 252, 145, 14, 33, 255, 1, 93, 25, 3, 231, 199, 183, 238, 187, 175, 87, 3, 207, 21, 129, 176, 124, 177, 195, 1, 162, 97, 140])
})

const oct128Key = new Key('oct', {
  k: Buffer.from([250, 126, 24, 75, 127, 133, 111, 142, 107, 4, 205, 10, 72, 61, 249, 0])
})

const oct256Key = new Key('oct', {
  k: Buffer.from([205, 34, 46, 245, 207, 202, 223, 84, 37, 48, 241, 120, 47, 215, 155, 254, 126, 216, 64, 3, 216, 156, 121, 163, 203, 108, 215, 21, 51, 119, 38, 210])
})

const oct512Key = new Key('oct', {
  k: Buffer.from([102, 163, 155, 242, 130, 52, 132, 60, 80, 152, 205, 43, 218, 103, 174, 176, 13, 26, 25, 171, 7, 111, 203, 111, 245, 169, 121, 187, 239, 14, 253, 118,
                  200, 84, 18, 231, 163, 199, 5, 238, 136, 94, 127, 102, 35, 196, 126, 240, 181, 37, 163, 121, 105, 110, 88, 70, 208, 248, 224, 10, 89, 209, 150, 131])
})


describe('Envelope.fromBuffer()', () => {
  it('decodes the buffer to envelope instance', () => {
    assert.deepEqual(Envelope.fromBuffer(buf1), env1)
    assert.deepEqual(Envelope.fromBuffer(buf2), env2)
  })
})


describe('Envelope.fromScript()', () => {
  it('decodes the script to envelope instance', () => {
    const s1 = env1.toScript()
    const s2 = env2.toScript(false)
    console.log(s1)
    assert.deepEqual(Envelope.fromScript(s1), env1)
    //assert.deepEqual(Envelope.fromScript(s2), env2)
  })
})


describe('Envelope.fromString()', () => {
  it('decodes the base64 string to envelope instance', () => {
    assert.deepEqual(Envelope.fromString(str1), env1)
    assert.deepEqual(Envelope.fromString(str2), env2)
  })
})


describe('Envelope.wrap()', () => {
  it('wraps the given payload into envelope instance', () => {
    assert.deepEqual(Envelope.wrap('Hello world!', { proto: 'test' }), env1)
    assert.deepEqual(Envelope.wrap({ data: 'Hello world!' }, { proto: 'test' }), env2)
  })
})


describe('Envelope#encodedPayload', () => {
  it('returns the payload as CBOR encoded buffer', () => {
    assert.equal(cbor.decode(env1.encodedPayload), 'Hello world!')
    assert.deepEqual(cbor.decode(env2.encodedPayload), { data: 'Hello world!' })
  })
})


describe('Envelope#encrypt()', () => {
  it('encrypts the envelope with the A128CBC-HS256 alg', async () => {
    await env1.encrypt(oct256Key, { alg: 'A128CBC-HS256' })
    assert.notEqual(env1.payload, 'Hello world!')
    assert.equal(env1.recipient.header.headers.alg, 'A128CBC-HS256')
  })

  it('encrypts the envelope with the A256GCM alg', async () => {
    await env1.encrypt(oct256Key, { alg: 'A256GCM' })
    assert.notEqual(env1.payload, 'Hello world!')
    assert.equal(env1.recipient.header.headers.alg, 'A256GCM')
  })

  it('encrypts the envelope with the A256GCM alg and given IV', async () => {
    const iv = Buffer.from([135, 219, 197, 24, 166, 181, 100, 238, 213, 184, 46, 227])
    await env1.encrypt(oct256Key, { alg: 'A256GCM', iv })
    assert.equal(env1.toString(), 'oWVwcm90b2R0ZXN0.TfJ3p_l8QhO45YETV7E.9g.gqNiaXZMh9vFGKa1ZO7VuC7jY2FsZ2dBMjU2R0NNY3RhZ1DwrPseCoOkmNJZES_P7_1q9g')
    assert.equal(env1.recipient.header.headers.alg, 'A256GCM')
    assert.deepEqual(env1.recipient.header.headers.iv, iv)
  })

  it('encrypts the envelope with the ECDH-ES+A128GCM alg', async () => {
    await env1.encrypt(ecKey, { alg: 'ECDH-ES+A128GCM' })
    assert.notEqual(env1.payload, 'Hello world!')
    assert.equal(env1.recipient.header.headers.alg, 'ECDH-ES+A128GCM')
  })

  it('encrypts the envelope with multiple keys with the A256GCM alg', async () => {
    await env1.encrypt([oct256Key, oct256Key, oct256Key], { alg: 'A256GCM' })
    assert.notEqual(env1.payload, 'Hello world!')
    assert.lengthOf(env1.recipient, 3)
  })
})


describe('Envelope#encrypt() and Envelope#decrypt()', () => {
  it('encrypts and decrypts envelope using the ECDH-ES+A128GCM alg', async () => {
    const pubkey = ecKey.toPublic()
    await env1.encrypt(pubkey, { alg: 'ECDH-ES+A128GCM' })
    assert.notEqual(env1.payload, 'Hello world!')
    await env1.decrypt(ecKey)
    assert.equal(env1.payload, 'Hello world!')
  })

  it('encrypts and decrypts envelope using the A128CBC-HS256 alg', async () => {
    await env1.encrypt(oct256Key, { alg: 'A128CBC-HS256' })
    assert.notEqual(env1.payload, 'Hello world!')
    await env1.decrypt(oct256Key)
    assert.equal(env1.payload, 'Hello world!')
  })

  it('encrypts and decrypts envelope using the A256CBC-HS512 alg', async () => {
    await env1.encrypt(oct512Key, { alg: 'A256CBC-HS512' })
    assert.notEqual(env1.payload, 'Hello world!')
    await env1.decrypt(oct512Key)
    assert.equal(env1.payload, 'Hello world!')
  })

  it('encrypts and decrypts envelope using the A128GCM alg', async () => {
    await env1.encrypt(oct128Key, { alg: 'A128GCM' })
    assert.notEqual(env1.payload, 'Hello world!')
    await env1.decrypt(oct128Key)
    assert.equal(env1.payload, 'Hello world!')
  })

  it('encrypts and decrypts envelope using the A256GCM alg', async () => {
    await env1.encrypt(oct256Key, { alg: 'A256GCM' })
    assert.notEqual(env1.payload, 'Hello world!')
    await env1.decrypt(oct256Key)
    assert.equal(env1.payload, 'Hello world!')
  })

  it('encrypts and decrypts envelope using the ECDH-ES+A256GCM alg', async () => {
    await env1.encrypt(ecKey, { alg: 'ECDH-ES+A256GCM' })
    assert.notEqual(env1.payload, 'Hello world!')
    await env1.decrypt(ecKey)
    assert.equal(env1.payload, 'Hello world!')
  })
})


describe('Envelope#sign()', () => {
  const ecStr = 'oWVwcm90b2R0ZXN0.bEhlbGxvIHdvcmxkIQ.gqFjYWxnZkVTMjU2S1hBH_D1cARfCqgwJC3CFUM_s1-FI8M8IVM7pB6K1S6Q-z6OH9UTlDyssAQ15NIfhd-_XGJN_UJPZZeRLfjBuSCXbYg'
  const octStr2 = 'oWVwcm90b2R0ZXN0.bEhlbGxvIHdvcmxkIQ.gqFjYWxnZUhTMjU2WCDzHu06NttxBEl_bF9W7OWFkCVPSZmLHBWZWg5o7YUNnQ'
  const octStr5 = 'oWVwcm90b2R0ZXN0.bEhlbGxvIHdvcmxkIQ.gqFjYWxnZUhTNTEyWECDg60rjMXJPUYvlz4I8pmcWdjBInk6-R7SMeXS9p9eWx-e4ld4ySpg5oK3XpiwFwMZ0xSdC1MBqLP0cWr5Yv68'

  it('signs the envelope with the ES256K alg', async () => {
    const env = await env1.sign(ecKey, { alg: 'ES256K' })
    assert.equal(env.toString(), ecStr)
  })

  it('signs the envelope with the HS256 alg', async () => {
    const env = await env1.sign(oct256Key, { alg: 'HS256' })
    assert.equal(env.toString(), octStr2)
  })

  it('signs the envelope with the HS512 alg', async () => {
    const env = await env1.sign(oct256Key, { alg: 'HS512' })
    assert.equal(env.toString(), octStr5)
  })

  it('signs the envelope twice', async () => {
    const env = await env1.sign([oct256Key, oct256Key], { alg: 'HS512' })
    assert.lengthOf(env.signature, 2)
  })

  it('signs the envelope twice with key specific headers', async () => {
    const env = await env1.sign([[oct256Key, {foo: 'a'}], [oct256Key, {foo: 'b'}]], { alg: 'HS512' })
    assert.lengthOf(env.signature, 2)
    assert.equal(env.signature[0].header.headers.foo, 'a')
    assert.equal(env.signature[1].header.headers.foo, 'b')
  })

  it('throws error if alg not recognised', async () => {
    await assert.isRejected(env1.sign(ecKey, { alg: 'FOOBAR' }), 'Unsupported algorithm: FOOBAR')
  })

  it('throws error if key and alg mismatch', async () => {
    await assert.isRejected(env1.sign(ecKey, { alg: 'HS256' }), 'Invalid key for HS256 algorithm')
  })
})


describe('Envelope#toBuffer()', () => {
  it('encodes the envelope as a CBOR encoded buffer', () => {
    assert.deepEqual(env1.toBuffer(), buf1)
    assert.deepEqual(env2.toBuffer(), buf2)
  })
})

describe('Envelope#toScript()', () => {
  it('encodes the envelope as a bitcoin op_return script', () => {
    const s1 = env1.toScript()
    const s2 = env2.toScript(false)
    assert.lengthOf(s1.chunks, 5)
    assert.equal(s1.chunks[0].opCodeNum, 0)
    assert.lengthOf(s2.chunks, 4)
    assert.notEqual(s2.chunks[0].opCodeNum, 0)
  })
})


describe('Envelope#toString()', () => {
  it('encodes the envelope as a base64 encoded string', () => {
    assert.equal(env1.toString(), str1)
    assert.equal(env2.toString(), str2)
  })
})


describe('Envelope#verify()', () => {
  const ecStr = 'oWVwcm90b2R0ZXN0.bEhlbGxvIHdvcmxkIQ.gqFjYWxnZkVTMjU2S1hBH_D1cARfCqgwJC3CFUM_s1-FI8M8IVM7pB6K1S6Q-z6OH9UTlDyssAQ15NIfhd-_XGJN_UJPZZeRLfjBuSCXbYg'
  const octStr2 = 'oWVwcm90b2R0ZXN0.bEhlbGxvIHdvcmxkIQ.gqFjYWxnZUhTMjU2WCDzHu06NttxBEl_bF9W7OWFkCVPSZmLHBWZWg5o7YUNnQ'
  const octStr5 = 'oWVwcm90b2R0ZXN0.bEhlbGxvIHdvcmxkIQ.gqFjYWxnZUhTNTEyWECDg60rjMXJPUYvlz4I8pmcWdjBInk6-R7SMeXS9p9eWx-e4ld4ySpg5oK3XpiwFwMZ0xSdC1MBqLP0cWr5Yv68'

  it('verifies the envelope signed with the ES256K alg', async () => {
    const env = Envelope.fromString(ecStr)
    await assert.becomes(env.verify(ecKey), true)
  })

  it('verifies the envelope signed with the HS256 alg', async () => {
    const env = Envelope.fromString(octStr2)
    await assert.becomes(env.verify(oct256Key), true)
  })

  it('verifies the envelope signed with the HS512 alg', async () => {
    const env = Envelope.fromString(octStr5)
    await assert.becomes(env.verify(oct256Key), true)
  })

  it('verifies the envelope signed twice with the HS512 alg', async () => {
    const env = await env1.sign([oct256Key, oct256Key], { alg: 'HS512' })
    await assert.becomes(env.verify([oct256Key, oct256Key]), true)
  })

  it('verifies the envelope signed twice with different keys', async () => {
    const env = await env1.sign([[ecKey, {alg: 'ES256K'}], [oct256Key, {alg: 'HS256'}]])
    await assert.becomes(env.verify([ecKey, oct256Key]), true)
  })
})


describe('Envelope#decrypt_at()', () => {
  let secret, sender, alice, bob
  before(async () => {
    secret  = await Key.generate('oct', 256)
    sender  = await Key.generate('ec', 'secp256k1')
    alice   = await Key.generate('ec', 'secp256k1')
    bob     = await Key.generate('ec', 'secp256k1')
  })

  let env
  beforeEach(async () => {
    const encKeys = [
      [secret, {alg: 'A256GCM'}],
      alice.toPublic(),
      bob.toPublic()
    ]
    env = Envelope.wrap('this is a secret message', { proto: 'test' })
    await env.sign(sender, { alg: 'ES256K' })
    await env.encrypt(encKeys, { alg: 'ECDH-ES+A256GCM' })
    assert.notEqual(env.payload, 'this is a secret message')
  })

  it('decrypts for alice at the given index', async () => {
    await env.decryptAt(1, alice)
    assert.equal(env.payload, 'this is a secret message')
  })

  it('decrypts for bob at the given index', async () => {
    await env.decryptAt(2, bob)
    assert.equal(env.payload, 'this is a secret message')
  })

  it('encodes and serializes in CBOR and decrypts for Alice', async () => {
    const buf = env.toBuffer()
    const e = Envelope.fromBuffer(buf)
    await env.decryptAt(1, alice)
    assert.becomes(env.verify(sender), true)
  })

  it('encodes and serializes in Base64 and decrypts for Bob', async () => {
    const str = env.toString()
    const e = Envelope.fromString(str)
    await env.decryptAt(2, bob)
    assert.becomes(env.verify(sender), true)
  })
})