import { assert } from 'chai'
import { Key } from '../../src/index'

let ecKey, octKey
before(async () => {
  ecKey = await Key.generate('ec', 'secp256k1')
  octKey = await Key.generate('oct', 256)
})


describe('Key.generate()', () => {
  it('generates new key from EC key params', async () => {
    const key = await Key.generate('ec', 'secp256k1')
    assert.equal(key.type, 'EC')
    assert.equal(key.params.crv, 'secp256k1')
    assert.lengthOf(key.params.d, 32)
    assert.lengthOf(key.params.x, 32)
    assert.lengthOf(key.params.y, 32)
  })

  it('generates new key from OCT key params', async () => {
    const key = await Key.generate('oct', 256)
    assert.equal(key.type, 'oct')
    assert.lengthOf(key.params.k, 32)
  })
})


describe('Envelope#encrypt()', () => {
  it('encrypts the key with the A128CBC-HS256 alg', async () => {
    const recipient = await ecKey.encrypt(octKey, { alg: 'A128CBC-HS256' })
    assert.instanceOf(recipient.key, Buffer)
    assert.containsAllKeys(recipient.header.headers, ['iv', 'tag'])
    assert.equal(recipient.header.headers.alg, 'A128CBC-HS256')
  })

  it('encrypts the key with the A256GCM alg', async () => {
    const recipient = await ecKey.encrypt(octKey, { alg: 'A256GCM' })
    assert.instanceOf(recipient.key, Buffer)
    assert.containsAllKeys(recipient.header.headers, ['iv', 'tag'])
    assert.equal(recipient.header.headers.alg, 'A256GCM')
  })

  it('encrypts the key with the ECDH-ES+A128GCM alg', async () => {
    const recipient = await octKey.encrypt(ecKey, { alg: 'ECDH-ES+A128GCM' })
    assert.instanceOf(recipient.key, Buffer)
    assert.containsAllKeys(recipient.header.headers, ['iv', 'tag', 'epk'])
    assert.equal(recipient.header.headers.alg, 'ECDH-ES+A128GCM')
  })
})


describe('Key#toPublic()', () => {
  it('converts EC key to public key', () => {
    const key = ecKey.toPublic()
    assert.equal(key.params.crv, ecKey.params.crv)
    assert.equal(key.params.x, ecKey.params.x)
    assert.equal(key.params.y, ecKey.params.y)
    assert.isUndefined(key.params.d)
  })
})

