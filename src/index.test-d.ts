import { expectAssignable, expectType } from 'tsd'
import { Envelope, Key, Recipient } from '.'

// Instantiate envelope
expectType<Envelope>( new Envelope({ payload: 'test' }) )
expectType<Envelope>( new Envelope({ headers: { foo: 'bar' }, payload: 123 }) )

// Wrap any type
expectType<Envelope>( Envelope.wrap(123) )
expectType<Envelope>( Envelope.wrap('test') )
expectType<Envelope>( Envelope.wrap(Buffer.from('test')) )
expectType<Envelope>( Envelope.wrap({foo: 'bar'}) )
expectType<Envelope>( Envelope.wrap(['foo', 'bar']) )

// Wrap with valid headers
expectType<Envelope>( Envelope.wrap('test', { proto: 'test' }) )
expectType<Envelope>( Envelope.wrap('test', { foo: 'bar' }) )
expectType<Envelope>( Envelope.wrap('test', { foo: { nested: 123 } }) )

// @ts-expect-error
Envelope.wrap('test', 123)

// Envelope instances
(async () => {
  const key1 = await Key.generate('ec', 'secp256k1')
  const key2 = await Key.generate('oct', 128)
  const env = Envelope.wrap('test', { proto: 'test' })

  // Sign and encrypt
  expectType<Envelope>( await env.sign(key1, { alg: 'ES256K' }) )
  expectType<Envelope>( await env.encrypt(key2, { alg: 'A128GCM' }) )

  // Serialise
  const envArr: any = env.toArray()
  const envBuf: Buffer = env.toBuffer()
  const envScr: any = env.toScript()
  const envStr: string = env.toString()

  // Decode
  expectType<Envelope>( Envelope.fromArray(envArr) )
  expectType<Envelope>( Envelope.fromBuffer(envBuf) )
  expectType<Envelope>( Envelope.fromScript(envScr) )
  expectType<Envelope>( Envelope.fromString(envStr) )
  
  // Decrypt and verify
  expectType<Envelope>( await env.decrypt(key1) )
  expectType<boolean>( await env.verify(key2) )

  // Multi recipient
  const alice = await Key.generate('ec', 'secp256k1')
  const bob = await Key.generate('ec', 'secp256k1')
  const charlie = await Key.generate('ec', 'secp256k1')

  const envM = Envelope.wrap('test', { proto: 'test' })
  expectType<Envelope>( await envM.sign(alice, { alg: 'ES256K' }) )
  expectType<Envelope>( await envM.encrypt([alice, bob, charlie], { alg: 'ECDH-ES+A128GCM' }) )
  expectType<Envelope>( await envM.encrypt([[alice, { alg: 'ECDH-ES+A128GCM' }], [bob, { alg: 'ECDH-ES+A128GCM' }], [charlie, { alg: 'ECDH-ES+A128GCM' }]]) )

  expectType<Envelope>( await envM.decryptAt(0, alice) )
  expectType<Envelope>( await envM.decryptAt(1, bob) )
  expectType<Envelope>( await envM.decryptAt(2, charlie) )
})

// Instantiate key
expectType<Key>( new Key('ec', {
  crv: 'secp256k1',
  d: Buffer.alloc(32),
  x: Buffer.alloc(32),
  y: Buffer.alloc(32),
}) )
expectType<Key>( new Key('oct', { k: Buffer.alloc(32) }) )

// @ts-expect-error
new Key('foo', { k: Buffer.alloc(32) })
// @ts-expect-error
new Key('oct', { d: Buffer.alloc(32) })

expectType<Promise<Key>>( Key.generate('ec', 'secp256k1') )
expectType<Promise<Key>>( Key.generate('oct', 128) )
expectType<Promise<Key>>( Key.generate('oct', 256) )
expectType<Promise<Key>>( Key.generate('oct', 512) )

// @ts-expect-error
Key.generate('foo', 'secp256k1')
// @ts-expect-error
Key.generate('ec', 'test')
// @ts-expect-error
Key.generate('oct', 64)

// Key instances
(async () => {
  const key1 = await Key.generate('ec', 'secp256k1')
  const key2 = await Key.generate('oct', 128)

  expectType<Recipient>( await key1.encrypt(key2, { alg: 'A128GCM' }) )

  // Serialise
  const keyBuf: Buffer = key1.toBuffer()
  expectAssignable<any>( key1.toObject() )
  expectType<Key>( key1.toPublic() )

  // Decode
  expectType<Key>( Key.decode(keyBuf) )
})