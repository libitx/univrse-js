import { assert } from 'chai'
import { Script } from 'bsv'
import { Envelope, Key } from '../../src/index'


const ALICE = 'a561645820dfef448a64826dfe935e494ce97d506945b4e672b29d16c10f76479738f9cf85617858208f3f5d9918af7327a4fbbe77a30fd87ced99f756abb8ad708a577b27bf4d16dd6179582090421b41892a286e6eddbe8fc64119812de58c0197d8c7ed6dfb885a30fbeb9f6363727669736563703235366b31636b7479624543'
const ALICE_PUB = 'a4617858208f3f5d9918af7327a4fbbe77a30fd87ced99f756abb8ad708a577b27bf4d16dd6179582090421b41892a286e6eddbe8fc64119812de58c0197d8c7ed6dfb885a30fbeb9f6363727669736563703235366b31636b7479624543'
const BOB = 'a5616458204bf0b781ab1cb2e2f29fd97cbd2612c5073dff842f672c780d70dc40aabee58b61785820d29cb7587b6466f7a5e2c30229cc7a56f62c6ffc833f9731942ce7cc11ec7f5b61795820810b81386d7215c52ead717cda91f2042c19d330aa136c7bb3a856f6573a92306363727669736563703235366b31636b7479624543'
const BOB_PUB = 'a461785820d29cb7587b6466f7a5e2c30229cc7a56f62c6ffc833f9731942ce7cc11ec7f5b61795820810b81386d7215c52ead717cda91f2042c19d330aa136c7bb3a856f6573a92306363727669736563703235366b31636b7479624543'

const b64_env = 'oWVwcm90b2R0ZXN0.WCKR-bsjg276jO8zDFSmqXt6UuOBrlcjlz7xmebt8JGaBCrv.gqJjYWxnZkVTMjU2S2NraWRlYWxpY2VYQSBLusPFIpVklfGXBUrHm-WllyKJVdyh-k4FEeuHL1cg0ntid_BV7_BVPHc8Vq5T3T4EsscwzvD50ffJvEIwd4_F.goKjY2FsZ2dBMTI4R0NNYml2TLM1hd-GMA1TsDsQDmN0YWdQEasV1DbMba7_iS3MeC2MFPaCpWNhbGdvRUNESC1FUytBMTI4R0NNY2Vwa1ghAn2mqno-TDOPiWoL9y8Wu6-zVUgLl6T8vuKxohewLzTRYml2TBH_oBLWx0siuHxQJGNraWRjYm9iY3RhZ1CM-lMFWCWwEHZl1biFGwxiWBxbiK7-24eccC7qAQsAhDNvw7U43f2pMm2BB2BA'
const script_env = '006a04554e49560ca16570726f746f647465737424582291f9bb23836efa8cef330c54a6a97b7a52e381ae5723973ef199e6edf0919a042aef4c5a82a263616c676645533235364b636b696465616c6963655841204bbac3c522956495f197054ac79be5a597228955dca1fa4e0511eb872f5720d27b6277f055eff0553c773c56ae53dd3e04b2c730cef0f9d1f7c9bc4230778fc54cbd8282a363616c67674131323847434d6269764cb33585df86300d53b03b100e637461675011ab15d436cc6daeff892dcc782d8c14f682a563616c676f454344482d45532b4131323847434d6365706b5821027da6aa7a3e4c338f896a0bf72f16bbafb355480b97a4fcbee2b1a217b02f34d16269764c11ffa012d6c74b22b87c5024636b696463626f6263746167508cfa53055825b0107665d5b8851b0c62581c5b88aefedb879c702eea010b0084336fc3b538ddfda9326d81076040'


describe('parses envelopes created in Elixir', () => {
  const alicePubKey = Key.decode(Buffer.from(ALICE_PUB, 'hex'))
  const bobKey = Key.decode(Buffer.from(BOB, 'hex'))

  it('parses base64, decrypts and verifies sigs', async () => {
    // Decode envelope
    const env = Envelope.fromString(b64_env)
    assert.equal(env.header.headers['proto'], 'test')

    // Inspect signature
    assert.equal(env.signature.header.headers['alg'], 'ES256K')
    assert.equal(env.signature.header.headers['kid'], 'alice')

    // Inspect recipients
    assert.lengthOf(env.recipient, 2)
    assert.equal(env.recipient[0].header.headers['alg'], 'A128GCM')
    assert.equal(env.recipient[1].header.headers['alg'], 'ECDH-ES+A128GCM')
    assert.equal(env.recipient[1].header.headers['kid'], 'bob')

    // Decrypt
    await env.decryptAt(1, bobKey)
    assert.deepEqual(env.payload, {data: 'Some data from Elixir land'})

    // Verify
    const verified = await env.verify(alicePubKey)
    assert.isTrue(verified)
  })

  it('parses script, decrypts and verifies sigs', async () => {
    // Decode envelope
    const env = Envelope.fromScript(Script.fromHex(script_env))
    assert.equal(env.header.headers['proto'], 'test')

    // Inspect signature
    assert.equal(env.signature.header.headers['alg'], 'ES256K')
    assert.equal(env.signature.header.headers['kid'], 'alice')

    // Inspect recipients
    assert.lengthOf(env.recipient, 2)
    assert.equal(env.recipient[0].header.headers['alg'], 'A128GCM')
    assert.equal(env.recipient[1].header.headers['alg'], 'ECDH-ES+A128GCM')
    assert.equal(env.recipient[1].header.headers['kid'], 'bob')

    // Decrypt
    await env.decryptAt(1, bobKey)
    assert.deepEqual(env.payload, {data: 'Some data from Elixir land'})

    // Verify
    const verified = await env.verify(alicePubKey)
    assert.isTrue(verified)
  })
})


//describe('create envelopes for testing externally', () => {
//  const aliceKey = Key.decode(Buffer.from(ALICE, 'hex'))
//  const bobPubKey = Key.decode(Buffer.from(BOB_PUB, 'hex'))
//
//  it('creates the envelope', async () => {
//    const key = await Key.generate('oct', 128)
//    const env = Envelope.wrap({ data: 'Some data from JS land' }, { proto: 'test' })
//
//    await env.sign(aliceKey, { alg: 'ES256K', kid: 'alice' })
//    await env.encrypt([
//      [key, { alg: 'A128GCM' }],
//      [bobPubKey, { alg: 'ECDH-ES+A128GCM', kid: 'bob' }]
//    ])
//
//    console.log(env.toString())
//    console.log(env.toScript().toHex())
//  })
//})
