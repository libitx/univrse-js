import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { Key } from '../../src/index'
import algs from '../../src/univrse/algs'

chai.use(chaiAsPromised)
const { assert } = chai

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
  k: Buffer.from([102, 163, 155, 242, 130, 52, 132, 60, 80, 152, 205, 43, 218, 103, 174, 176, 13, 26, 25, 171, 7, 111, 203, 111, 245, 169, 121, 187, 239, 14, 253,
    118, 200, 84, 18, 231, 163, 199, 5, 238, 136, 94, 127, 102, 35, 196, 126, 240, 181, 37, 163, 121, 105, 110, 88, 70, 208, 248, 224, 10, 89, 209, 150, 131])
})


const es256kSig = Buffer.from([
  32, 16, 194, 9, 63, 13, 122, 78, 39, 16, 18, 139, 242, 58, 137, 10, 177, 213, 48, 68, 143, 4, 146, 67, 196, 237, 227, 211, 93, 214, 113, 101, 170, 98, 109,
  159, 12, 228, 57, 187, 236, 185, 163, 90, 135, 218, 62, 80, 208, 157, 5, 141, 228, 8, 215, 148, 101, 233, 242, 6, 62, 95, 8, 52, 198])
const es256kBsmSig = Buffer.from([
    31, 21, 105, 207, 133, 3, 239, 35, 126, 207, 145, 253, 69, 196, 64, 126, 140, 214, 235, 197, 237, 133, 56, 2, 43, 156, 56, 193, 201, 43, 180, 111, 24, 74,
    56, 129, 250, 130, 242, 45, 205, 244, 46, 221, 152, 116, 149, 204, 30, 228, 57, 93, 114, 64, 20, 217, 76, 98, 173, 128, 106, 242, 233, 168, 146])
const hs256Sig = Buffer.from([
    26, 61, 97, 208, 153, 53, 69, 235, 105, 51, 91, 10, 56, 62, 201, 79, 109, 174, 65, 171, 226, 37, 213, 101, 90, 172, 82, 13, 250, 134, 119, 91])
const hs512Sig = Buffer.from([
    244, 57, 145, 234, 205, 200, 237, 33, 242, 229, 58, 153, 175, 148, 159, 98, 13, 87, 79, 255, 236, 232, 207, 142, 199, 197, 70, 51, 208, 175, 75, 242, 115,
    0, 206, 209, 63, 224, 209, 98, 51, 168, 166, 70, 115, 5, 9, 64, 150, 100, 147, 117, 107, 221, 133, 24, 248, 206, 163, 216, 50, 93, 181, 184])


const gcmIv = Buffer.from([254, 83, 226, 198, 180, 6, 208, 104, 179, 81, 188, 197])
const gcm128Enc = Buffer.from([34, 12, 62, 38, 218, 224, 165, 167, 186, 23, 67, 255])
const gcm256Enc = Buffer.from([122, 118, 227, 209, 232, 74, 73, 45, 24, 184, 7, 36])


describe('alg.encrypt() and alg.decrypt()', () => {
  it('encrypts and decrypts the message with the A128CBC-HS256 alg', async () => {
    const {encrypted, iv, tag} = await algs.encrypt('A128CBC-HS256', 'Hello world!', oct256Key)
    const result = await algs.decrypt('A128CBC-HS256', encrypted, oct256Key, { iv, tag })
    assert.equal(result.toString(), 'Hello world!')
  })

  it('encrypts and decrypts the message with the A256CBC-HS512 alg', async () => {
    const {encrypted, iv, tag} = await algs.encrypt('A256CBC-HS512', 'Hello world!', oct512Key)
    const result = await algs.decrypt('A256CBC-HS512', encrypted, oct512Key, { iv, tag })
    assert.equal(result.toString(), 'Hello world!')
  })

  it('encrypts and decrypts the message with the A128GCM alg', async () => {
    const {encrypted, iv, tag} = await algs.encrypt('A128GCM', 'Hello world!', oct128Key)
    const result = await algs.decrypt('A128GCM', encrypted, oct128Key, { iv, tag })
    assert.equal(result.toString(), 'Hello world!')
  })

  it('encrypts and decrypts the message with the A256GCM alg', async () => {
    const {encrypted, iv, tag} = await algs.encrypt('A256GCM', 'Hello world!', oct256Key)
    const result = await algs.decrypt('A256GCM', encrypted, oct256Key, { iv, tag })
    assert.equal(result.toString(), 'Hello world!')
  })

  it('encrypts and decrypts the message with the ECDH-ES+A128GCM alg', async () => {
    const {encrypted, iv, tag, epk} = await algs.encrypt('ECDH-ES+A128GCM', 'Hello world!', ecKey)
    const result = await algs.decrypt('ECDH-ES+A128GCM', encrypted, ecKey, { iv, tag, epk })
    assert.equal(result.toString(), 'Hello world!')
  })

  it('encrypts and decrypts the message with the ECIES-BIE1 alg', async () => {
    const {encrypted} = await algs.encrypt('ECIES-BIE1', 'Hello world!', ecKey)
    const result = await algs.decrypt('ECIES-BIE1', encrypted, ecKey)
    assert.equal(result.toString(), 'Hello world!')
  })
})


describe('alg.encrypt()', () => {
  it('encrypts the message with the A128GCM alg and known iv', async () => {
    const {encrypted, ...headers} = await algs.encrypt('A128GCM', 'Hello world!', oct128Key, { iv: gcmIv })
    assert.deepEqual(encrypted, gcm128Enc)
  })

  it('encrypts the message with the A256GCM alg and known iv', async () => {
    const {encrypted, ...headers} = await algs.encrypt('A256GCM', 'Hello world!', oct256Key, { iv: gcmIv })
    assert.deepEqual(encrypted, gcm256Enc)
  })

  it('throws error if alg not recognised', async () => {
    await assert.isRejected(algs.encrypt('FOOBAR', 'Hello world!', oct128Key), 'Unsupported algorithm: FOOBAR')
  })

  it('xy123 throws error if key and alg mismatch', async () => {
    await assert.isRejected(algs.encrypt('A128CBC-HS256', 'Hello world!', oct128Key), 'Invalid key for A128CBC-HS256 algorithm')
  })
})


describe('alg.decrypt()', () => {
  it('decrypts a message from bsv.js using the ECIES-BIE1 alg', async () => {
    const encrypted = Buffer.from('QklFMQMIQhsRI05VZZDvO74hMGv/0j8EmvmR22Zwn3dn5mnNcYLEgAXGdpwQIvX5/CmiCQZ3WvQFPFhDu+Nz2om8ta8vwaILdEnGInL+CpAykhlkDg==', 'base64')
    const result = await algs.decrypt('ECIES-BIE1', encrypted, ecKey)
    assert.equal(result.toString(), 'Hello world!')
  })
})


describe('alg.sign()', () => {
  it('signs the message with the ES256K alg', async () => {
    const sig = await algs.sign('ES256K', 'Hello world!', ecKey)
    assert.deepEqual(sig, es256kSig)
  })

  it('signs the message with the ES256K-BSM alg', async () => {
    const sig = await algs.sign('ES256K-BSM', 'Hello world!', ecKey)
    assert.deepEqual(sig, es256kBsmSig)
  })

  it('signs the message with the HS256 alg', async () => {
    const sig = await algs.sign('HS256', 'Hello world!', oct256Key)
    assert.deepEqual(sig, hs256Sig)
  })

  it('signs the message with the HS512 alg', async () => {
    const sig = await algs.sign('HS512', 'Hello world!', oct256Key)
    assert.deepEqual(sig, hs512Sig)
  })

  it('throws error if alg not recognised', async () => {
    await assert.isRejected(algs.sign('FOOBAR', 'Hello world!', ecKey), 'Unsupported algorithm: FOOBAR')
  })

  it('throws error if key and alg mismatch', async () => {
    await assert.isRejected(algs.sign('ES256K', 'hello world!', oct256Key), 'Invalid key for ES256K algorithm')
  })
})


describe('alg.verify()', () => {
  it('verifies the message signed with the ES256K alg', async () => {
    await assert.becomes(algs.verify('ES256K', 'Hello world!', es256kSig, ecKey), true)
  })

  it('verifies the message signed with the ES256K-BSM alg', async () => {
    await assert.becomes(algs.verify('ES256K-BSM', 'Hello world!', es256kBsmSig, ecKey), true)
  })

  it('verifies the message signed with the HS256 alg', async () => {
    await assert.becomes(algs.verify('HS256', 'Hello world!', hs256Sig, oct256Key), true)
  })

  it('verifies the message signed with the HS512 alg', async () => {
    await assert.becomes(algs.verify('HS512', 'Hello world!', hs512Sig, oct256Key), true)
  })

  it('throws error if alg not recognised', async () => {
    await assert.isRejected(algs.verify('FOOBAR', 'Hello world!', es256kSig, ecKey), 'Unsupported algorithm: FOOBAR')
  })

  it('throws error if key and alg mismatch', async () => {
    await assert.isRejected(algs.verify('ES256K', 'Hello world!', hs256Sig, oct256Key), 'Invalid key for ES256K algorithm')
  })
})
