import { Buffer } from 'buffer'
import { Bn, Point, PubKey } from 'bsv'
import crypto from 'isomorphic-webcrypto'
import Key from '../key'
import AES_GCM from './aes_gcm'

/**
 * Algorithm parameters
 */
const params = {
  'ECDH-ES+A128GCM': { enc: 'A128GCM', keylen: 16 },
  'ECDH-ES+A256GCM': { enc: 'A256GCM', keylen: 32 }
}

/**
 * ECDH_AES module. Implements ECDH-ES+AES_GCM encryption and decryption.
 * 
 * https://tools.ietf.org/html/rfc7518#section-4.6
 */
const ECDH_AES = {
  /**
   * Decrypts the cyphertext with the key using the specified algorithm.
   * 
   * Accepted options:
   * 
   * * `epk` - Ephemeral public key
   * * `apu` - Agreement PartyUInfo
   * * `apv` - Agreement PartyVInfo
   * * Any accepted AES_GCM options
   * 
   * @param {String} alg
   * @param {Buffer} encrypted
   * @param {Key} key
   * @param {Object} opts
   * @returns {Buffer}
   */
  async decrypt(alg, encrypted, key, opts = {}) {
    assertKey(key, alg)

    const { enc } = params[alg]
    const ePubKey = PubKey.fromBuffer(opts.epk)
    const ephemeralKey = new Key('ec', {
      crv: 'secp256k1',
      x: Buffer.from(ePubKey.point.x.toArray('big', 32)),
      y: Buffer.from(ePubKey.point.y.toArray('big', 32))
    })

    const secret = await kdf(computeSharedSecret(key, ephemeralKey), alg, opts)
    return AES_GCM.decrypt(enc, encrypted, new Key('oct', { k: secret }), opts)
  },

  /**
   * Encrypts the message with the key using the specified algorithm. Returns
   * an object containing the encrypted cyphertext and any headers to add to
   * the Recipient.
   * 
   * Accepted options:
   * 
   * * `apu` - Agreement PartyUInfo
   * * `apv` - Agreement PartyVInfo
   * * Any accepted AES_GCM options
   * 
   * @param {String} alg
   * @param {Buffer|String} msg
   * @param {Key} key
   * @param {Object} opts
   * @returns {Object}
   */
  async encrypt(alg, msg, key, opts = {}) {
    assertKey(key, alg)

    const { enc } = params[alg]
    const ephemeralKey = await Key.generate('ec', 'secp256k1')
    const secret = await kdf(computeSharedSecret(ephemeralKey, key), alg, opts)
    const result = await AES_GCM.encrypt(enc, msg, new Key('oct', { k: secret }), opts)

    return {
      ...result,
      epk: pubKeyBuf(ephemeralKey)
    }
  }
}

/**
 * Asserts the key is valid.
 * 
 * @param {Key} key 
 * @param {String} alg
 */
function assertKey(key, alg) {
  if (key.type !== 'EC' || key.params.crv !== 'secp256k1') {
    throw `Invalid key for ${alg} algorithm`
  }
}

/**
 * Computes and returns a ECDH shared secret from the given keys.
 * 
 * @param {Key} privKey
 * @param {Key} pubKey
 * @returns {Buffer}
 */
function computeSharedSecret(privKey, pubKey) {
  const x = Bn.fromBuffer(pubKey.params.x),
        y = Bn.fromBuffer(pubKey.params.y),
        d = Bn.fromBuffer(privKey.params.d),
        p = new Point(x, y),
        s = p.mul(d);
  return Buffer.from(s.x.toArray('big', 32))
}

/**
 * Implements Concat KDF as defined in NIST.800-56A.
 * 
 * @param {Buffer} secret
 * @param {String} alg
 * @param {Object} opts
 */
async function kdf(secret, alg, opts) {
  const { keylen } = params[alg]
  const algBuf = Buffer.from(alg),
        apuBuf = Buffer.from(opts.apu ? opts.apu : ''),
        apvBuf = Buffer.from(opts.apv ? opts.apv : ''),
        keylenInt = Buffer.alloc(4),
        algInt = Buffer.alloc(4),
        apuInt = Buffer.alloc(4),
        apvInt = Buffer.alloc(4);

  keylenInt.writeUInt32BE(keylen*8)
  algInt.writeUInt32BE(algBuf.length)
  apuInt.writeUInt32BE(apuBuf.length)
  apvInt.writeUInt32BE(apvBuf.length)

  const msg = Buffer.concat([
    secret,
    keylenInt,
    algInt, algBuf,
    apuInt, apuBuf,
    apvInt, apvBuf,
    Buffer.from('')
  ])

  const hash = await crypto.subtle.digest('SHA-256', msg)
  return Buffer.from(hash).slice(0, keylen)
}

/**
 * Converts a Key to a Buffer
 * 
 * @param {Key} key
 * @returns {Buffer}
 */
function pubKeyBuf(key) {
  const x = Bn.fromBuffer(key.params.x),
        y = Bn.fromBuffer(key.params.y),
        p = new Point(x, y),
        pubKey = new PubKey(p);

  return pubKey.toBuffer()
}

export default ECDH_AES