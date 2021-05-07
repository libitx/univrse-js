import { Buffer } from 'buffer'
import { Bn, Point, PubKey } from 'bsv'
import crypto from 'isomorphic-webcrypto'
import Key from '../key'
import { fromBsvPubKey } from '../util'


/**
 * ECIES_BIE1 module. Implements Electrum-flavoured ECIES encryption and
 * decryption.
 */
const ECIES_BIE1 = {
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

    const len = encrypted.length - 69,
          prefix = encrypted.slice(0, 4),
          ephemeralPubKeyBuf = encrypted.slice(4, 4 + 33),
          cipher = encrypted.slice(4 + 33, 4 + 33 + len),
          mac = encrypted.slice(4 + 33 + len);

    if (prefix.toString() !== 'BIE1') throw 'invalid magic bytes';

    // Derive ECDH key and sha512 hash
    const ephemeralPubKey = fromBsvPubKey(PubKey.fromDer(ephemeralPubKeyBuf))
    const keyHash = await crypto.subtle.digest('SHA-512', computeSharedSecret(key, ephemeralPubKey))

    // iv and keyE used in AES, keyM used in HMAC
    const iv = keyHash.slice(0, 16),
          keyE = keyHash.slice(16, 32),
          keyM = keyHash.slice(32);

    // HMAC validation
    const macKey = await crypto.subtle.importKey('raw', keyM, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
    const verified = await crypto.subtle.verify({ name: 'HMAC' }, macKey, mac, encrypted.slice(0, -32))
    if (!verified) throw 'mac validation failed';

    // Decrypt cyphertext
    const encKey = await crypto.subtle.importKey('raw', keyE, 'AES-CBC', false, ['decrypt'])
    const result = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, encKey, cipher)
    return Buffer.from(result)
  },

  /**
   * Encrypts the message with the key using the specified algorithm. Returns
   * an object containing the encrypted cyphertext and any headers to add to
   * the Recipient.
   * 
   * @param {String} alg
   * @param {Buffer|String} msg
   * @param {Key} key
   * @param {Object} opts
   * @returns {Object}
   */
  async encrypt(alg, msg, key, _opts = {}) {
    assertKey(key, alg)

    // Derive ECDH key and sha512 hash
    const ephemeralKey = await Key.generate('ec', 'secp256k1')
    const keyHash = await crypto.subtle.digest('SHA-512', computeSharedSecret(ephemeralKey, key))

    // iv and keyE used in AES, keyM used in HMAC
    const iv = keyHash.slice(0, 16),
          keyE = keyHash.slice(16, 32),
          keyM = keyHash.slice(32);
    
    // Create ciphertext
    const encKey = await crypto.subtle.importKey('raw', keyE, 'AES-CBC', false, ['encrypt'])
    const cipher = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, encKey, Buffer.from(msg))
    
    // Concat encrypted data with hmac
    const macKey = await crypto.subtle.importKey('raw', keyM, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    const macData = Buffer.concat([
      Buffer.from('BIE1'),
      pubKeyBuf(ephemeralKey),
      Buffer.from(cipher)
    ])
    const mac = await crypto.subtle.sign({ name: 'HMAC' }, macKey, macData)

    return {
      encrypted: Buffer.concat([macData, Buffer.from(mac)])
    }
  }
}

/**
 * Asserts the key is valid.
 * 
 * @param {Key} key 
 * @param {String} alg
 */
function assertKey(key, _alg) {
  if (key.type !== 'EC' || key.params.crv !== 'secp256k1') {
    throw `Invalid key for ECIES-BIE1 algorithm`
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

  return Buffer.concat([
    Buffer.from([s.y.isOdd() ? 0x03 : 0x02]),
    Buffer.from(s.x.toArray('big', 32))
  ])
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

export default ECIES_BIE1