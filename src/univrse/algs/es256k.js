import { Buffer } from 'buffer'
import { Ecdsa, Hash, KeyPair, Sig } from 'bsv'
import { toPrivKey, toPubKey } from '../util'

/**
 * ES256K module. Implements ECDSA signatures on the secp256k1 curve.
 */
 export const ES256K = {
  /**
   * Signs the message with the key using the specified algorithm.
   * 
   * @param {String} alg
   * @param {Buffer|String} msg
   * @param {Key} key
   * @returns {Buffer}
   */
  async sign(alg, msg, key) {
    assertKey(key, alg)

    const hashBuf = Hash.sha256(Buffer.from(msg))
    const keyPair = KeyPair.fromPrivKey(toPrivKey(key))

    const sig = new Ecdsa().fromObject({ hashBuf, keyPair })
      .sign()
      .calcrecovery()
      .sig

    return sig.toCompact()
  },

  /**
   * Verifies the signature with the message and key, using the specified
   * algorithm.
   * 
   * @param {String} alg
   * @param {Buffer|String} msg
   * @param {Buffer} sig
   * @param {Key} key
   * @returns {Boolean}
   */
  async verify(alg, msg, signature, key) {
    assertKey(key, alg)

    const hashBuf = Hash.sha256(Buffer.from(msg))
    const sig = new Sig().fromCompact(Buffer.from(signature))
    const keyPair = new KeyPair()
    keyPair.pubKey = toPubKey(key)

    const ecdsa = new Ecdsa().fromObject({ hashBuf, sig, keyPair })
    ecdsa.verify()
    return ecdsa.verified
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
    throw 'Invalid key for ES256K algorithm'
  }
}

export default ES256K