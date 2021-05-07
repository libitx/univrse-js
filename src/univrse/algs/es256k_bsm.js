import { Buffer } from 'buffer'
import { Bw, Ecdsa, Hash, KeyPair, Sig } from 'bsv'
import { toBsvPrivKey, toBsvPubKey } from '../util'

/**
 * ES256K_BSM module. Calculates a message digest using the Bitcoin Signed
 * Message algorithm, and uses 65 byte compact signatures.
 */
 export const ES256K_BSM = {
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

    const hashBuf = messageDigest(msg)
    const keyPair = KeyPair.fromPrivKey(toBsvPrivKey(key))

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

    const hashBuf = messageDigest(msg)
    const sig = new Sig().fromCompact(Buffer.from(signature))
    const keyPair = new KeyPair()
    keyPair.pubKey = toBsvPubKey(key)

    const ecdsa = new Ecdsa().fromObject({ hashBuf, sig, keyPair })
    ecdsa.verify()
    return ecdsa.verified
  }
}

/**
 * Creates a digest of the given message using the Bitcoin Signed Message
 * algorithm.
 * 
 * @param {Buffer|String} msg 
 * @returns {Buffer}
 */
function messageDigest(msg) {
  const prefix = Buffer.from('Bitcoin Signed Message:\n'),
        msgBuf = Buffer.from(msg);

  const concatMsg = Buffer.concat([
    Bw.varIntBufNum(prefix.length),
    prefix,
    Bw.varIntBufNum(msgBuf.length),
    msgBuf
  ])

  return Hash.sha256Sha256(concatMsg)
}

/**
 * Asserts the key is valid.
 * 
 * @param {Key} key 
 * @param {String} alg
 */
function assertKey(key, _alg) {
  if (key.type !== 'EC' || key.params.crv !== 'secp256k1') {
    throw 'Invalid key for ES256K-BSM algorithm'
  }
}

export default ES256K_BSM