import { Buffer } from 'buffer'
import crypto from 'isomorphic-webcrypto'

/**
 * Algorithm parameters
 */
const params = {
  HS256: { hash: 'SHA-256' },
  HS512: { hash: 'SHA-512' },
}

/**
 * HMAC module.
 */
 export const HMAC = {
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

    const { hash } = params[alg]
    const mKey = await crypto.subtle.importKey('raw', key.params.k, { name: 'HMAC', hash }, false, ['sign'])
    const sig = await crypto.subtle.sign('HMAC', mKey, Buffer.from(msg))
    return Buffer.from(sig)
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
  async verify(alg, msg, sig, key) {
    assertKey(key, alg)

    const { hash } = params[alg]
    const mKey = await crypto.subtle.importKey('raw', key.params.k, { name: 'HMAC', hash }, false, ['verify'])
    return crypto.subtle.verify('HMAC', mKey, sig, Buffer.from(msg))
  }
}

/**
 * Asserts the key is valid.
 * 
 * @param {Key} key 
 * @param {String} alg 
 */
function assertKey(key, alg) {
  if (key.type !== 'oct') {
    throw `Invalid key for ${alg} algorithm`
  }
}

export default HMAC