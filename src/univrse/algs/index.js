import AES_CBC_HMAC from './aes_cbc_hmac'
import AES_GCM from './aes_gcm'
import ECDH_AES from './ecdh_aes'
import ES256K from './es256k'
import HMAC from './hmac'

/**
 * All supported algorithms.
 */
const algs = {
  'A128CBC-HS256': AES_CBC_HMAC,
  'A256CBC-HS512': AES_CBC_HMAC,
  A128GCM: AES_GCM,
  A256GCM: AES_GCM,
  'ECDH-ES+A128GCM': ECDH_AES,
  'ECDH-ES+A256GCM': ECDH_AES,
  ES256K,
  HS256: HMAC,
  HS512: HMAC,

  get(alg) {
    if (this[alg]) {
      return this[alg]
    } else {
      throw `Unsupported algorithm: ${alg}`
    }
  }
}

/**
 * Proxy module for calling crypto functions on supported algorithms.
 */
export default {
  /**
   * Calls `decrypt()` on the given algorithm, passing the arguments through.
   * 
   * @param {String} alg 
   * @param  {...any} args
   * @returns {Buffer}
   */
  async decrypt(alg, ...args) {
    return algs.get(alg).decrypt(alg, ...args)
  },

  /**
   * Calls `encrypt()` on the given algorithm, passing the arguments through.
   * 
   * @param {String} alg 
   * @param  {...any} args
   * @returns {Buffer}
   */
  async encrypt(alg, ...args) {
    return algs.get(alg).encrypt(alg, ...args)
  },

  /**
   * Calls `sign()` on the given algorithm, passing the arguments through.
   * 
   * @param {String} alg 
   * @param  {...any} args
   * @returns {Buffer}
   */
  async sign(alg, ...args) {
    return algs.get(alg).sign(alg, ...args)
  },

  /**
   * Calls `verify()` on the given algorithm, passing the arguments through.
   * 
   * @param {String} alg 
   * @param  {...any} args
   * @returns {Boolean}
   */
  async verify(alg, ...args) {
    return algs.get(alg).verify(alg, ...args)
  }
}
