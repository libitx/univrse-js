import { Buffer } from 'buffer'
import crypto from 'isomorphic-webcrypto'

/**
 * Algorithm parameters
 */
const params = {
  A128GCM: { keylen: 16 },
  A256GCM: { keylen: 32 },
}

/**
 * AES_GCM module. Sign and encrypt data using AES-GCM symetric encryption.
 */
const AES_GCM = {
  /**
   * Decrypts the cyphertext with the key using the specified algorithm.
   * 
   * Accepted options:
   * 
   * * `aad` - Ephemeral public key
   * * `iv` - Agreement PartyUInfo
   * * `tag` - Agreement PartyVInfo
   * 
   * @param {String} alg
   * @param {Buffer} encrypted
   * @param {Key} key
   * @param {Object} opts
   * @returns {Buffer}
   */
  async decrypt(alg, encrypted, key, { aad, iv, tag }) {
    assertKey(key, alg)

    encrypted = Buffer.concat([
      Buffer.from(encrypted),
      Buffer.from(tag)
    ])

    const additionalData = Buffer.from(aad ? aad : '')

    const eKey = await crypto.subtle.importKey('raw', key.params.k, 'AES-GCM', false, ['decrypt'])
    const result = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData }, eKey, encrypted)
    return Buffer.from(result)
  },

  /**
   * Encrypts the message with the key using the specified algorithm. Returns
   * an object containing the encrypted cyphertext and any headers to add to
   * the Recipient.
   * 
   * Accepted options:
   * 
   * * `aad` - Ephemeral public key
   * * `iv` - Agreement PartyUInfo
   * 
   * @param {String} alg
   * @param {Buffer|String} msg
   * @param {Key} key
   * @param {Object} opts
   * @returns {Object}
   */
  async encrypt(alg, msg, key, opts = {}) {
    assertKey(key, alg)

    const iv = opts.iv ? opts.iv : crypto.getRandomValues(new Uint8Array(12))
    const additionalData = Buffer.from(opts.aad ? opts.aad : '')

    const eKey = await crypto.subtle.importKey('raw', key.params.k, 'AES-GCM', false, ['encrypt'])
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, eKey, Buffer.from(msg))
    return {
      encrypted: Buffer.from(encrypted).slice(0, -16),
      iv: Buffer.from(iv),
      tag: Buffer.from(encrypted).slice(-16)
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
  const { keylen } = params[alg]
  if (key.type !== 'oct' || key.params.k.length !== keylen) {
    throw `Invalid key for ${alg} algorithm`
  }
}

export default AES_GCM