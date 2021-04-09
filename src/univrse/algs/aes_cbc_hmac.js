import { Buffer } from 'buffer'
import crypto from 'isomorphic-webcrypto'

/**
 * Algorithm parameters
 */
const params = {
  'A128CBC-HS256': { keylen: 32, hash: 'SHA-256' },
  'A256CBC-HS512': { keylen: 64, hash: 'SHA-512' }
}

/**
 * AES_CBC_HMAC module. Sign and encrypt data using AES-CBC symetric encryption,
 * with HMAC for message authentication.
 * 
 * https://tools.ietf.org/html/rfc7518#section-5.2.2
 */
const AES_CBC_HMAC = {
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

    const { hash } = params[alg]
    const { e, m } = splitKey(key)
    const additionalData = Buffer.from(aad ? aad : '')

    const eKey = await crypto.subtle.importKey('raw', e, 'AES-CBC', false, ['decrypt'])
    const mKey = await crypto.subtle.importKey('raw', m, { name: 'HMAC', hash }, false, ['verify'])
    const macmsg = createMacMessage({ additionalData, iv, encrypted })

    if (await crypto.subtle.verify('HMAC', mKey, tag, macmsg)) {
      const result = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, eKey, encrypted)
      return Buffer.from(result)
    } else {
      throw 'HMAC validation failed'
    }
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

    const { hash } = params[alg]
    const { e, m } = splitKey(key)
    const iv = opts.iv ? opts.iv : crypto.getRandomValues(new Uint8Array(16))
    const additionalData = Buffer.from(opts.aad ? opts.aad : '')

    const eKey = await crypto.subtle.importKey('raw', e, 'AES-CBC', false, ['encrypt'])
    const mKey = await crypto.subtle.importKey('raw', m, { name: 'HMAC', hash }, false, ['sign'])
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, eKey, Buffer.from(msg))
    const macmsg = createMacMessage({ additionalData, iv, encrypted })
    const tag = await crypto.subtle.sign('HMAC', mKey, macmsg)
    return {
      encrypted: Buffer.from(encrypted),
      iv: Buffer.from(iv),
      tag: Buffer.from(tag)
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

/**
 * Splits the key into two buffers - encryption key and mac key.
 * 
 * @param {Key} key 
 * @returns {Object}
 */
function splitKey(key) {
  const keylen = key.params.k.length / 2
  const m = key.params.k.slice(0, keylen)
  const e = key.params.k.slice(keylen)
  return { e, m }
}

/**
 * Creates the MAC message as per https://tools.ietf.org/html/rfc7518#section-5.2.2
 * 
 * @param {Object} opts
 * @param {Buffer} opts.additionalData
 * @param {Buffer} opts.iv
 * @param {Buffer} opts.encrypted
 * @returns {Buffer}
 */
function createMacMessage({ additionalData, iv, encrypted }) {
  const aadLenBuf = Buffer.alloc(8, 0)
  aadLenBuf.writeUInt32BE(additionalData.length >> 8, 0)
  aadLenBuf.writeUInt32BE(additionalData.length & 0x00ff, 4)

  return Buffer.concat([
    additionalData,
    Buffer.from(iv),
    Buffer.from(encrypted),
    aadLenBuf
  ])
}

export default AES_CBC_HMAC