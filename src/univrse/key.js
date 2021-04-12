import { Buffer } from 'buffer'
import { KeyPair } from 'bsv'
import cbor from 'borc'
import crypto from 'isomorphic-webcrypto'
import Recipient from './recipient.js'
import algs from './algs/index.js'

/**
 * Key class
 * 
 * Univrse Keys mirror the API of, and are compatible with, JSON JWK keys.
 */
class Key {
  /**
   * Instantiates a new Key instance of the given type and parameters.
   * 
   * @param {String} type 
   * @param {Object} params
   * @constructor
   */
  constructor(type, params) {
    this.type = type
    this.params = params
  }

  /**
   * Decodes the given CBOR encoded key into a Key instance.
   * 
   * @param {Buffer} buf
   * @constructor
   */
  static decode(buf) {
    const { kty, ...params } = cbor.decode(buf)
    return new this(kty, params)
  }

  /**
   * Securely generates a new key of the given type and paramter.
   * 
   * ## Supported key types
   * 
   * Eliptic curve keys:
   * 
   * * `type` must be 'EC'
   * * `param` must be supported curve type, from: `secp256k1`
   * 
   * Octet byte sequence:
   * 
   * * `type` must be 'oct'
   * * `param` must be supported bit length, from: `128`, `256` or `512`
   * 
   * @param {String} type 
   * @param {String|Number} param
   * @constructor
   */
  static async generate(type, param) {
    if (type.toLowerCase() === 'ec' && param === 'secp256k1') {
      // generate secp256k1 key using bsv
      const key = KeyPair.fromRandom()
      return new this('EC', {
        crv: 'secp256k1',
        d: Buffer.from(key.privKey.bn.toArray('big', 32)),
        x: Buffer.from(key.pubKey.point.x.toArray('big', 32)),
        y: Buffer.from(key.pubKey.point.y.toArray('big', 32))
      })
    } else if (type.toLowerCase() == 'oct' && [128, 256, 512].includes(param)) {
      // use generateKey() as getRandomValues() is not guaranteed to
      // run in a secure context
      const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: param }, true, ['encrypt', 'decrypt'])
      const buf = await crypto.subtle.exportKey('raw', key)
      return new this('oct', { k: Buffer.from(buf) })
    } else {
      throw 'Invalid key type or param'
    }
  }

  /**
   * Encrypts the key using the given encryption key, and returns the encrypted
   * key wrapped in a Recipient instance.
   * 
   * A headers object must be given including at least the encryption `alg`
   * value.
   * 
   * A third argument of options can be given for the relevant encryption
   * algorithm.
   * 
   * @param {Key} key encryption key
   * @param {Object} headers
   * @param {Object} opts
   * @returns {Recipient}
   */
  async encrypt(key, headers = {}, opts = {}) {
    const { alg } = headers
    const encOpts = {
      ...opts,
      ...['iv'].reduce((o, k) => { o[k] = headers[k]; return o }, {})
    }

    const { encrypted, ...newHeaders } = await algs.encrypt(alg, this.toBuffer(), key, encOpts)
    return Recipient.wrap(encrypted, { ...headers, ...newHeaders })
  }

  /**
   * Returns the Key as a CBOR encoded Buffer.
   * 
   * @returns {Buffer}
   */
  toBuffer() {
    return cbor.encode(this.toObject())
  }

  /**
   * Returns the Key as a JWK compatible object.
   * 
   * @returns {Object}
   */
  toObject() {
    return {
      ...this.params,
      kty: this.type
    }
  }

  /**
   * Returns a public key from the current key, which can be safely shared with
   * other parties.
   * 
   * Only for use with `EC` key types.
   * 
   * @returns {Key}
   */
  toPublic() {
    if (this.type === 'EC') {
      const { crv, x, y } = this.params
      return new this.constructor('EC', { crv, x, y })
    } else {
      throw `Cannot convert key type '${ this.type }' to public key`
    }
  }
}

export default Key