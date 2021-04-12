import { OpCode, Script } from 'bsv'
import cbor from 'borc'
import base64url from 'base64url'
import Header from './header.js'
import Recipient from './recipient.js'
import Signature from './signature.js'
import algs from './algs/index.js'

const UNIVRSE_PREFIX = 'UNIV'

/**
 * Envelope class
 * 
 * A Univrse Envelope is a structure containing a set of headers, a payload,
 * and optionally one or more Signatures and Recipients.
 * 
 * An Envelope can be converted to a compact CBOR encoded buffer, a Base64
 * encoded string, or a Bitcoin OP_RETURN Script. This allows envelopes to be
 * easily and efficiently transferred between different parties, who in turn can
 * decode the wrapped payload.
 */
class Envelope {
  /**
   * Instantiates a new Envelope instance with the given params.
   * 
   * Accepted params
   * 
   * * `headers` - headers object
   * * `payload` - data payload
   * * `signature` - singature instance or array of signatures
   * * `recipient` - recipient instance or array of recipients
   * 
   * @param {Object} params
   * @constructor
   */
  constructor({ headers, payload, signature, recipient }) {
    this.header = Header.wrap(headers)
    this.payload = payload
    this.signature = signature
    this.recipient = recipient
  }

  /**
   * Instantiates a new Envelope instance with the given array of parts.
   * 
   * Used internally when decoding envelopes.
   * 
   * @param {Array} parts
   * @constructor
   */
  static fromArray(parts) {
    return new this({
      headers: parts[0],
      payload: parts[1],
      signature: Array.isArray(parts[2]) ? Signature.fromArray(parts[2]) : undefined,
      recipient: Array.isArray(parts[3]) ? Recipient.fromArray(parts[3]) : undefined
    })
  }

  /**
   * Decodes the given buffer and instantiates a new Envelope instance.
   * 
   * @param {Buffer} buf
   * @constructor
   */
  static fromBuffer(buf) {
    return this.fromArray(cbor.decode(buf))
  }

  /**
   * Decodes the given Bitcoin Script and instantiates a new Envelope instance.
   * 
   * @param {Script} script
   * @constructor
   */
  static fromScript(script) {
    const idx = script.chunks.findIndex((c, i, chunks) => {
      return c.opCodeNum === 106 && chunks[i+1].buf
        && chunks[i+1].buf.toString() === UNIVRSE_PREFIX
    })

    if (idx >= 0) {
      const parts = script.chunks.slice(idx+2).map(c => cbor.decode(c.buf))
      return this.fromArray(parts)
    } else {
      throw 'Invalid Univrse script'
    }
  }

  /**
   * Decodes the given base64 string and instantiates a new Envelope instance.
   * 
   * @param {String} str
   * @constructor
   */
  static fromString(str) {
    const parts = str.split('.')
      .map(s => {
        const buf = base64url.toBuffer(s)
        return cbor.decode(buf)
      })

    return this.fromArray(parts)
  }

  /**
   * Wraps the given payload and headers in a new Envelope instance.
   * 
   * @param {*} payload
   * @param {Object} headers
   * @constructor
   */
  static wrap(payload, headers = {}) {
    return new this({ headers, payload })
  }

  /**
   * CBOR encoded payload
   * 
   * @type {Buffer}
   */
  get encodedPayload() {
    return cbor.encode(this.payload)
  }

  /**
   * Sets the payload by decoding the given encoded payload.
   * 
   * @type {Buffer}
   */
  set encodedPayload(payload) {
    this.payload = cbor.decode(payload)
  }

  /**
   * Decrypts the payload using the given key.
   * 
   * If the Envelope contains multiple recipients, it is assumed the key belongs
   * to the first recipient. Otherwise, see `decryptAt()`.
   * 
   * An second argument of options can be given for the relevant encryption
   * algorithm.
   * 
   * @param {Key} key
   * @param {Object} opts
   * @returns {Envelope}
   */
  async decrypt(key, opts = {}) {
    const header = Array.isArray(this.recipient) ? this.recipient[0].header : this.recipient.header
    const { alg } = header.headers
    const aad = cbor.encode([
      'enc',
      this.header.unwrap(),
      opts.aad ? opts.aad : ''
    ])

    const encOpts = {
      ...opts,
      ...['epk', 'iv', 'tag'].reduce((o, k) => { o[k] = header.headers[k]; return o }, {}),
      aad
    }

    this.encodedPayload = await algs.decrypt(alg, this.payload, key, encOpts)
    return this
  }

  /**
   * Decrypts the payload by first decrypting the content key at the specified
   * recipient index.
   * 
   * The Envelope mustcontains multiple recipients.
   * 
   * @param {Number} i recipient index
   * @param {Key} key
   * @param {Object} opts
   * @returns {Envelope}
   */
   async decryptAt(i, key, opts = {}) {
    if (!Array.isArray(this.recipient) || this.recipient.length <= i) {
      throw 'Invalid recipient index'
    }

    await this.recipient[i].decrypt(key, opts)
    return this.decrypt(this.recipient[i].key, opts)
   }

  /**
   * Encrypts the payload using the given key or array of keys.
   * 
   * A headers object must be given including at least the encryption `alg`
   * value.
   * 
   * A third argument of options can be given for the relevant encryption
   * algorithm.
   * 
   * Where an array of keys is given, the first key is taken as the content key
   * and used to encrypt the payload. The content key is then encrypted by each
   * subsequent key and included in the Recipient instances that are attached to
   * the envelope.
   * 
   * When encrypting to multiple recipients, it is possible to specify different
   * algorithms for each key by giving an array of two element arrays. The first
   * element of each pair is the key and the second is a headers object.
   * 
   * ## Examples
   * 
   * Encrypts for a single recipient:
   * 
   *    envelope.encrypt(aesKey, { alg: 'A128GCM' })
   * 
   * Encrypts for a multiple recipients using the same algorithm:
   * 
   *    envelope.encrypt([aesKey, recKey], { alg: 'A128GCM' })
   * 
   * Encrypts for a multiple recipients using different algorithms:
   * 
   *    envelope.encrypt([
   *      aesKey,
   *      [rec1Key, { alg: 'ECDH-ES+A128GCM' }],
   *      [rec2Key, { alg: 'ECDH-ES+A128GCM' }],
   *    ], { alg: 'A128GCM' })
   * 
   * @param {Key|Key[]|[Key, Object][]} key encryption key or array of keys
   * @param {Object} headers
   * @param {Object} opts
   * @returns {Envelope}
   */
  async encrypt(key, headers = {}, opts = {}) {
    if (Array.isArray(key)) {
      const [mkey, mheaders] = mergeKeyHeaders(key[0], headers)
      await this.encrypt(mkey, mheaders)
      let kkey, kheaders, krecipient
      for (let i = 1; i < key.length; i++) {
        [kkey, kheaders] = mergeKeyHeaders(key[i], headers)
        krecipient = await mkey.encrypt(kkey, kheaders, opts)
        this.pushRecipient(krecipient)
      }
      return this
    }

    const { alg } = headers
    const aad = cbor.encode([
      'enc',
      this.header.unwrap(),
      opts.aad ? opts.aad : ''
    ])

    const encOpts = {
      ...opts,
      ...['iv'].reduce((o, k) => { o[k] = headers[k]; return o }, {}),
      aad
    }

    const { encrypted, ...newHeaders } = await algs.encrypt(alg, this.encodedPayload, key, encOpts)
    this.payload = encrypted
    const recipient = Recipient.wrap(null, { ...headers, ...newHeaders })
    return this.pushRecipient(recipient)
  }

  /**
   * Attaches the given Recipient instance onto the Envelope.
   * 
   * @param {Recipient} recipient
   * @returns {Envelope}
   */
  pushRecipient(recipient) {
    if (Array.isArray(this.recipient)) {
      this.recipient.push(recipient)
    } else if (this.recipient) {
      this.recipient = [this.recipient, recipient]
    } else {
      this.recipient = recipient
    }
    return this
  }

  /**
   * Attaches the given Signature instance onto the Envelope.
   * 
   * @param {Signature} signature
   * @returns {Envelope}
   */
  pushSignature(signature) {
    if (Array.isArray(this.signature)) {
      this.signature.push(signature)
    } else if (this.signature) {
      this.signature = [this.signature, signature]
    } else {
      this.signature = signature
    }
    return this
  }

  /**
   * Signs the payload using the given key or array of keys.
   * 
   * A headers object must be given including at least the signature `alg`
   * value.
   * 
   * Where an array of keys is given, it is possible to specify different
   * algorithms for each key by giving an array of two element arrays. The first
   * element of each pair is the key and the second is a headers object.
   * 
   * ## Examples
   * 
   * Creates a signature using a single key:
   * 
   *    envelope.sign(octKey, { alg: 'HS256' })
   * 
   * Creates multiple signatures using the same algorithm:
   * 
   *    envelope.sign([userKey, appKey], { alg: 'HS256' })
   * 
   * Creates multiple signatures using different algorithms:
   * 
   *    envelope.sign([
   *      octKey,
   *      [ecKey1, { alg: 'ES256K' }],
   *      [ecKey2, { alg: 'ES256K' }]
   *    ], { alg: 'HS256' })
   * 
   * @param {Key|Key[]|[Key, Object][]} key signing key or array of keys
   * @param {Object} headers
   * @returns {Envelope}
   */
  async sign(key, headers = {}) {
    if (Array.isArray(key)) {
      for (let i = 0; i < key.length; i++) {
        if (Array.isArray(key[i]) && key[i].length === 2) {
          await this.sign(key[i][0], { ...headers, ...key[i][1] })
        } else {
          await this.sign(key[i], headers)
        }
      }
      return this
    }

    const alg = {
      ...this.header.headers,
      ...headers
    }['alg']

    const data = cbor.encode(this.toArray().slice(0, 2))
    const sig = await algs.sign(alg, data, key)
    return this.pushSignature(Signature.wrap(sig, headers))
  }

  /**
   * Returns the Envelope as an array of component parts.
   * 
   * Used internally prior to encoding the envelope.
   * 
   * @returns {Array}
   */
  toArray() {
    const parts = [
      this.header.unwrap(),
      this.payload
    ]

    if (Array.isArray(this.signature)) {
      parts.push(this.signature.map(s => s.toArray()))
    } else if (this.signature && typeof this.signature.toArray === 'function') {
      parts.push(this.signature.toArray())
    } else if (this.recipient) {
      parts.push(null)
    }

    if (Array.isArray(this.recipient)) {
      parts.push(this.recipient.map(s => s.toArray()))
    } else if (this.recipient && typeof this.recipient.toArray === 'function') {
      parts.push(this.recipient.toArray())
    }

    return parts
  }

  /**
   * Returns the Envelope as a CBOR encoded Buffer.
   * 
   * @returns {Buffer}
   */
  toBuffer() {
    return cbor.encode(this.toArray())
  }

  /**
   * Returns the Envelope as bsv Script instance.
   * 
   * @param {Boolean} [falseReturn=true]
   * @returns {String}
   */
  toScript(falseReturn = true) {
    const script = new Script()
    if (falseReturn) {
      script.writeOpCode(OpCode.OP_FALSE)
    }
    script.writeOpCode(OpCode.OP_RETURN)
    script.writeBuffer(Buffer.from(UNIVRSE_PREFIX))

    return this.toArray()
      .reduce((s, p) => {
        return s.writeBuffer(cbor.encode(p))
      }, script)
  }

  /**
   * Returns the Envelope as Base64 encoded string.
   * 
   * @returns {String}
   */
  toString() {
    return this.toArray()
      .map(p => base64url.encode(cbor.encode(p)))
      .join('.')
  }

  /**
   * Verifies the signature(s) using the given Key or array of Keys.
   * 
   * Where the envelope has multiple signature, can optionally specfify the
   * signature index the key relates to.
   * 
   * @param {Key|Key[]} key key or array of keys
   * @param {Number} i signature index
   * @returns {Boolean}
   */
  async verify(key, i) {
    // If index not provided and array of keys, iterate over each and verify each signature
    if (!i && Array.isArray(key) && Array.isArray(this.signature) && key.length === this.signature.length) {
      const verifications = key.map((k, i) => this.verify(k, i))
      const results = await Promise.all(verifications)
      return results.every(r => r === true)
    }
    
    // If index is given use the specified signature
    let signature = this.signature
    if (Number.isInteger(i) && Array.isArray(this.signature)) {
      signature = this.signature[i]
    }

    const alg = {
      ...this.header.headers,
      ...signature.header.headers
    }['alg']

    const data = cbor.encode(this.toArray().slice(0, 2))
    return algs.verify(alg, data, signature.signature, key)
  }
}

/**
 * Helper function to merge key headers
 */
function mergeKeyHeaders(key, headers) {
  if (Array.isArray(key) && key.length === 2) {
    return [key[0], { ...headers, ...key[1] }]
  } else {
    return [key, headers]
  }
}

export default Envelope