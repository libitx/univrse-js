import Header from './header.js'
import Key from './key.js'
import algs from './algs/index.js'

/**
 * Recipient class
 * 
 * A Univrse Recipient is a structure wrapping a set of headers and an optional
 * content encryption key.
 */
class Recipient {
  /**
   * Instantiates a new Recipient instance with the given params.
   * 
   * Accepted params
   * 
   * * `headers` - headers object
   * * `key` - content encryption key
   * 
   * @param {Object} params
   * @constructor
   */
  constructor({ headers, key }) {
    this.header = Header.wrap(headers)
    this.key = key
  }

  /**
   * Instantiates a new Recipient instance with the given array of parts.
   * 
   * Used internally when decoding CBOR encoded recipients.
   * 
   * @param {Array} parts
   * @constructor
   */
  static fromArray(parts) {
    if (parts.length === 2 && typeof parts[0] === 'object' && typeof parts[0].alg === 'string') {
      return new this({ headers: parts[0], key: parts[1] })
    } else {
      return parts.map(p => this.fromArray(p))
    }
  }

  /**
   * Wraps the given key and headers in a new Recipient instance.
   * 
   * @param {Key|Buffer} key Key instance or encrypted key
   * @param {Object} headers
   * @constructor
   */
  static wrap(key, headers = {}) {
    return new this({ headers, key })
  }

  /**
   * Decrypts the key using the given encryption key.
   * 
   * An second argument of options can be given for the relevant encryption
   * algorithm.
   * 
   * @param {Key} key
   * @param {Object} opts
   * @returns {Recipient}
   */
  async decrypt(key, opts = {}) {
    const { alg } = this.header.headers

    const encOpts = {
      ...opts,
      ...['epk', 'iv', 'tag'].reduce((o, k) => { o[k] = this.header.headers[k]; return o }, {})
    }

    const encodedKey = await algs.decrypt(alg, this.key, key, encOpts)
    this.key = Key.decode(encodedKey)
    return this
  }

  /**
   * Returns the Recipient as an array of component parts.
   * 
   * Used internally prior to encoding the recipient.
   * 
   * @returns {Array}
   */
  toArray() {
    return [this.header.unwrap(), this.key]
  }
}

export default Recipient