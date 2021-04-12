import Header from './header.js'

/**
 * Key class
 * 
 * A Univrse Signature is a structure wrapping a set of headers and the raw
 * signature.
 */
class Signature {
  /**
   * Instantiates a new Signature instance with the given params.
   * 
   * Accepted params
   * 
   * * `headers` - headers object
   * * `signature` - raw signature
   * 
   * @param {Object} params
   * @constructor
   */
  constructor({ headers, signature }) {
    this.header = Header.wrap(headers)
    this.signature = signature
  }

  /**
   * Instantiates a new Signature instance with the given array of parts.
   * 
   * Used internally when decoding CBOR encoded signatures.
   * 
   * @param {Array} parts
   * @constructor
   */
  static fromArray(parts) {
    if (parts.length === 2 && typeof parts[0] === 'object' && typeof parts[0].alg === 'string') {
      return new this({ headers: parts[0], signature: parts[1] })
    } else {
      return parts.map(p => this.fromArray(p))
    }
  }

  /**
   * Wraps the given signature and headers in a new Signature instance.
   * 
   * @param {Buffer} signature
   * @param {Object} headers
   * @constructor
   */
  static wrap(signature, headers = {}) {
    return new this({ headers, signature })
  }

  /**
   * Returns the Signature as an array of component parts.
   * 
   * Used internally prior to encoding the signature.
   * 
   * @returns {Array}
   */
  toArray() {
    return [this.header.unwrap(), this.signature]
  }
}

export default Signature