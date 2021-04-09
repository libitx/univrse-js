/**
 * Header class
 * 
 * A Universe Header is simply an object of arbitrary key-value pairs. Headers
 * can be found in the Envelope, Signature and Recipient objects.
 * 
 * Known header parameters include:
 * 
 * * `alg` - Signature or encryption algorithm (Signature, Recipient)
 * * `crit` - An array of critical headers (Envelope)
 * * `cty` - Content type (Envelope)
 * * `iv` - Initialisation vector (Recipient)
 * * `kid` - Key identifier (Signature, Recipient)
 * * `proto` - Protocol identifier (Envelope)
 * * `zip` - Compression algorithm (Envelope)
 */
class Header {
  /**
   * Instantiates a new Header instance with the given headers.
   * 
   * @param {Object} headers
   * @constructor
   */
  constructor(headers = {}) {
    this.headers = headers
  }

  /**
   * Wraps the given headers in a new Header instance
   * 
   * @param {Object} headers
   * @constructor
   */
  static wrap(headers) {
    return new this(headers)
  }

  /**
   * Unwraps the Header instance and returns the headers object
   * 
   * @returns {Object}
   */
  unwrap() {
    return this.headers
  }
}

export default Header