const DoubleSubmitTokenManager = require('csrf')
const HmacTokenManager = require('./Hmac')
const EncryptedTokenManager = require('./Encrypted')

/**
 * Token Manager Factory class for providing token manager object based on CSRF token pattern
 */
class TokenManagerFactory {
  constructor (opts) {
    this.opts = opts || {}
    this.csrfTokenPattern = this.opts.csrfTokenPattern
  }

  /**
   * Get token manager object
   */
  getTokenManager () {
    if (this.csrfTokenPattern === 'hmac') {
      return new HmacTokenManager(this.opts)
    } else if (this.csrfTokenPattern === 'encrypted') {
      return new EncryptedTokenManager(this.opts)
    } else { // If not passed, treat double submit token manager as default.
      return new DoubleSubmitTokenManager(this.opts)
    }
  }
}

module.exports = TokenManagerFactory
