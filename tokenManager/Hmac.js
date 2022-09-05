const Crypto = require('crypto')

/**
 * HMAC Token Manager
 */
class HmacTokenManager {
  constructor (opts) {
    this.opts = opts

    this.hmacSecret = this.opts.hmacSecret
    this.expiry = this.opts.expiry || 60 * 60 // 1 hours default value
  }

  /**
   * Verify secret
   *
   * @param {string} secret
   * @param {string} token
   * @param {IncomingMessage} req
   * @returns {boolean}
   */
  verify (secret, token, req) {
    if (!token) return false

    const tokenParts = token.split(':')
    if (tokenParts.length !== 5) return false

    const csrfUserId = tokenParts[0]
    const csrfNonce = tokenParts[1]
    const csrfOperation = tokenParts[2]
    const timestamp = tokenParts[3]

    // Check for token expiry
    if (Math.floor(Date.now() / 1000) - timestamp > this.expiry) return false

    // Check for csrfUserId
    if (this._sanitize(req._csrfUserId) !== csrfUserId) return false

    return this.create('dummy', {
      _csrfUserId: csrfUserId,
      _csrfNonce: csrfNonce,
      _csrfOperation: csrfOperation
    }, timestamp) === token
  }

  /**
   * Returns token
   *
   * @param {String} secret
   * @param {IncomingMessage} req
   * @param {number} timestamp
   * @return {String}
   */
  create (secret, req, timestamp = Math.floor(Date.now() / 1000)) {
    const csrfUserId = this._sanitize(req._csrfUserId)
    const csrfNonce = this._sanitize(req._csrfNonce)
    const csrfOperation = this._sanitize(req._csrfOperation)

    const prefix = `${csrfUserId}:${csrfNonce}:${csrfOperation}:${timestamp}`
    return prefix + ':' + Crypto.createHmac('sha256', this.hmacSecret).update(prefix).digest('hex')
  }

  /**
   * Returns sanitized string
   *
   * @param {string} str
   * @returns {string}
   * @private
   */
  _sanitize (str) {
    return `${str}`.replace(/\s+/g, '_').replace(/:+/g, '_')
  }
}

module.exports = HmacTokenManager
