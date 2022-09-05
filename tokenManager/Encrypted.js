const Crypto = require('crypto')

const ALGORITHM = 'aes-256-cbc'
const IV_LENGTH = 16

/**
 * Encrypted Token Manager
 */
class EncryptedTokenManager {
  constructor (opts) {
    this.opts = opts

    this.encryptionKey = this.opts.encryptionKey
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

    const encryptionKey = this.encryptionKey
    let decrypted

    try {
      const [iv, encryptedText] = token.split(':').map(part => Buffer.from(part, 'hex'))
      const decipher = Crypto.createDecipheriv(ALGORITHM, Buffer.from(encryptionKey, 'hex'), iv)
      decrypted = decipher.update(encryptedText)
      decrypted = (Buffer.concat([decrypted, decipher.final()])).toString()
    } catch (e) {
      return false
    }

    const tokenParts = decrypted.split(':')
    if (tokenParts.length !== 3) return false

    const csrfUserId = tokenParts[0]
    const timestamp = tokenParts[2]

    // Check for token expiry
    if (Math.floor(Date.now() / 1000) - timestamp > this.expiry) return false

    // Check for csrfUserId
    return this._sanitize(req._csrfUserId) === csrfUserId
  }

  /**
   * Returns token
   *
   * @param {String} secret
   * @param {IncomingMessage} req
   * @return {String}
   */
  create (secret, req) {
    const encryptionKey = this.encryptionKey
    const csrfUserId = this._sanitize(req._csrfUserId)
    const csrfNonce = this._sanitize(req._csrfNonce)

    const text = `${csrfUserId}:${csrfNonce}:${Math.floor(Date.now() / 1000)}`
    const iv = Crypto.randomBytes(IV_LENGTH)
    const cipher = Crypto.createCipheriv(ALGORITHM, Buffer.from(encryptionKey, 'hex'), iv)
    let encrypted = cipher.update(text)
    encrypted = Buffer.concat([encrypted, cipher.final()])

    return `${iv.toString('hex')}:${encrypted.toString('hex')}`
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

module.exports = EncryptedTokenManager
