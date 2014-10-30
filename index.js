/*!
 * csurf
 * Copyright(c) 2011 Sencha Inc.
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2014 Maël Nison
 * Copyright(c) 2014-2016 Douglas Christopher Wilson
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 * @private
 */

var Cookie = require('cookie')
var createError = require('http-errors')
var sign = require('cookie-signature').sign
var Tokens = require('csrf')

/**
 * Module exports.
 * @public
 */

module.exports = csurf

/**
 * CSRF protection middleware.
 *
 * This middleware adds a `req.csrfToken()` function to make a token
 * which should be added to requests which mutate
 * state, within a hidden form field, query-string etc. This
 * token is validated against the visitor's session.
 *
 * @param {Object} options
 * @return {Function} middleware
 * @public
 */

function csurf (options) {
  var generator = csurf.generator(options)
  var validator = csurf.validator(options)

  return function csurf (req, res, next) {
    generator(req, res, function (err) {
      if (err) return next(err)
      try {
        validator(req, res, next)
      } catch (error) {
        next(error)
      }
    })
  }
}

csurf.generator = function csurfGeneratorBuilder (options) {
  var curToken = null
  var curSecret

  // default options
  var opts = options || {}

  // get cookie options
  var cookie = getCookieOptions(opts.cookie)

  // get session options
  var sessionKey = opts.sessionKey || 'session'

  // token manager
  var tokenManager = new Tokens(opts)

  // csrf parameter getter
  var getRequestCsrf = opts.value || defaultValue

  return function csurfGenerator (req, res, next) {
    // validate the configuration against request
    if (!verifyConfiguration(req, sessionKey, cookie)) {
      return next(new Error('misconfigured csrf'))
    }

    req.csrfToken = function () {
      var secret = getSecret(req, sessionKey, cookie)

      if (curToken !== null && curSecret === secret) {
        // use cached token if secret has not changed
        return curToken
      } else {
        if (secret === undefined) {
          // no csrf in the session, so we create a new one
          secret = tokenManager.secretSync()
          setSecret(req, res, sessionKey, secret, cookie)
        }

        // update cached token
        curToken = tokenManager.create(secret)
        curSecret = secret

        return curToken
      }
    }

    req.checkCsrf = function () {
      var secret = getSecret(req, sessionKey, cookie)

      return tokenManager.verify(secret, getRequestCsrf(req))
    }

    next()
  }
}

csurf.validator = function csurfValidatorBuilder (options) {
  // default options
  options = options || {}

  // ignored methods
  var ignoreMethods = options.ignoreMethods === undefined
    ? ['GET', 'HEAD', 'OPTIONS'] : options.ignoreMethods

  if (!Array.isArray(ignoreMethods)) {
    throw new TypeError('option ignoreMethods must be an array')
  }

  // generate lookup
  var ignoreMethod = getIgnoredMethods(ignoreMethods)

  return function csurfValidator (req, res, next) {
    // verify the incoming token
    if (!ignoreMethod[req.method] && !req.checkCsrf()) {
      throw createError(403, 'invalid csrf token', {
        code: 'EBADCSRFTOKEN'
      })
    }

    next()
  }
}

/**
 * Default value function, checking the `req.body`
 * and `req.query` for the CSRF token.
 *
 * @param {IncomingMessage} req
 * @return {String}
 * @api private
 */

function defaultValue (req) {
  return (req.body && req.body._csrf) ||
    (req.query && req.query._csrf) ||
    (req.headers['csrf-token']) ||
    (req.headers['xsrf-token']) ||
    (req.headers['x-csrf-token']) ||
    (req.headers['x-xsrf-token'])
}

/**
 * Get options for cookie.
 *
 * @param {boolean|object} [options]
 * @returns {object}
 * @api private
 */

function getCookieOptions (options) {
  if (options !== true && typeof options !== 'object') {
    return undefined
  }

  var opts = {
    key: '_csrf',
    path: '/'
  }

  if (options && typeof options === 'object') {
    for (var prop in options) {
      var val = options[prop]

      if (val !== undefined) {
        opts[prop] = val
      }
    }
  }

  return opts
}

/**
 * Get a lookup of ignored methods.
 *
 * @param {array} methods
 * @returns {object}
 * @api private
 */

function getIgnoredMethods (methods) {
  var obj = Object.create(null)

  for (var i = 0; i < methods.length; i++) {
    var method = methods[i].toUpperCase()
    obj[method] = true
  }

  return obj
}

/**
 * Get the token secret from the request.
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @param {Object} [cookie]
 * @api private
 */

function getSecret (req, sessionKey, cookie) {
  // get the bag & key
  var bag = getSecretBag(req, sessionKey, cookie)
  var key = cookie ? cookie.key : 'csrfSecret'

  if (!bag) {
    /* istanbul ignore next: should never actually run */
    throw new Error('misconfigured csrf')
  }

  // return secret from bag
  return bag[key]
}

/**
 * Get the token secret bag from the request.
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @param {Object} [cookie]
 * @api private
 */

function getSecretBag (req, sessionKey, cookie) {
  if (cookie) {
    // get secret from cookie
    var cookieKey = cookie.signed
      ? 'signedCookies'
      : 'cookies'

    return req[cookieKey]
  } else {
    // get secret from session
    return req[sessionKey]
  }
}

/**
 * Set a cookie on the HTTP response.
 *
 * @param {OutgoingMessage} res
 * @param {string} name
 * @param {string} val
 * @param {Object} [options]
 * @api private
 */

function setCookie (res, name, val, options) {
  var data = Cookie.serialize(name, val, options)

  var prev = res.getHeader('set-cookie') || []
  var header = Array.isArray(prev) ? prev.concat(data)
    : Array.isArray(data) ? [prev].concat(data)
    : [prev, data]

  res.setHeader('set-cookie', header)
}

/**
 * Set the token secret on the request.
 *
 * @param {IncomingMessage} req
 * @param {OutgoingMessage} res
 * @param {string} sessionKey
 * @param {string} val
 * @param {Object} [cookie]
 * @api private
 */

function setSecret (req, res, sessionKey, val, cookie) {
  if (cookie) {
    // set secret on cookie
    if (cookie.signed) {
      var secret = req.secret

      if (!secret) {
        /* istanbul ignore next: should never actually run */
        throw new Error('misconfigured csrf')
      }

      val = 's:' + sign(val, secret)
    }

    setCookie(res, cookie.key, val, cookie)
  } else if (req[sessionKey]) {
    // set secret on session
    req[sessionKey].csrfSecret = val
  } else {
    /* istanbul ignore next: should never actually run */
    throw new Error('misconfigured csrf')
  }
}

/**
 * Verify the configuration against the request.
 * @private
 */

function verifyConfiguration (req, sessionKey, cookie) {
  if (!getSecretBag(req, sessionKey, cookie)) {
    return false
  }

  if (cookie && cookie.signed && !req.secret) {
    return false
  }

  return true
}
