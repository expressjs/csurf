/*!
 * csurf
 * Copyright(c) 2011 Sencha Inc.
 * Copyright(c) 2014 Jonathan Ong
 * MIT Licensed
 */

/**
 * Module dependencies.
 */

var Cookie = require('cookie');
var csrfTokens = require('csrf');
var sign = require('cookie-signature').sign;
var extend = require('extend');

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
 * @api public
 */

var ignoreMethodDefaults = {
  GET: true,
  HEAD: true,
  OPTIONS: true,
};

module.exports = function csurf(options) {
  options = options || {};

  // get value getter
  var value = options.value || defaultValue

  // token repo
  var tokens = csrfTokens(options);

  // default cookie key
  if (options.cookie && !options.cookie.key) {
    options.cookie.key = '_csrf'
  }

  // Allow user to define HTTP methods to ignore
  var ignoreMethod = extend({}, ignoreMethodDefaults, options && options.ignoreMethod)

  return function csrf(req, res, next) {
    var secret = getsecret(req, options.cookie)
    var token

    // lazy-load token getter
    req.csrfToken = function csrfToken() {
      var sec = !options.cookie
        ? getsecret(req, options.cookie)
        : secret

      // use cached token if secret has not changed
      if (token && sec === secret) {
        return token
      }

      // generate & set new secret
      if (sec === undefined) {
        sec = tokens.secretSync()
        setsecret(req, res, sec, options.cookie)
      }

      // update changed secret
      secret = sec

      // create new token
      token = tokens.create(secret)

      return token
    }

    // generate & set secret
    if (!secret) {
      secret = tokens.secretSync()
      setsecret(req, res, secret, options.cookie)
    }

    // verify the incoming token
    verifytoken(req, tokens, secret, value(req), ignoreMethod)

    next()
  }
};

/**
 * Default value function, checking the `req.body`
 * and `req.query` for the CSRF token.
 *
 * @param {IncomingMessage} req
 * @return {String}
 * @api private
 */

function defaultValue(req) {
  return (req.body && req.body._csrf)
    || (req.query && req.query._csrf)
    || (req.headers['x-csrf-token'])
    || (req.headers['x-xsrf-token']);
}

/**
 * Get the token secret from the request.
 *
 * @param {IncomingMessage} req
 * @param {Object} [cookie]
 * @api private
 */

function getsecret(req, cookie) {
  var secret

  if (cookie) {
    // get secret from cookie
    var bag = cookie.signed
      ? 'signedCookies'
      : 'cookies'

    secret = req[bag][cookie.key]
  } else if (req.session) {
    // get secret from session
    secret = req.session.csrfSecret
  } else {
    throw new Error('misconfigured csrf')
  }

  return secret
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

function setcookie(res, name, val, options) {
  var data = Cookie.serialize(name, val, options);

  var prev = res.getHeader('set-cookie') || [];
  var header = Array.isArray(prev) ? prev.concat(data)
    : Array.isArray(data) ? [prev].concat(data)
    : [prev, data];

  res.setHeader('set-cookie', header);
}

/**
 * Set the token secret on the request.
 *
 * @param {IncomingMessage} req
 * @param {OutgoingMessage} res
 * @param {string} val
 * @param {Object} [cookie]
 * @api private
 */

function setsecret(req, res, val, cookie) {
  if (cookie) {
    // set secret on cookie
    if (cookie.signed) {
      var secret = req.secret

      if (!secret) {
        throw new Error('cookieParser("secret") required for signed cookies')
      }

      val = 's:' + sign(val, secret)
    }

    setcookie(res, cookie.key, val, cookie);
  } else if (req.session) {
    // set secret on session
    req.session.csrfSecret = val
  } else {
    /* istanbul ignore next: should never actually run */
    throw new Error('misconfigured csrf')
  }
}

/**
 * Verify the token.
 *
 * @param {IncomingMessage} req
 * @param {Object} tokens
 * @param {string} secret
 * @param {string} val
 * @api private
 */

function verifytoken(req, tokens, secret, val, ignoreMethod) {
  // ignore these methods
  if (ignoreMethod[req.method]) {
    return
  }

  // valid token
  if (tokens.verify(secret, val)) {
    return
  }

  var err = new Error('invalid csrf token')
  err.status = 403
  throw err
}
