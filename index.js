/*!
 * csurf
 * Copyright(c) 2011 Sencha Inc.
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2014 Douglas Christopher Wilson
 * Copyright(c) 2014 Maël Nison
 * MIT Licensed
 */

/**
 * Module dependencies.
 */

var Cookie = require('cookie');
var csrfTokens = require('csrf');
var createError = require('http-errors');
var sign = require('cookie-signature').sign;

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

var csurf = module.exports = function csurf(options) {
  var generator = csurf.generator(options);
  var validator = csurf.validator(options);

  return function csurf(req, res, next) {
    generator(req, res, function() {
      try {
        validator(req, res, next);
      } catch (error) {
        next(error);
      }
    });
  };
};

csurf.generator = function csurfGeneratorBuilder(options) {
  var curToken = null;
  var curSecret;

  // default options
  options = options || {};

  // get cookie options
  var cookie = options.cookie !== true
    ? options.cookie || undefined
    : {}

  // default cookie key
  if (cookie && !cookie.key)
    cookie.key = '_csrf';

  // token manager
  var tokenManager = csrfTokens(options);

  // csrf parameter getter
  var getRequestCsrf = options.value || defaultValue;

  return function csurfGenerator(req, res, next) {
    req.csrfToken = function () {
      var secret = getsecret(req, cookie);

      if (curToken !== null && curSecret === secret) {

        // use cached token if secret has not changed
        return curToken;

      } else {

        if (secret === undefined) {
          // no csrf in the session, so we create a new one
          secret = tokenManager.secretSync();
          setsecret(req, res, secret, cookie);
        }

        // update cached token
        curToken = tokenManager.create(secret);
        curSecret = secret;

        return curToken;

      }
    };

    req.checkCsrf = function () {
      var secret = getsecret(req, cookie);

      return tokenManager.verify(secret, getRequestCsrf(req));
    };

    next();
  };
};

csurf.validator = function csurfValidatorBuilder(options) {
  // default options
  options = options || {};

  // ignored methods
  var ignoreMethods = options.ignoreMethods === undefined ?
    ['GET', 'HEAD', 'OPTIONS'] : options.ignoreMethods

  if (!Array.isArray(ignoreMethods))
    throw new TypeError('option ignoreMethods must be an array')

  // generate lookup
  var ignoreMethod = getIgnoredMethods(ignoreMethods);

  return function csurfValidator(req, res, next) {
    // verify the incoming token
    if (!ignoreMethod[req.method] && !req.checkCsrf()) {
      throw createError(403, 'invalid csrf token', {
        code: 'EBADCSRFTOKEN'
      });
    }

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
 * Get a lookup of ignored methods.
 *
 * @param {array} methods
 * @returns {object}
 * @api private
 */

function getIgnoredMethods(methods) {
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
