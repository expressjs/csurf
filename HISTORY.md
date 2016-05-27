1.9.0 / 2016-05-27
==================

  * Pass invalid csrf token error to `next()` instead of throwing
  * Pass misconfigured error to `next()` instead of throwing
  * Provide misconfigured error when using cookies without cookie-parser
  * deps: cookie@0.3.1
    - Add `sameSite` option
    - Fix cookie `Max-Age` to never be a floating point number
    - Improve error message when `expires` is not a `Date`
    - Throw better error for invalid argument to parse
    - Throw on invalid values provided to `serialize`
    - perf: enable strict mode
    - perf: hoist regular expression
    - perf: use for loop in parse
    - perf: use string concatination for serialization
  * deps: csrf@~3.0.3
    - Use `tsscmp` module for timing-safe token verification
    - deps: base64-url@1.2.2
    - deps: rndm@1.2.0
    - deps: uid-safe@2.1.1
  * deps: http-errors@~1.5.0
    - Add `HttpError` export, for `err instanceof createError.HttpError`
    - Support new code `421 Misdirected Request`
    - Use `setprototypeof` module to replace `__proto__` setting
    - deps: inherits@2.0.1
    - deps: statuses@'>= 1.3.0 < 2'
    - perf: enable strict mode
  * perf: enable strict mode
  * perf: remove argument reassignment

1.8.3 / 2015-06-10
==================

  * deps: cookie@0.1.3
    - Slight optimizations

1.8.2 / 2015-05-09
==================

  * deps: csrf@~3.0.0
    - deps: uid-safe@~2.0.0

1.8.1 / 2015-05-03
==================

  * deps: csrf@~2.0.7
    - Fix compatibility with `crypto.DEFAULT_ENCODING` global changes

1.8.0 / 2015-04-07
==================

  * Add `sessionKey` option

1.7.0 / 2015-02-15
==================

  * Accept `CSRF-Token` and `XSRF-Token` request headers
  * Default `cookie.path` to `'/'`, if using cookies
  * deps: cookie-signature@1.0.6
  * deps: csrf@~2.0.6
    - deps: base64-url@1.2.1
    - deps: uid-safe@~1.1.0
  * deps: http-errors@~1.3.1
   - Construct errors using defined constructors from `createError`
   - Fix error names that are not identifiers
   - Set a meaningful `name` property on constructed errors

1.6.6 / 2015-01-31
==================

  * deps: csrf@~2.0.5
    - deps: base64-url@1.2.0
    - deps: uid-safe@~1.0.3

1.6.5 / 2015-01-08
==================

  * deps: csrf@~2.0.4
    - deps: uid-safe@~1.0.2

1.6.4 / 2014-12-30
==================

  * deps: csrf@~2.0.3
    - Slight speed improvement for `verify`
    - deps: base64-url@1.1.0
    - deps: rndm@~1.1.0
  * deps: http-errors@~1.2.8
   - Fix stack trace from exported function

1.6.3 / 2014-11-09
==================

  * deps: csrf@~2.0.2
    - deps: scmp@1.0.0
  * deps: http-errors@~1.2.7
   - Remove duplicate line

1.6.2 / 2014-10-14
==================

  * Fix cookie name when using `cookie: true`
  * deps: http-errors@~1.2.6
    - Fix `expose` to be `true` for `ClientError` constructor
    - Use `inherits` instead of `util`
    - deps: statuses@1

1.6.1 / 2014-09-05
==================

  * deps: cookie-signature@1.0.5

1.6.0 / 2014-09-03
==================

  * Set `code` property on CSRF token errors

1.5.0 / 2014-08-24
==================

  * Add `ignoreMethods` option

1.4.1 / 2014-08-22
==================

  * Use `csrf-tokens` instead of `csrf`
 
1.4.0 / 2014-07-30
==================

  * Support changing `req.session` after `csurf` middleware
    - Calling `res.csrfToken()` after `req.session.destroy()` will now work

1.3.0 / 2014-07-03
==================

  * Add support for environments without `res.cookie` (connect@3)

1.2.2 / 2014-06-18
==================

  * deps: csrf-tokens@~2.0.0

1.2.1 / 2014-06-09
==================

  * Refactor to use `csrf-tokens` module

1.2.0 / 2014-05-13
==================

  * Add support for double-submit cookie

1.1.0 / 2014-04-06
==================

  * Add constant-time string compare
