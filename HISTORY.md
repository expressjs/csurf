1.6.1 / 2014-09-05
==================

 * bump cookie-signature

1.6.0 / 2014-09-03
==================

 * set `code` property on CSRF token errors

1.5.0 / 2014-08-24
==================

 * add `ignoreMethods` option

1.4.1 / 2014-08-22
==================

 * csrf-tokens -> csrf
 
1.4.0 / 2014-07-30
==================

 * Support changing `req.session` after `csurf` middleware
   - Calling `res.csrfToken()` after `req.session.destroy()` will now work

1.3.0 / 2014-07-03
==================

 * add support for environments without `res.cookie` (connect@3)

1.2.2 / 2014-06-18
==================

 * bump csrf-tokens

1.2.1 / 2014-06-09
==================

 * refactor to use csrf-tokens

1.2.0 / 2014-05-13
==================

 * add support for double-submit cookie

1.1.0 / 2014-04-06
==================

 * add constant-time string compare
