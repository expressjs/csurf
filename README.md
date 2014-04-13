# CSURF [![Build Status](https://travis-ci.org/expressjs/csurf.svg?branch=master)](https://travis-ci.org/expressjs/csurf)

CSRF middleware for connect/express/node.

## Example

```js
var csrf = require('csurf');

app.use(csrf());
```

It currently has the same API as [connect-csrf](http://www.senchalabs.org/connect/csrf.html), except it is now in its own repository.
