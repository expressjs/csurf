
process.env.NODE_ENV = 'test';

var assert = require('assert');
var connect = require('connect');
var http = require('http')
var session = require('cookie-session');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var request = require('supertest');
var url = require('url')

var csurf = require('..')

describe('csurf', function () {
  it('should work in req.body', function(done) {
    var server = createServer()

    request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text;

      request(server)
      .post('/')
      .set('Cookie', cookies(res))
      .send('_csrf=' + encodeURIComponent(token))
      .expect(200, done)
    });
  });

  it('should work in req.query', function(done) {
    var server = createServer()

    request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text;

      request(server)
      .post('/?_csrf=' + encodeURIComponent(token))
      .set('Cookie', cookies(res))
      .expect(200, done)
    });
  });

  it('should work in x-csrf-token header', function(done) {
    var server = createServer()

    request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text;

      request(server)
      .post('/')
      .set('Cookie', cookies(res))
      .set('x-csrf-token', token)
      .expect(200, done)
    });
  });

  it('should work in x-xsrf-token header', function(done) {
    var server = createServer()

    request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text;

      request(server)
      .post('/')
      .set('Cookie', cookies(res))
      .set('x-xsrf-token', token)
      .expect(200, done)
    });
  });

  it('should work with a valid token (cookie-based, defaults)', function(done) {
    var server = createServer({ cookie: true })

    request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text;

      assert.equal(res.headers['set-cookie'].length, 1);
      assert.equal(res.headers['set-cookie'][0].split('=')[0], '_csrf');

      request(server)
      .post('/')
      .set('Cookie', cookies(res))
      .set('X-CSRF-Token', token)
      .expect(200, done)
    });
  });

  it('should work with a valid token (cookie-based, custom key)', function(done) {
    var server = createServer({ cookie: { key: '_customcsrf' } });

    request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text;

      assert.equal(res.headers['set-cookie'].length, 1);
      assert.equal(res.headers['set-cookie'][0].split('=')[0], '_customcsrf');

      request(server)
      .post('/')
      .set('Cookie', cookies(res))
      .set('X-CSRF-Token', token)
      .expect(200, done)
    });
  });

  it('should work with a valid token (cookie-based, signed)', function(done) {
    var server = createServer({ cookie: { signed: true } })

    request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text;

      request(server)
      .post('/')
      .set('Cookie', cookies(res))
      .set('X-CSRF-Token', token)
      .expect(200, done)
    });
  });

  it('should fail with an invalid token', function(done) {
    var server = createServer()

    request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      request(server)
      .post('/')
      .set('Cookie', cookies(res))
      .set('X-CSRF-Token', '42')
      .expect(403, done)
    });
  });

  it('should fail with no token', function(done){
    var server = createServer()

    request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      request(server)
      .post('/')
      .set('Cookie', cookies(res))
      .expect(403, done)
    });
  });

  it('should provide error code on invalid token error', function(done){
    var app = connect()
    app.use(session({ keys: ['a', 'b'] }))
    app.use(csurf())

    app.use(function (req, res) {
      res.end(req.csrfToken() || 'none')
    })

    app.use(function (err, req, res, next) {
      if (err.code !== 'EBADCSRFTOKEN') return next(err)
      res.statusCode = 403
      res.end('session has expired or form tampered with')
    })

    request(app)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      request(app)
      .post('/')
      .set('Cookie', cookies(res))
      .set('X-CSRF-Token', String(res.text + 'p'))
      .expect(403, 'session has expired or form tampered with', done)
    });
  });

  it('should error without secret storage', function(done) {
    var app = connect()

    app.use(csurf())

    request(app)
    .post('/')
    .expect(500, /misconfigured csrf/, done)
  });

  it('should error without cookieParser secret and signed cookie storage', function(done) {
    var app = connect()

    app.use(cookieParser())
    app.use(csurf({ cookie: { signed: true } }))

    request(app)
    .post('/')
    .expect(500, /cookieParser.*secret/, done)
  });

  describe('with "ignoreMethods" option', function () {
    it('should reject invalid value', function () {
      assert.throws(createServer.bind(null, {ignoreMethods: 'tj'}), /option ignoreMethods/)
    })

    it('should not check token on given methods', function (done) {
      var server = createServer({ignoreMethods: ['GET', 'POST']})

      request(server)
      .get('/')
      .expect(200, function (err, res) {
        if (err) return done(err)
        var cookie = cookies(res)
        request(server)
        .post('/')
        .set('Cookie', cookie)
        .expect(200, function (err, res) {
          if (err) return done(err)
          request(server)
          .put('/')
          .set('Cookie', cookie)
          .expect(403, done)
        })
      })
    })
  })

  describe('req.csrfToken()', function () {
    it('should return same token for each call', function (done) {
      var app = connect()
      app.use(session({ keys: ['a', 'b'] }))
      app.use(csurf())
      app.use(function (req, res) {
        var token1 = req.csrfToken()
        var token2 = req.csrfToken()
        res.end(String(token1 === token2))
      })

      request(app)
      .get('/')
      .expect(200, 'true', done)
    })
  })

  describe('when using session storage', function () {
    var app
    before(function () {
      app = connect()
      app.use(session({ keys: ['a', 'b'] }))
      app.use(csurf())
      app.use('/break', function (req, res, next) {
        // break session
        req.session = null
        next()
      })
      app.use('/new', function (req, res, next) {
        // regenerate session
        req.session = {hit: 1}
        next()
      })
      app.use(function (req, res) {
        res.end(req.csrfToken() || 'none')
      })
    })

    it('should work with a valid token', function(done) {
      request(app)
      .get('/')
      .expect(200, function (err, res) {
        if (err) return done(err)
        var token = res.text
        request(app)
        .post('/')
        .set('Cookie', cookies(res))
        .set('X-CSRF-Token', token)
        .expect(200, done)
      })
    })

    it('should provide a valid token when session regenerated', function(done) {
      request(app)
      .get('/new')
      .expect(200, function (err, res) {
        if (err) return done(err)
        var token = res.text
        request(app)
        .post('/')
        .set('Cookie', cookies(res))
        .set('X-CSRF-Token', token)
        .expect(200, done)
      })
    })

    it('should error if session missing', function(done) {
      request(app)
      .get('/break')
      .expect(500, /misconfigured csrf/, done)
    })
  })
});

function cookies(req) {
  return req.headers['set-cookie'].map(function (cookies) {
    return cookies.split(';')[0];
  }).join(';');
}

function createServer(opts) {
  var app = connect()

  if (!opts || (opts && !opts.cookie)) {
    app.use(session({ keys: ['a', 'b'] }))
  } else if (opts && opts.cookie) {
    app.use(cookieParser('keyboard cat'))
  }

  app.use(function (req, res, next) {
    req.query = url.parse(req.url, true).query
    next()
  })
  app.use(bodyParser.urlencoded({extended: false}))
  app.use(csurf(opts))

  app.use(function (req, res) {
    res.end(req.csrfToken() || 'none')
  })

  return http.createServer(app)
}
