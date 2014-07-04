
process.env.NODE_ENV = 'test';

var connect = require('connect');
var http = require('http')
var session = require('cookie-session');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var request = require('supertest');
var should = require('should')

var csurf = require('..')

describe('csurf', function () {
  it('should work with a valid token (session-based)', function(done) {
    var server = createServer()

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

  it('should work with a valid token (cookie-based, defaults)', function(done) {
    var server = createServer({ cookie: true })

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

  it('should work with a valid token (cookie-based, custom key)', function(done) {
    var server = createServer({ cookie: { key: '_customcsrf' } });

    request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text;

      res.headers['set-cookie'][0].split('=')[0].should.equal('_customcsrf');

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

  it('should error without cookieParser secret and signed cookie storage', function(done) {
    var app = connect()

    app.use(cookieParser())
    app.use(csurf({ cookie: { signed: true } }))

    request(app)
    .get('/')
    .expect(500, /cookieParser.*secret/, done)
  });
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

  app.use(bodyParser())
  app.use(csurf(opts))

  app.use(function (req, res) {
    res.end(req.csrfToken() || 'none')
  })

  return http.createServer(app)
}
