
process.env.NODE_ENV = 'test'

var connect = require('connect')
var http = require('http')
var bodyParser = require('body-parser')
var querystring = require('querystring')
var request = require('supertest')

var csurf = require('..')

describe('csurf with HMAC based token pattern', function () {
  it('should work in req.body', function (done) {
    var server = createServerWithoutCookieAndSession({
      csrfTokenPattern: 'hmac',
      hmacSecret: 'e92633a08116905e4f30eefd1'
    })

    request(server)
      .get('/')
      .expect(200, function (err, res) {
        if (err) return done(err)
        var token = res.text

        request(server)
          .post('/')
          .send('_csrf=' + encodeURIComponent(token))
          .expect(200, done)
      })
  })
})

it('should work in req.query', function (done) {
  var server = createServerWithoutCookieAndSession({
    csrfTokenPattern: 'hmac',
    hmacSecret: 'e92633a08116905e4f30eefd1'
  })

  request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text

      request(server)
        .post('/?_csrf=' + encodeURIComponent(token))
        .expect(200, done)
    })
})

it('should work in csrf-token header', function (done) {
  var server = createServerWithoutCookieAndSession({
    csrfTokenPattern: 'hmac',
    hmacSecret: 'e92633a08116905e4f30eefd1'
  })

  request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text

      request(server)
        .post('/')
        .set('csrf-token', token)
        .expect(200, done)
    })
})

it('should work in xsrf-token header', function (done) {
  var server = createServerWithoutCookieAndSession({
    csrfTokenPattern: 'hmac',
    hmacSecret: 'e92633a08116905e4f30eefd1'
  })

  request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text

      request(server)
        .post('/')
        .set('xsrf-token', token)
        .expect(200, done)
    })
})

it('should work in x-csrf-token header', function (done) {
  var server = createServerWithoutCookieAndSession({
    csrfTokenPattern: 'hmac',
    hmacSecret: 'e92633a08116905e4f30eefd1'
  })

  request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text

      request(server)
        .post('/')
        .set('x-csrf-token', token)
        .expect(200, done)
    })
})

it('should work in x-xsrf-token header', function (done) {
  var server = createServerWithoutCookieAndSession({
    csrfTokenPattern: 'hmac',
    hmacSecret: 'e92633a08116905e4f30eefd1'
  })

  request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text

      request(server)
        .post('/')
        .set('x-xsrf-token', token)
        .expect(200, done)
    })
})

it('should fail with an invalid token', function (done) {
  var server = createServerWithoutCookieAndSession({
    csrfTokenPattern: 'hmac',
    hmacSecret: 'e92633a08116905e4f30eefd1'
  })

  request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      request(server)
        .post('/')
        .set('X-CSRF-Token', '42')
        .expect(403, done)
    })
})

it('should fail with no token', function (done) {
  var server = createServerWithoutCookieAndSession({
    csrfTokenPattern: 'hmac',
    hmacSecret: 'e92633a08116905e4f30eefd1'
  })

  request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      request(server)
        .post('/')
        .expect(403, done)
    })
})

it('should fail with expired token', function (done) {
  var server = createServerWithoutCookieAndSession({
    csrfTokenPattern: 'hmac',
    hmacSecret: 'e92633a08116905e4f30eefd1',
    expiry: 0.5
  })

  // Token expiry is 0.5 seconds and we use it after 1 second.

  request(server)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text

      setTimeout(function () {
        request(server)
          .post('/')
          .set('x-xsrf-token', token)
          .expect(403, done)
      }, 1000)
    })
})

function createServerWithoutCookieAndSession (opts) {
  var app = connect()

  app.use(function (req, res, next) {
    var index = req.url.indexOf('?') + 1

    if (index) {
      req.query = querystring.parse(req.url.substring(index))
    }

    next()
  })
  app.use(bodyParser.urlencoded({ extended: false }))

  app.use(function(req, res, next) {
    req._csrfUserId = 123
    req._csrfNonce = 1
    req._csrfOperation = 'test'
    next()
  })

  app.use(csurf(opts))

  app.use(function (req, res) {
    res.end(req.csrfToken() || 'none')
  })

  return http.createServer(app)
}
