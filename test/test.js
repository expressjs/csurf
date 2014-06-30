
process.env.NODE_ENV = 'test';

var connect = require('connect');
var session = require('cookie-session');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var request = require('supertest');

var csrf = require('..');

describe('csrf', function(){
  it('should work with a valid token (session-based)', function(done) {
    var app = trifecta();

    app.use(function(req, res){
      res.end(req.csrfToken() || 'none');
    });

    request(app)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text;

      request(app)
      .post('/')
      .set('Cookie', cookies(res))
      .set('X-CSRF-Token', token)
      .expect(200, done)
    });
  });

  it('should work with a valid token (cookie-based, defaults)', function(done) {
    var app = trifecta(null, { cookie: true });

    app.use(function(req, res) {
      (req.session === undefined).should.be.true;
      res.end(req.csrfToken() || 'none');
    });

    request(app)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text;

      request(app)
      .post('/')
      .set('Cookie', cookies(res))
      .set('X-CSRF-Token', token)
      .expect(200, done)
    });
  });

  it('should work with a valid token (cookie-based, custom key)', function(done) {
    var app = trifecta(null, { cookie: { key: '_customcsrf' } });

    app.use(function(req, res) {
      (req.session === undefined).should.be.true;
      res.end(req.csrfToken() || 'none');
    });

    request(app)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      var token = res.text;

      res.headers['set-cookie'][0].split('=')[0].should.equal('_customcsrf');

      request(app)
      .post('/')
      .set('Cookie', cookies(res))
      .set('X-CSRF-Token', token)
      .expect(200, done)
    });
  });

  it('should fail with an invalid token', function(done) {
    var app = trifecta();

    app.use(function(req, res){
      res.end(req.csrfToken() || 'none');
    });

    request(app)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      request(app)
      .post('/')
      .set('Cookie', cookies(res))
      .set('X-CSRF-Token', '42')
      .expect(403, done)
    });
  });

  it('should fail with no token', function(done){
    var app = trifecta();

    app.use(function(req, res){
      res.end(req.csrfToken() || 'none');
    });

    request(app)
    .get('/')
    .expect(200, function (err, res) {
      if (err) return done(err)
      request(app)
      .post('/')
      .set('Cookie', cookies(res))
      .expect(403, done)
    });
  });
});

function trifecta(app, opts) {
  app = app || connect();
  if (!opts || (opts && !opts.cookie)) {
    app.use(session({
      keys: ['a', 'b']
    }));
  } else if (opts && opts.cookie)
    app.use(cookieParser());
  app.use(bodyParser());
  app.use(csrf(opts));
  return app;
}

function cookies(req) {
  return req.headers['set-cookie'].map(function (cookies) {
    return cookies.split(';')[0];
  }).join(';');
}