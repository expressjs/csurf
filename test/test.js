var connect = require('connect');
var session = require('cookie-session');
var bodyParser = require('body-parser');
var request = require('supertest');

var csrf = require('..');

describe('csrf', function(){
  it('should work with a valid token', function(done){
    var app = trifecta();

    app.use(function(req, res){
      res.end(req.csrfToken() || 'none');
    });

    var server = app.listen();

    request(server)
    .get('/')
    .end(function(err, res){
      var token = res.text;

      request(server)
      .post('/')
      .set('Cookie', cookies(res))
      .set('X-CSRF-Token', token)
      .end(function(err, res){
        res.statusCode.should.equal(200)
        done();
      });
    });
  });

  it('should fail with an invalid token', function(done){
    var app = trifecta();

    app.use(function(req, res){
      res.end(req.csrfToken() || 'none');
    });

    var server = app.listen();

    request(server)
    .get('/')
    .end(function(err, res){
      request(server)
      .post('/')
      .set('Cookie', cookies(res))
      .set('X-CSRF-Token', '42')
      .end(function(err, res){
        res.statusCode.should.equal(403)
        done();
      });
    });
  });

  it('should fail with no token', function(done){
    var app = trifecta();

    app.use(function(req, res){
      res.end(req.csrfToken() || 'none');
    });

    var server = app.listen();

    request(server)
    .get('/')
    .end(function(err, res){
      request(server)
      .post('/')
      .set('Cookie', cookies(res))
      .end(function(err, res){
        res.statusCode.should.equal(403);
        done();
      });
    });
  });
});

function trifecta(app) {
  app = app || connect();
  app.use(session({
    keys: ['a', 'b']
  }));
  app.use(bodyParser());
  app.use(csrf());
  return app;
}

function cookies(req) {
  return req.headers['set-cookie'].map(function (cookies) {
    return cookies.split(';')[0];
  }).join(';');
}