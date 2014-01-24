var auth = require('./../index')({}, {});
var expect = require('chai').expect;
var sinon = require('sinon');

function getMockRequest() {
  var mock_request = {
    query: {
      timestamp: 1390595898,
      hash: 'hfbdshfd',
      app_id: 'fdsfsdfd',
      user: 2
    },
    params: {
      userid: 2
    }
  };

  return mock_request;
}

describe('BL Hapi auth module', function () {
  describe('authenticate', function () {
    it('should call external auth', function (done) {
      var mock = sinon.mock(auth);
      mock.expects('externalAuth').callsArgWith(1, null, 'Authed');

      auth.authenticate(getMockRequest(), function (err, result) {
        expect(err).to.equal(null);
        expect(result).to.equal('Authed');
        mock.restore();
        done();
      });
    });

    it('should have a timestamp', function (done) {
      var mock_request = getMockRequest();
      delete mock_request.query.timestamp;

      auth.authenticate(mock_request, function (err, result) {
        expect(err).to.not.equal(null);
        done();
      });
    });

    it('should have timestamp as int', function (done) {
      var mock_request = getMockRequest();
      mock_request.query.timestamp = 'fdwfhbdfdf';

      auth.authenticate(mock_request, function (err, result) {
        expect(err).to.not.equal(null);
        done();
      });
    });

    it('should have a hash', function (done) {
      var mock_request = getMockRequest();
      delete mock_request.query.hash;

      auth.authenticate(mock_request, function (err, result) {
        expect(err).to.not.equal(null);
        done();
      });
    });

    it('should have a hash that is not empty', function (done) {
      var mock_request = getMockRequest();
      mock_request.query.hash = '';

      auth.authenticate(mock_request, function (err, result) {
        expect(err).to.not.equal(null);
        done();
      });
    });

    it('should have a user', function (done) {
      var mock_request = getMockRequest();
      delete mock_request.query.user;

      auth.authenticate(mock_request, function (err, result) {
        expect(err).to.not.equal(null);
        done();
      });
    });

    it('user should be an integer', function (done) {
      var mock_request = getMockRequest();
      mock_request.query.user = 'fdsfdf';

      auth.authenticate(mock_request, function (err, result) {
        expect(err).to.not.equal(null);
        done();
      });
    });

    it('should fail on different users', function (done) {
      var mock_request = getMockRequest();
      mock_request.query.user = 1;

      auth.authenticate(mock_request, function (err, result) {
        expect(err).to.not.equal(null);
        done();
      });
    });

    it('should have a app_id', function (done) {
      var mock_request = getMockRequest();
      delete mock_request.query.app_id;


      auth.authenticate(mock_request, function (err, result) {
        expect(err).to.not.equal(null);
        done();
      });
    });
  });

  describe('try buildQuery', function () {
    it('should return a param string', function () {
      var query = auth.buildQuery('fhdjbfhdfdf', 123, 'app', 1);

      expect(query).to.equal('hash=fhdjbfhdfdf&timestamp=123&app_id=app&user=1');
    });
  });

  describe('test externalAuth', function () {
    it('should contact api and fail auth', function (done) {
      var query = 'hash=fhdjbfhdfdf&timestamp=123&app_id=app&user=1';

      auth.externalAuth(query, function (err, result) {
        expect(err).to.not.equal(null);
        done();
      });
    });

    it('should contact api and fail request', function (done) {
      auth.auth_host = 'dafdsfdfd';

      var query = 'hash=fhdjbfhdfdf&timestamp=123&app_id=app&user=1';

      auth.externalAuth(query, function (err, result) {
        expect(err).to.not.equal(null);
        done();
      });
    });
  });

  describe('test validate', function () {
    it('should validate a dataset', function (done) {
      auth.validate({success: true}, function (err, result) {
        expect(err).to.equal(null);
        expect(result).to.deep.equal({success: true});
        done();
      });
    });
  });
});
