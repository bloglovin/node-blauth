/* jslint node: true */
'use strict';

var Hapi = require('hapi');
var http = require('http');

var Scheme = function (server, options) {
  this.auth_host = 'local.bloglovin.com';
  this.auth_path = '/auth?return=API';
};

//
// ## Authenticate
// Send in a request and a callback to authenticate
// The request is authorized if the err object in callback is null
//
// If not auth, the err argument will be a hapi error.unauthorized object
// with a message hinting on what's wrong.
//
// A request needs to have a querystring containing a hash,
// a timestamp in seconds (UNIX), an app_id and a user
//
// * **request** hapi request object**
// * **callback** function (err, message)
//
Scheme.prototype.authenticate = function (request, callback) {
  var error = null;

  // Validate that we aren't missing anything obvious
  if ( ! request.query.hash || request.query.length > 0) {
    error = 'Hash not set';
  }

  if ( ! request.query.timestamp) {
    error = 'No timestamp set';
  }

  var number = parseInt(request.query.timestamp, 10);
  // This is a bit random, but it's not valid if it's too old
  // also we want to make sure it's a number
  if (isNaN(number) || number < 1390585898) {
    error = 'Timestamp invalid';
  }

  if ( ! request.query.app_id) {
    error = 'No app_id set';
  }

  if ( ! request.query.user) {
    error = 'No user set';
  }

  var number = parseInt(request.query.user, 10);
  // This is a bit random, but it's not valid if it's too old
  // also we want to make sure it's a number
  if (isNaN(number)) {
    error = 'User invalid';
  }

  // The users should match..
  if (request.params.userid && request.params.userid !== request.query.user) {
    error = 'Wrong user';
  }
  // If we have any errors so far, no need to go to the API
  // Just return our message
  if (error) {
    return callback(Hapi.error.unauthorized(error), null);
  }

  var querystring = this.buildQuery(
    request.query.hash,
    request.query.timestamp,
    request.query.app_id,
    request.query.user
  );

  this.externalAuth(querystring, callback);
};

//
// ## buildQuery
// Put all params together to a string
//
// * **hash** string
// * **timestamp** int unixtimestamp in seconds
// * **app_id** string
// * **user** int
//
Scheme.prototype.buildQuery = function (hash, timestamp, app_id, user) {
  // Send auth request to core api
  var querystring = [
    'hash=' + hash,
    'timestamp=' + timestamp,
    'app_id=' + app_id,
    'user=' + user,
  ].join('&');

  return querystring;
};

Scheme.prototype.externalAuth = function (querystring, callback) {
  var self = this;
  var options = {
    hostname: this.auth_host,
    path: this.auth_path + '&' + querystring,
    agent: false,
    port: 80,
  };

  var req = http.get(options, function(res) {
    var data = [];

    if (res.statusCode == 403) {
      return callback('Error', null);
    }

    res.on('data', function (chunk) {
      data.push(chunk.toString());
    });

    res.on('end', function () {
      data = JSON.parse(data.join());
      self.validate(data, callback);
    });
  });

  req.on('error', function(e) {
    return callback('Error', null);
  });
};

Scheme.prototype.validate = function (data, callback) {
  if (data.success === true) {
    callback(null, data);
  }
};

module.exports = function (server, options) {
  return new Scheme(server, options);
}
