/* jslint node: true */
'use strict';

var Hapi = require('hapi');
var http = require('http');
var QS = require('querystring');
var SchemeObj = null;

var Scheme = function (server, options) {
  this.auth_host = options.host || 'www.bloglovin.com';
  this.auth_path = options.path || '/auth?return=API';
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
Scheme.prototype.authenticate = function (request, reply) {
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
    return reply(Hapi.error.unauthorized(error), null);
  }

  reply(null, {credentials: {}});
};

Scheme.prototype.payload = function (request, next) {
  var querystring = this.buildQuery(
    request.query.hash,
    request.query.timestamp,
    request.query.app_id,
    request.query.user,
    request.path
  );

  this.externalAuth(querystring, request.payload, next);
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
Scheme.prototype.buildQuery = function (hash, timestamp, app_id, user, path) {
  // Send auth request to core api
  var querystring = [
    'hash=' + hash,
    'timestamp=' + timestamp,
    'app_id=' + app_id,
    'user=' + user,
    'path=' + path
  ].join('&');

  return querystring;
};

Scheme.prototype.externalAuth = function (querystring, params, next) {
  var self = this;
  var post_data = QS.stringify(params);
  var options = {
    hostname: this.auth_host,
    path: this.auth_path + '&' + querystring,
    agent: false,
    port: 80,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': post_data.length
    }
  };


  var req = http.request(options, function(res) {
    var data = [];

    console.log(res.statusCode);
    if (res.statusCode == 403) {
      var error = Hapi.error.unauthorized('Not authorized');
      return next(error);
    }

    res.on('data', function (chunk) {
      data.push(chunk.toString());
    });

    res.on('end', function () {
      data = JSON.parse(data.join());
      self.validate(data, next);
    });
  });

  req.setTimeout(3000, function () {
    req.abort();
    var error = Hapi.error.unauthorized('Not authorized');
    return next(error);
  });

  req.on('error', function(e) {
    var error = Hapi.error.unauthorized('Not authorized');
    return next(error);
  });

  req.write(post_data);
  req.end();
};

Scheme.prototype.validate = function (data, next) {
  if (data.success === true) {
    next(null);
  }
};

var internals = {};

internals.blauth = function (server, options) {
  SchemeObj = new Scheme(server, options);
  return SchemeObj;
};

exports.register = function (plugin, options, next) {
  plugin.auth.scheme('blauth', internals.blauth);
  plugin.auth.strategy('default', 'blauth', true, {host: 'www.bloglovin.com'});

  plugin.ext('onPostAuth', function (request, reply) {
    // this should be triggered by hapi imho, but let's
    // do a hack! HACKISH HACKS FOR THE WIN
    if (
      request.auth.isAuthenticated === true
      && SchemeObj != null
    ) {
      return SchemeObj.payload(request, reply);
    }

    return reply();
  });

  next();
};
