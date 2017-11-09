const express = require('express'),
  mongodb = require('mongodb'),
  passport = require('passport'),
  cookieParser = require('cookie-parser'),
  bodyParser = require('body-parser'),
  methodOverride = require('method-override'),
  session = require('express-session'),
  node_acl = require('acl'),
  app = express(),
  localStrategy = require('passport-local').Strategy;

let acl;

// Some test data. Get this from your database.
const users = [{
  id: 1,
  username: 'bob',
  password: 'secret',
  email: 'bob@example.com'
}, {
  id: 2,
  username: 'joe',
  password: 'birthday',
  email: 'joe@example.com'
}];

// Setup express
app.use(cookieParser());
app.use(bodyParser());
app.use(methodOverride());
app.use(session({
  secret: 'Example'
}));
// Initialize Passport. Also use passport.session() middleware, to support
// persistent login sessions.
app.use(passport.initialize());
app.use(passport.session());
// Error handling
app.use((error, req, res, next) => {
  if (!error) {
    return next();
  }
  res.send(error.msg, error.errorCode);
});

authentication_setup();

// Connecting to mongo database and setup authorization
mongodb.connect('mongodb://127.0.0.1:27017/acl', authorization_setup);

// Setting up passport
function authentication_setup() {
  // Setup session support
  passport.serializeUser((user, done) => done(null, user.id));

  passport.deserializeUser((id, done) => {
    find_user_by_id(id, (error, user) => done(error, user));
  });

  // Setup strategy (local in this case)
  passport.use(new localStrategy((username, password, done) => {
    process.nextTick(() => {
      find_by_username(username, (error, user) => {
        if (error) {
          return done(error);
        }
        if (!user) {
          return done(null, false, {
            message: 'Unknown user ' + username
          });
        }
        if (user.password !== password) {
          return done(null, false, {
            message: 'Invalid password'
          });
        }
        // Authenticated
        return done(null, user);
      });
    });
  }));
}

// Setting up node_acl
function authorization_setup(error, db) {
  var mongoBackend = new node_acl.mongodbBackend(db /*, {String} prefix */ );
  // Create a new access control list by providing the mongo backend
  //  Also inject a simple logger to provide meaningful output
  acl = new node_acl(mongoBackend, logger());

  set_roles();
  set_routes();
}

function set_roles() {
  acl.allow([{
    roles: 'admin',
    allows: [{
      resources: '/secret',
      permissions: '*'
    }, {
      resources: '/users',
      permissions: ['get_list']
    }]
  }, {
    roles: 'user',
    allows: [{
      resources: '/secret',
      permissions: 'get'
    }, {
      resources: '/users',
      permissions: ['get']
    }]
  }, {
    roles: 'guest',
    allows: []
  }]);

  // Inherit roles
  //  Every user is allowed to do what guests do
  //  Every admin is allowed to do what users do
  acl.addRoleParents('user', 'guest');
  acl.addRoleParents('admin', 'user');
}

// Defining routes ( resources )
function set_routes() {
  // Check your current user and roles
  app.get('/status', (req, res) => {
    acl.userRoles(get_user_id(req, res), (error, roles) => {
      res.send(`User: ${JSON.stringify(req.user)} Roles: ${JSON.stringify(roles)}`)
    });
  });

  //  http://localhost:3500/users
  app.get('/users', [authenticated, acl.middleware(1, get_user_id, 'get_list')], (req, res) => {
    res.send(users);
  })

  //  http://localhost:3500/users/1
  app.get('/users/:id', [authenticated, acl.middleware(2, get_user_id, 'get')], (req, res) => {
    const {
      id
    } = req.params;
    find_user_by_id(id, (err, user) => {
      res.send(user);
    })
  })

  // Only for users and higher
  //  http://localhost:3500/secret
  app.get('/secret', [authenticated, acl.middleware(1, get_user_id)], (req, res) => {
    res.send('Welcome Sir!');
  });

  // Logging out the current user
  //  http://localhost:3500/logout
  app.get('/logout', (req, res) => {
    req.logout();
    res.send('Logged out!');
  });

  // Logging in a user
  //  http://localhost:3500/login?username=bob&password=secret
  app.get('/login', passport.authenticate('local', {}), (req, res) => {
    const userId = get_user_id(req, res);
    acl.allow(userId, [`/users/${userId}`], 'get', () => {
      acl.addUserRoles(userId, ['user', userId]);
      res.send(`${userId} is logged in!`);
    });
  });

  // Setting a new role
  //  http://localhost:3500/allow/1/admin
  app.get('/allow/:user/:role', (req, res, next) => {
    const {
      user,
      role
    } = req.params;
    acl.addUserRoles(user, role);
    res.send(`${user} is a ${role}`);
  });

  // Unsetting a role
  //  http://localhost:3500/disallow/1/admin
  app.get('/disallow/:user/:role', (req, res, next) => {
    const {
      user,
      role
    } = req.params;
    acl.removeUserRoles(user, role);
    res.send(`${user} is not a ${role} anymore.`);
  });
}

// This gets the ID from currently logged in user
function get_user_id(req, res) {
  // Since numbers are not supported by node_acl in this case, convert
  //  them to strings, so we can use IDs nonetheless.
  return req.user && req.user.id.toString() || false;
}

// Helper used in session setup by passport
function find_user_by_id(id, cb) {
  var index = id - 1;
  if (users[index]) {
    cb(null, users[index]);
  } else {
    var error = new Error('User does not exist.');
    error.status = 404;
    cb(error);
  }
}

// Helper used in the local strategy setup by passport
function find_by_username(username, cb) {
  const user = users.find(user => user.username === username);
  if (user) {
    return cb(null, user);
  }
  return cb(null, null);
}

// Generic debug logger for node_acl
function logger() {
  return {
    debug: (msg) => console.log('-DEBUG-', msg)
  };
}

// Authentication middleware for passport
function authenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.send(401, 'User not authenticated');
}

app.listen(3500, () => {
  console.log('Express server listening on port 3500');
});
