'use strict'

/**
 * Module dependencies.
 */

var express = require('express');
var path = require('path');
var session = require('express-session');
var mysql = require('mysql2/promise');
const argon2 = require('argon2');
const { V4 } = require('paseto');
const xss = require('xss');
require('dotenv').config({ path: __dirname + '/.env' });

// Error handling
process.on('uncaughtException', function (err) {
  console.error(err);
  console.log("Node NOT Exiting...");
});



// MySQL server connection
const connection = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB,
  waitForConnections: true,
  keepAliveInitialDelay: 10000,
  enableKeepAlive: true
})

var app = module.exports = express();

// Config
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: false }))
app.use(session({

  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false,

}))

// Session-persisted message middleware
app.use(function (req, res, next) {
  var err = req.session.error;
  var msg = req.session.success;

  delete req.session.error;
  delete req.session.success;

  res.locals.message = '';

  if (err) res.locals.message = '<p class="msg error">' + err + '</p>';
  if (msg) res.locals.message = '<p class="msg success">' + msg + '</p>';

  next();
});

// Deny access to logged out users to restricted pages
function restrict(req, res, next) {

  if (req.session.token === undefined) {
    console.log('Access denied!')
   res.redirect('/login');
  } else {

  V4.verify(req.session.token, pubKey).then((payload) => {

    const tokenScopes = new Set(payload.scopes);

    if (tokenScopes.has('restricted:view')) {
      console.log('Access granted!');
      next();
    } else {
      res.redirect('/login');
    }
  });
}
}

let comments = []; // Store in memory for demonstration purposes

// Generate key pair for PASETO, for demonstration purposes, do not use this in production
let privKey; // ASSUME THIS IS SECURE STORAGE
let pubKey;

(async () => {
  const { publicKey: publicKey_paserk, secretKey: privateKey_paserk } = await V4.generateKey('public', { format: "paserk" })
  privKey = privateKey_paserk;
  pubKey = publicKey_paserk;
})();

// Routes
app.get('/', (req, res) => {
  res.render('login', { comments: comments });
});

// Logged in users can see this
app.get('/restricted', restrict, function (req, res) {
  res.render('restricted', {
  });
});

app.get('/logout', function (req, res) {
  req.session.destroy(function () {
    res.redirect('/login');
  });
});

app.get('/login', function (req, res) {
  res.render('login', { comments: comments });
});

app.get('/register', function (req, res) {
  res.render('register');
});

app.get('/index', function (req, res) {
  res.render('index', { comments: comments });
})

app.post('/comment', (req, res) => {

  const comment = xss(req.body.comment); // Sanitize the input 

  comments.push(comment);

  res.redirect('/');

});
// Hashing function
async function hashPassword(password) {
  try {
    return await argon2.hash(password);
  } catch {
    console.log('Hashing Error');
  }
}


//Registration
app.post('/auth/register', async (req, res) => {

  const username = req.body.username;
  const password = req.body.password;
  const poolConn = await connection.getConnection();

  if (username && password) {

    const [rows] = await poolConn.query(`SELECT * FROM secureuser WHERE username =?`, [username])

    if (rows.length > 0) {
      res.send('Username already exists, click to <a href="/register">try again</a>');
    }
    else {
      hashPassword(password).then(hash => {
        poolConn.query(`INSERT INTO secureuser (userid, username, pass) VALUES (DEFAULT, ?, ?)`, [username, hash])

        req.session.username = username;
        res.redirect('../restricted');

      }).catch(err => {
        console.log(err);
      });
      try {
        const token = await V4.sign({ user: username, scopes: ['restricted:view'], exp: new Date(Date.now() + 5 * 60 * 1000).toISOString() }, privKey);
        req.session.token = token;
      } catch (err) {
        console.log(err);
      }
    }
  }
  else {
    res.send('Please enter Username and Password then <a href="/register">try again</a>');
    res.end();
  }
});

// Authentication
app.post('/auth/login', async (req, res) => {

  const username = req.body.username;
  const password = req.body.password;
  const poolConn = await connection.getConnection();

  // Secure login query
  if (username && password) {

    const [rows] = await poolConn.query(`SELECT * FROM secureuser WHERE username=?`, [username])

    if (rows.length > 0) {

      const user = rows[0];

      if (await argon2.verify(user.pass, password)) {
        req.session.username = username; // Send token as a cookie or in the response body
        try {

          const token = await V4.sign({ user: username, scopes: ['restricted:view'], exp: new Date(Date.now() + 5 * 60 * 1000).toISOString() }, privKey);
          req.session.token = token;

        } catch (err) {
          console.log(err);
        }
        res.redirect('/restricted');

      } else {
        // Password is incorrect
        res.send('Incorrect Username and/or Password, click to <a href="/login">try again</a>');
        res.end();
      }
    } else {
      // No user found with that username
      res.send('Incorrect Username and/or Password, click to <a href="/login">try again</a>');
      res.end();
    }
  } else {
    // No username or password provided
    res.send('Please enter Username and Password then <a href="/login">try again</a>');
    res.end();
  }
});





if (!module.parent) {
  app.listen(3000);
  console.log(`Express started on port 3000`);
}