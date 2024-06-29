'use strict'

/**
 * Module dependencies.
 */

var express = require('express');
var path = require('path');
var session = require('express-session');
var mysql = require('mysql2/promise');
const util = require('util');
const argon2 = require('argon2');
const { V4 } = require('paseto');
const { createPrivateKey } = require('crypto');
// const key = createPrivateKey(privateKey);

// Error handling
process.on('uncaughtException', function (err) {
  console.error(err);
  console.log("Node NOT Exiting...");
});

// MySQL server connection

const connection = mysql.createPool({
  host: 'localhost',
  user: 'Admin',
  password: 'UkR3ROzecWiHVuTUCjVL',
  database: 'userdb',
  waitForConnections: true,
  multipleStatements: true,
  keepAliveInitialDelay: 10000,
  enableKeepAlive: true
})

//payload
const payload = {
  sub: 'username',
  'urn:example:claim': 'example'
}

var app = module.exports = express();

// config

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false }))
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 600000000 }
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

// deny access to logged out users to restricted pages
function restrict(req, res, next) {
  if (req.session.loggedin) {
    next();
  } else {
    console.log('Access denied!');
    res.redirect('/login');
  }
}
app.get('/', (req, res) => {
  res.render('login');
});

// logged in users can see this
app.get('/restricted', restrict, function (req, res) {
  const USERNAME = req.session.username;
  res.render('restricted',{
    loggedIn: true,
    USERNAME
  })
});

app.get('/logout', function (req, res) {
  // destroy the user's session to log them out
  // will be re-created next request
  req.session.destroy(function () {
    res.redirect('/login');
  });
});

app.get('/login', function (req, res) {
  res.render('login');
});

app.get('/register', function (req, res) {
  res.render('register');
});

app.get('/index', function (req, res) {
  res.render('index');
})
async function hashPassword(password) {
  try {
    return await argon2.hash(password);
  } catch {
    console.log('Error');
  }
}
//register and log in user

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
        console.log(hash);
        poolConn.query(`INSERT INTO secureuser (userid, username, pass) VALUES (DEFAULT, ?, ?)`, [username, hash])
        req.session.username = username;
        res.redirect('../restricted');

      }).catch(err => {
        console.log(err);
      });
    }
  }
  else {
    res.send('Please enter Username and Password then <a href="/register">try again</a>');
    res.end();
  }
});

// login and authenticate user
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
        req.session.loggedin = true;
        req.session.username = username;
        res.redirect('../restricted');

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