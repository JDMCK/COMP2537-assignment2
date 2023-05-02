require('dotenv').config();
const express = require('express');
const fs = require('fs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const saltRounds = 12;

const port = process.env.PORT || 8000;
const app = express();

const expireTime = 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * milliseconds)

// Secret info for mongodb
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;

const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

// Secret for cookie
const node_session_secret = process.env.NODE_SESSION_SECRET;

// Gets a reference to the mongo database / creates a mongo client
const MongoClient = require("mongodb").MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true`;
let database = new MongoClient(atlasURI, { useNewUrlParser: true, useUnifiedTopology: true });

// Gets a reference to the users collection
const usersCollection = database.db(mongodb_database).collection('users');

// Establishes a connection to the mongoDB of 'assignmen1'
const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/assignment1`,
  crypto: {
    secret: mongodb_session_secret
  }
});

// Lets the server look at the req body
app.use(express.urlencoded({ extended: false }));

// Uses ejs as the view engine
app.set('view engine', 'ejs');

// Generates the cookie
const createSession = (req) => {
  req.session.authenticated = true;
  req.session.name = req.body.name;
  req.session.email = req.body.email;
  req.session.cookie.maxAge = expireTime;
};

// For css and images
app.use('/css', express.static('./public/index.css'));
app.use('/img', express.static('./public/'));

// Uses express-session, and uses the mongoStore to store the session
app.use(session({
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false,
  resave: true
}));

// Shows home if user logged in, shows options to login or signup otherwise
app.get('/', async (req, res) => {

  let html = './views/index.ejs';

  if (req.session.authenticated) {
    html = `
    <link rel="stylesheet" href="css">
    <div class="content">
      <h1>Welcome, ${req.session.name}</h1>
      <a href="/members">VIP Zone</a>
      <br>
      <br>
      <a href="/logout">Signout</a>
    </div>`;
  }

  res.render(html);
});

// Login page
app.get('/login', (req, res) => {
  let html = `
  <link rel="stylesheet" href="css">
  <div class="content">
    <h1>Sign In</h1>
    <form action="/loggingin" method="post">
      <input type="text" name="email" placeholder="email">
      <input type="password" name="password" placeholder="password">
      <button>Submit</button>
    </form>
  </div>
  <br>
  <p>or</p>
  <br>
  <a href="/signup">Signup</a>`;
  res.send(html);
});

app.post('/loggingin', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const schema = Joi.object(
    {
      email: Joi.string().email(),
      password: Joi.string().max(20).required()
    }
  );

  const validationResult = schema.validate(req.body);
  if (validationResult.error != null) {
    res.redirect("/invalidLogin");
    return;
  }

  const result = await usersCollection.find({ email: email }).project({ email: 1, name: 1, password: 1 }).toArray();

  // No users with that input email found
  if (result.length != 1) {
    res.redirect('/invalidLogin');
    return;
  }

  // Checks if password is correct
  const passwordOk = await bcrypt.compare(password, result[0].password)
  if (passwordOk) {
    req.body.name = result[0].name;
    createSession(req);
    res.redirect('/members');
  }
  else {
    res.redirect("/invalidLogin");
  }
});

// If the login info is wrong
app.get('/invalidLogin', (req, res) => {
  let html = `
  <link rel="stylesheet" href="css">
  <div class="content">
    <h1>Invalid password</h1>
    <a href="/login">Try again</a>
  </div>`;
  res.send(html);
});

// Logout, destroy cookie and drop session from db
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// New user signup page
app.get('/signup', (req, res) => {
  let html = `
  <link rel="stylesheet" href="css">
  <div class="content">
    <h1>Signup</h1>
    <form action="/signupSubmit" method="post">
      <input type="text" name="name" placeholder="name">
      <input type="password" name="password" placeholder="password">
      <input type="text" name="email" placeholder="johnsmith@example">
      <button>Submit</button>
    </form>
  </div>
  <br>
  <p>or</p>
  <br>
  <a href="/login">Login</a>`;
  res.send(html);
});

app.post('/signupSubmit', async (req, res) => {

  const email = req.body.email;
  const name = req.body.name;
  const password = req.body.password;

  const schema = Joi.object(
    {
      name: Joi.string().alphanum().max(20).required(),
      password: Joi.string().max(20).required(),
      email: Joi.string().email().required()
    }
  );

  const validationResult = schema.validate(req.body);

  let html;
  let emails = await usersCollection.find({ email: email }).project({ email: 1 }).toArray();

  if (validationResult.error != null) {

    html = `
    <link rel="stylesheet" href="css">
    <div class="content">
      <h1>${validationResult.error.details[0].message}</h1>
      <a href="/signup">Try again</a>
    </div>`;
    res.send(html);

  } else if (emails.length == 0) {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await usersCollection.insertOne({ email: email, name: name, password: hashedPassword });
    createSession(req);
    res.redirect('/members');
  } else {
    html = `
      <link rel="stylesheet" href="css">
      <div class="content">
        <h1>Sorry, that email is being used</h1>
        <a href="/signup">Try again</a>
      </div>`;
    res.send(html);
  }
});

app.get('/members', (req, res) => {

  const images = [
    {
      image: 'giraffe.gif',
      caption: 'sassy giraffe'
    },
    {
      image: 'fish.gif',
      caption: 'spazzy fish'
    },
    {
      image: 'penguin.gif',
      caption: 'flying penguin'
    }
  ];

  if (req.session.authenticated) {
    let image = images[Math.floor(Math.random() * images.length)];
    let html = `
    <link rel="stylesheet" href="css">
    <div class="content">
      <img src="img/${image.image}" alt="sassy giraffe">
      <h1>Hello ${req.session.name}, this is a ${image.caption}</h1>
      <a href="/logout">Signout</a>
      <br>
      <br>
      <a href="/">Home</a>
    </div>`;
    res.send(html);
  } else {
    res.redirect('/');
  }
});

app.use('*', (req, res) => {
  let html = `
  <link rel="stylesheet" href="css">
  <div class="content">
    <h1>404</h1>
    <p>Page not found.</p>
    <br>
    <a href="/">Home</a>
  </div>`;
  res.status(404);
  res.send(html);
});

app.listen(port, () => console.log(`Listening on port ${port}...`));