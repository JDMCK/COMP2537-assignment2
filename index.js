require('dotenv').config();
const express = require('express');
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

// Establishes a connection to the mongoDB of 'assignment2'
const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
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
  req.session.userType = req.body.userType;
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

// Validates session
function sessionValidation(req, res, next) {
  if (req.session.authenticated)
    next();
  else
    res.redirect('/');
}

// Determines if current user is an admin
function adminAuthorization(req, res, next) {
  if (req.session.userType != 'admin') {
    res.status(403);
    res.render("errorMessage", { error: "Not Authorized" });
  }
  else
    next();
}

// Shows home if user logged in, shows options to login or signup otherwise
app.get('/', async (req, res) => {
  res.render('index', { req: req, active: 'home' });
});

// Login page
app.get('/login', (req, res) => {
  res.render('login', { active: 'login' });
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

  const result = await usersCollection.find({ email: email }).project({ email: 1, name: 1, userType: 1, password: 1 }).toArray();

  // No users with that input email found
  if (result.length != 1) {
    res.redirect('/invalidLogin');
    return;
  }

  // Checks if password is correct
  const passwordOk = await bcrypt.compare(password, result[0].password)
  if (passwordOk) {
    req.body.name = result[0].name;
    req.body.userType = result[0].userType;
    createSession(req);
    res.redirect('/members');
  }
  else {
    res.redirect("/invalidLogin");
  }
});

// If the login info is wrong
app.get('/invalidLogin', (req, res) => {
  res.render('invalidLogin');
});

// Logout, destroy cookie and drop session from db
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// New user signup page
app.get('/signup', (req, res) => {
  res.render('signup');
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

  let emails = await usersCollection.find({ email: email }).project({ email: 1 }).toArray();

  if (validationResult.error != null) {
    res.render('invalidSignup', { error: validationResult.error });
  } else if (emails.length == 0) {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const userType = email == 'jesse@jessemckenzie.com' ? 'admin' : 'user';
    req.body.userType = userType;
    await usersCollection.insertOne({
      email: email,
      name: name,
      password: hashedPassword,
      userType: userType
    });
    createSession(req);
    res.redirect('/members');
  } else {
    res.render('existingAccount');
  }
});

app.get('/members', sessionValidation, (req, res) => {

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
    },
    {
      image: 'dog.gif',
      caption: 'glizzy dog'
    },
    {
      image: 'cat.gif',
      caption: 'cat jam'
    },
    {
      image: 'lion.gif',
      caption: 'mighty lion'
    }
  ];
  const shuffleArray = array => {
    for (let i = array.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      const temp = array[i];
      array[i] = array[j];
      array[j] = temp;
    }
    return array;
  }

  res.render('members', { name: req.session.name, images: shuffleArray(images), active: 'members' });
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
  const result = await usersCollection.find().project({ name: 1, userType: 1, email: 1 }).toArray();
  res.render('admin', { users: result, currentUserName: req.session.name, active: 'admin' });
});

app.get('/adminControl', async (req, res) => {
  const user = JSON.parse(req.query.user);
  const newUserType = user.userType == 'admin' ? 'user' : 'admin';

  await usersCollection.updateOne({ email: user.email }, { $set: { userType: newUserType } });
  res.redirect('/admin');
});

app.use((req, res) => {
  res.status(404);
  res.render('404', { active: 'error404' });
});

app.listen(port, () => console.log(`Listening on port ${port}...`));