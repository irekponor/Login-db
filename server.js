// Load .env variables
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

// Importing installed libraries
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const passport = require("passport");
const initializePassport = require("./passport");
const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override");

const app = express();

// Start a connection to the database
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Connect to the database
db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err.stack);
    return;
  }
  console.log("Connected to database.");
});

// Initialize passport for authentication
initializePassport(
  passport,
  (email) => getUserByEmail(db, email),
  (id) => getUserById(db, id)
);

app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: process.env.SECRET_KEY, // The secret_key can be named anything you want brrr
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method"));

// Login POST route
app.post(
  "/login",
  checkNotAuthenticated,
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

// Register POST route
app.post("/register", checkNotAuthenticated, async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const { name, email } = req.body;

    // Inserting the new user into the database
    db.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword],
      (err, results) => {
        if (err) {
          console.error("Error inserting user:", err);
          return res.redirect("/register");
        }
        console.log("User registered:", results.insertId);
        res.redirect("/login");
      }
    );
  } catch (e) {
    console.error("Registration error:", e);
    res.redirect("/register");
  }
});

// Routes
app.get("/", checkAuthenticated, (req, res) => {
  res.render("index.ejs", { name: req.user.name });
});

app.get("/login", checkNotAuthenticated, (req, res) => {
  res.render("login.ejs");
});

app.get("/register", checkNotAuthenticated, (req, res) => {
  res.render("register.ejs");
});

// Logout functionality code
app.delete("/logout", (req, res) => {
  req.logout(req.user, (err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

// Authentication checks
function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
}

// Start the server
app.listen(2991);

module.exports = { db };
