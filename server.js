// Load .env variables
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

// Importing installed libraries
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override");
const initializePassport = require("./passport");

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

// Define the function to get a user by email from the database
function getUserByEmail(email) {
  return new Promise((resolve, reject) => {
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
      if (err) return reject(err);
      resolve(results[0]); // Return the first user found
    });
  });
}

// Define the function to get a user by ID from the database
function getUserById(id) {
  return new Promise((resolve, reject) => {
    db.query("SELECT * FROM users WHERE id = ?", [id], (err, results) => {
      if (err) return reject(err);
      resolve(results[0]);
    });
  });
}

// Initialize passport for authentication and pass db-related functions
initializePassport(passport, getUserByEmail, getUserById);

app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method"));

// Register POST
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    db.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword],
      (err, results) => {
        if (err) {
          console.error("Error inserting user into the database:", err.message);
          return res.redirect("/register"); // Redirect if there's an error
        }
        console.log("User registered successfully:", results.insertId);
        res.redirect("/login"); // Redirect after successful registration
      }
    );
  } catch (e) {
    console.error("Registration error:", e);
    res.redirect("/register"); // Redirect if there's an error
  }
});

// Login POST
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

// Routes
app.get("/nodejs", (req, res) => {
  const sql = "SELECT * FROM STUDENTS";
});
app.get("/", checkAuthenticated, (req, res) => {
  res.render("index.ejs", { name: req.user.name });
});

app.get("/login", checkNotAuthenticated, (req, res) => {
  res.render("login.ejs");
});

app.get("/register", checkNotAuthenticated, (req, res) => {
  res.render("register.ejs");
});

// Logout functionality
app.delete("/logout", (req, res) => {
  req.logout(req.user, (err) => {
    if (err) return next(err);
    res.redirect("/login");
  });
});

// Authentication check
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
app.listen(8890, () => {
  console.log("listening.....");
});
