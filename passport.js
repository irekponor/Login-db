const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

// Define the function to get a user by email from the database
function getUserByEmail(email) {
  return new Promise((resolve, reject) => {
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
      if (err) return reject(err);
      resolve(results[0]); // Return the first user found
    });
  });
}

function initialize(passport, getUserByEmail, getUserById) {
  // users authentication
  const authenticateUsers = async (email, password, done) => {
    try {
      // Await the promise to get the user by email
      const user = await getUserByEmail(email);

      if (user == null) {
        return done(null, false, { message: "User not found" });
      }

      if (await bcrypt.compare(password, user.password)) {
        return done(null, user);
      } else {
        return done(null, false, { message: "Incorrect password!" });
      }
    } catch (e) {
      console.log(e);
      return done(e);
    }
  };

  // the usernameField can be customized to whatever you want
  passport.use(
    new LocalStrategy({ usernameField: "email" }, authenticateUsers)
  );

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => {
    return done(null, getUserById(id));
  });
}

module.exports = initialize;
