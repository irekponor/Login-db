const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

function initialize(passport, getUserByEmail, getUserById) {
  // users authentication
  const authenticateUsers = async (email, password, done) => {
    // get users by email
    const user = getUserByEmail(email);
    if (user == null) {
      return done(null, false, { message: "User not found" });
    }
    try {
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

  // the usernamefield can be customized to whatever you want
  passport.use(
    new LocalStrategy({ usernameField: "email" }, authenticateUsers)
  );
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => {
    return done(null, getUserById(id));
  });
}

module.exports = initialize;
