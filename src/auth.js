// auth.js

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

// Replace with your user model or a mock user database
const users = [
  { id: 1, username: 'user', password: 'password' }
];

passport.use(new LocalStrategy(
  (username, password, done) => {
    client.hgetall(`user:${username}`, (err, user) => {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false, { message: 'Incorrect username or password.' });
      }
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) {
          return done(err);
        }
        if (!isMatch) {
          return done(null, false, { message: 'Incorrect username or password.' });
        }
        return done(null, user);
      });
    });
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = users.find(u => u.id === id);
  done(null, user);
});

module.exports = passport;
