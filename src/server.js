"use strict";
const LocalStrategy = require('passport-local').Strategy;
const fs = require('fs');
const axios = require("axios");
const express = require("express");
const cors = require("cors");
const session = require('express-session');
const fetch = require('node-fetch');
const md = require("machine-digest");
const path = require('path');
const bodyParser = require('body-parser');
const passport = require('passport');
const redis = require("redis");
const bcrypt = require('bcrypt');
const config = require("../config");
const utils = require("./utils");
const logger = require("./logger");
const errors = require("./errors");
const publicKeyPath = path.join(__dirname,"..","sample.public.pem");
const { LicenseKey } = require("./model");

const app = express();
const port = process.env.PORT || 3002;

app.use(cors());
//redis connection
const client = redis.createClient({
  host: "localhost",
  port: 6379,
}); 
client.on("connect", () => {
  console.log("Connected to Redis");
});
client.on("error", (err) => {
  console.error("Redis error:", err);
});

let PublicKey;    
// Initialize PublicKey
try {
  const publicKeyBuffer = fs.readFileSync(publicKeyPath);
  PublicKey = publicKeyBuffer.toString("utf8");
  logger.info("Public key loaded successfully.");
} catch (err) {
  logger.error(`Failed to read public key file: ${err.message}`);
  process.exit(1); // Exit process if reading fails
}
// Express middleware
app.use(cors()); // Enable CORS
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Change to true if using HTTPS
}));
app.use(passport.initialize());
app.use(passport.session());
passport.use(new LocalStrategy(
  (username, password, done) => {
    console.log(`Attempting login for username: ${username}`);
    client.hgetall(`user:${username}`, (err, user) => {
      if (err) {
        console.error('Error fetching user:', err);
        return done(err);
      }
      if (!user) {
        console.log('User not found');
        return done(null, false, { message: 'Incorrect username or password.' });
      }
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) {
          console.error('Error comparing passwords:', err);
          return done(err);
        }
        if (!isMatch) {
          console.log('Password incorrect');
          return done(null, false, { message: 'Incorrect username or password.' });
        }
        console.log('Login successful');
        return done(null, user);
      });
    });
  }
));
passport.serializeUser((user, done) => {
  console.log(`Serializing user: ${user.username}`);
  done(null, user.username);
});
passport.deserializeUser((username, done) => {
  console.log(`Deserializing user: ${username}`);
  client.hgetall(`user:${username}`, (err, user) => {
    if (err) {
      console.error('Error deserializing user:', err);
      return done(err);
    }
    done(null, user);
  });
});

// Routes from index.js{issue part}
app.get("/issue", (req, res) => {
  console.log('Rendering issue page');
  res.render("license", { message: "" });
});

app.post("/issue", async (req, res) => {
  const { startDate, endDate, persist } = req.body;
  const options = {
    startDate: new Date(startDate).getTime(),
    endDate: new Date(endDate).getTime(),
    persist: persist === "on",  // Convert checkbox value to boolean
  };

  try {
    console.log('Issuing license with options:', options);
    const result = await LicenseKey.issue(options);
    console.log('License issued successfully:', result.key);
    res.render("license", { message: `License key issued successfully: ${result.key}` });
  } catch (error) {
    console.error('Failed to issue license key:', error.message);
    res.render("license", { message: `Failed to issue license key: ${error.message}` });
  }
});

// Routes from server .js
app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    console.log('User authenticated, rendering index.html');
    res.sendFile(__dirname + '/public/index.html');
  } else {
    console.log('User not authenticated, redirecting to login');
    res.redirect('/login');
  }
});

//login route
app.get('/login', (req, res) => {
  console.log('Rendering login.html');
  res.sendFile(__dirname + '/public/login.html');
});

app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login' }),
  (req, res) => {
    console.log('Login successful, redirecting to home');
    res.redirect('/');
  }
);

//signup route
app.get('/signup', (req, res) => {
  console.log('Rendering signup.html');
  res.sendFile(__dirname + '/public/signup.html');
});

app.post('/signup', (req, res) => {
  const { username, password } = req.body;

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err);
      res.status(500).send('Error signing up. Please try again later.');
      return;
    }

    console.log('Storing user data in Redis');
    client.hmset(`user:${username}`, {
      username: username,
      password: hash,
      id: Math.random().toString(36).substr(2, 9) // Generate a random ID
    }, (err, reply) => {
      if (err) {
        console.error('Error storing user data in Redis:', err);
        res.status(500).send('Error signing up. Please try again later.');
      } else {
        console.log(`User signed up: ${username}`);
        res.redirect('/login');
      }
    });
  });
});

// Logout route
app.get('/logout', (req, res) => {
  console.log('Attempting to logout user');

  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).send('Error logging out. Please try again later.');
    }

    req.session.destroy((err) => {
      if (err) {
        console.error('Session destroy error:', err);
        return res.status(500).send('Error logging out. Please try again later.');
      }

      console.log('Session destroyed:', req.session);

      res.clearCookie('connect.sid', { path: '/' }, (err) => {
        if (err) {
          console.error('Cookie clear error:', err);
        } else {
          console.log('Session cookie cleared');
        }
      });

      console.log('User logged out and session destroyed');
      res.redirect('/login');
    });
  });
});

// API endpoint to get current user data
app.get('/user', (req, res) => {
  if (req.isAuthenticated()) {
    console.log('Fetching current user data');
    res.json(req.user);
  } else {
    console.log('Unauthorized access attempt');
    res.status(401).json({ message: 'Unauthorized' });
  }
});

// Fetch Redis keys and display
app.get("/api/redis/keys", (req, res) => {
  console.log('Fetching Redis keys');
  client.keys("LCT:LicenseKey:*", async (err, keys) => {
    if (err) {
      console.error("Error fetching Redis keys:", err);
      return res.status(500).json({ error: "Failed to fetch Redis keys" });
    }
    try {
      const keysWithDetails = await Promise.all(keys.map(async (key) => {
        return new Promise((resolve) => {
          client.hgetall(key, (err, keyData) => {
            if (err) {
              console.error(`Error fetching data for key ${key}:`, err);
              return resolve({
                key,
                hasMachine: false,
                issueDate: 'N/A',
                startDate: 'N/A',
                endDate: 'N/A'
              });
            }

            // Log the fetched data for debugging purposes
            console.log(`Fetched key data for ${key}:`, keyData);

            // Resolve with all necessary fields
            resolve({
              key,
              hasMachine: keyData && keyData.machine ? true : false,
              issueDate: keyData.issueDate || 'N/A',
              startDate: keyData.startDate || 'N/A',
              endDate: keyData.endDate || 'N/A'
            });
          });
        });
      }));

      console.log("Redis keys with detailed data:", keysWithDetails);
      res.json({ keys: keysWithDetails });
    } catch (error) {
      console.error("Error processing Redis keys:", error);
      res.status(500).json({ error: "Failed to process Redis keys" });
    }
  });
});

// Send create request - Adjusted to use local routes
app.post("/api/create-license", async (req, res) => {
  const { name, startDate, endDate, persist } = req.body;

  const currentDate = Date.now();

  // Validation checks
  if (endDate < currentDate) {
      return res.status(400).json({ error: "End date cannot be less than the current date." });
  }
  if (endDate < startDate) {
      return res.status(400).json({ error: "End date cannot be earlier than the start date." });
  }

  try {
    const options = req.body;
    console.log('Creating license with options:', options);
    const result = await LicenseKey.issue(options);
    res.json({ key: result.key });
  } catch (error) {
    console.error("Error creating license:", error.message);
    res.status(500).json({ error: "Failed to create license" });
  }
});

// Delete a specific key
app.delete("/api/redis/keys/:keyName", (req, res) => {
  const { keyName } = req.params;

  console.log(`Deleting Redis key: ${keyName}`);
  client.del(keyName, (err, reply) => {
    if (err) {
      console.error(`Error deleting Redis key "${keyName}":`, err);
      return res.status(500).json({ error: `Failed to delete Redis key "${keyName}"` });
    }

    console.log(`Deleted Redis key "${keyName}":`, reply === 1 ? "Deleted" : "Not found");
    res.json({ success: reply === 1 });
  });
});

// Delete all keys
app.delete("/api/redis/keys", (req, res) => {
  console.log('Deleting all Redis keys');
  client.keys("LCT:LicenseKey:*", (err, keys) => {
    if (err) {
      console.error("Error fetching Redis keys:", err);
      return res.status(500).json({ error: "Failed to fetch Redis keys" });
    }

    if (keys.length === 0) {
      console.log("No keys to delete");
      return res.json({ message: "No keys to delete" });
    }

    keys.forEach((key) => {
      client.del(key, (err, reply) => {
        if (err) {
          console.error(`Error deleting Redis key "${key}":`, err);
          // Handle errors if needed
        } else {
          console.log(`Deleted Redis key "${key}":`, reply === 1 ? "Deleted" : "Not found");
        }
      });
    });

    res.json({ message: "Deleted all keys successfully" });
  });
});


// Handle License Function{validation part}
async function handleLicense(req) {
  const { key, id: machine } = req.body;
  console.log("Processing key:", key);

  if (!utils.attrsNotNull(req.body, ["key", "id"])) {
    return { status: errors.BAD_REQUEST };
  }

  const data = LicenseKey.validate(key);
  if (!data) return { status: errors.INVALID_INPUT };

  if (!config.stateless) {
    const licenseKey = await LicenseKey.fetch(key);
    console.log("Validated and fetched");

    if (!licenseKey || licenseKey.revoked == 1) {
      logger.error(`Failed to check the license key in database: ${key}`);
      return { status: errors.NULL_DATA };
    }

    let success = await LicenseKey.authorize(key, machine);
    if (licenseKey.machine === machine) success = true;
    console.log("Authorized");

    if (!success) {
      logger.error(`Used key encountered: ${key}, ${machine}`);
      return { status: errors.DUPLICATE_DATA };
    }
  }

  const license = LicenseKey.generateLicense(key, machine);
  console.log("Generated");
  return { status: errors.SUCCESS, license, hasMachine: !!machine };
}


app.get("/license", (req, res) => {
  console.log('Rendering license page');
  res.render("license", { message: "" });
});

// License validation endpoint
app.post("/v1/license", async (req, res) => {
  const result = await handleLicense(req);
  res.json(result);
});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
  