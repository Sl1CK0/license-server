  const express = require('express');
  const fs = require('fs');
  const path = require('path');
  const bodyParser = require('body-parser');
  const fetch = require('node-fetch');
  const md = require("machine-digest");
  const utils = require("../src/utils");
  const config = require("../config");
  const logger = require("../src/logger");

  const app = express();
  const port = 3001;

  const keyPath = path.join(__dirname, 'key.txt');
  const licenseServer = "http://localhost:3002/v1/license";
  const publicKeyPath = path.join(__dirname, "sample.public.pem");

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

  // Middleware
  app.use(express.static('public'));
  app.use(bodyParser.json());

  // Function to check license
  const checkLicense = async (licenseKey) => {
    logger.info("Verifying license");

    const machineId = md.get().digest;
    let _license;

    try {
      const params = {
        method: "POST",
        body: JSON.stringify({ id: machineId, key: licenseKey }),
        headers: { "Content-Type": "application/json" },
      };

      logger.info(`Request to license server: ${JSON.stringify(params)}`);
      const res = await fetch(licenseServer, params);
      const resData = await res.json();
      logger.info(`Response from license server: ${JSON.stringify(resData)}`);

      if (resData.status !== 0) {
        logger.error(`License server returned an error. Status code: ${resData.status}`);

        throw new Error(`License server error. Status code: ${resData.status}`);
      }
      _license = resData.license;
    } catch (fetchErr) {
      logger.error(`Failed to fetch license from server: ${fetchErr.message}`);
      throw new Error(`License server fetch error: ${fetchErr.message}`);
    }

    try {
      const buf = Buffer.from(_license, "hex");
      const decryptedLicense = utils.crypt(PublicKey, buf, false).toString();
      const license = JSON.parse(decryptedLicense);

      logger.debug(`Decrypted license: ${JSON.stringify(license)}`);

      const isValid = license.key === licenseKey &&
                      license.machine === machineId &&
                      license.identity === config.identity &&
                      (license.meta.persist || 
                        (license.meta.startDate < Date.now() && 
                        license.meta.endDate > Date.now()));

      logger.debug(`License validation result: ${isValid}`);
      return isValid;
    } catch (decryptErr) {
      logger.error(`Failed to decrypt or validate license: ${decryptErr.message}`);
      throw new Error(`License decryption/validation error: ${decryptErr.message}`);
    }
  };

  // Check license on server startup
  const validateKeyOnStartup = async () => {
    if (fs.existsSync(keyPath)) {
      try {
        const key = fs.readFileSync(keyPath, 'utf8');
        logger.info("Key file found. Validating...");
        const isValid = await checkLicense(key);
        return isValid;
      } catch (error) {
        logger.error(`Failed to validate license on startup: ${error.message}`);
        return false;
      }
    } else {
      logger.info("Key file does not exist.");
      return false;
    }
  };

  // Serve default page or redirect to success if key.txt is valid
  app.get('/', async (req, res) => {
    try {
      const isValid = await validateKeyOnStartup();
      if (isValid) {
        res.redirect('/success?validated=true');
      } else {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
      }
    } catch (error) {
      logger.error(`Error during startup validation: ${error.message}`);
      res.status(500).send("Internal Server Error");
    }
  });

  // Serve success page only if license is validated
  app.get('/success', (req, res) => {
    try {
      const isValid = req.query.validated === 'true';
      if (isValid) {
        res.sendFile(path.join(__dirname, 'public', 'success.html'));
      } else {
        res.redirect('/?validated=false');
      }
    } catch (error) {
      logger.error(`Error during success page validation: ${error.message}`);
      res.status(500).send("Internal Server Error");
    }
  });

  // Endpoint to save text and validate license key
  app.post('/save-text', async (req, res) => {
    const { text } = req.body;
    if (!text) {
      return res.status(400).json({ success: false, message: 'No text provided' });
    }

    fs.writeFile(keyPath, text, async (err) => {
      if (err) {
        logger.error(`Failed to save text: ${err.message}`);
        return res.status(500).json({ success: false, message: 'Failed to save text' });
      }

      try {
        const isValid = await checkLicense(text);
        if (isValid) {
          res.json({ success: true });
        } else {
          res.status(400).json({ success: false, message: 'License validation failed' });
        }
      } catch (error) {
        logger.error(`License validation error: ${error.message}`);
        res.status(500).json({ success: false, message: 'License validation error' });
      }
    });
  });

  // Start server
  app.listen(port, async () => {
    console.log(`Server is running on http://localhost:${port}`);
    try {
      const isValid = await validateKeyOnStartup();
      if (isValid) {
        console.log("Key is valid. Redirecting to success page...");
      } else {
        console.log("Key is not valid or not found. Serving index.html.");
      }
    } catch (error) {
      console.error(`Error during startup validation: ${error.message}`);
    }
  });
