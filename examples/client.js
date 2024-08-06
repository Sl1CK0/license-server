"use strict";
const md = require("machine-digest");
const fetch = require("node-fetch");
const fs = require("fs");
const path = require("path");
const logger = require("../src/logger");
const utils = require("../src/utils");
const config = require("../config"); // Ensure this path is correct for your config module

const keyPath = path.join(__dirname, 'key.txt');
const licenseServer = "http://localhost:3000/v1/license";
const publicKeyPath = path.join(__dirname, "sample.public.pem");

let PublicKey;

md.secret = "client software";

try {
  // Read and initialize PublicKey
  const publicKeyBuffer = fs.readFileSync(publicKeyPath);
  PublicKey = publicKeyBuffer.toString("utf8");
  logger.info("Public key loaded successfully.");
} catch (err) {
  logger.error(`Failed to read public key file: ${err.message}`);
  process.exit(1); // Exit process if reading fails
}

const checkLicense = async () => {
  logger.info("Verifying license");
  let status = false;

  while (!status) {
    try {
      status = await _checkLicense();
    } catch (e) {
      logger.error(`Error during license verification: ${e.message}`);
      logger.error("Failed to verify software license, please check your license key and license file");
      process.exit(1);
    }
  }
};

const _checkLicense = async () => {
  let licenseKey;
  try {
    licenseKey = fs.readFileSync(keyPath).toString().trim();
    logger.info("License key loaded successfully.");
  } catch (err) {
    logger.error(`Failed to read license key file: ${err.message}`);
    throw new Error("License key file read error");
  }

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
      throw new Error("Failed to get license from server, error code: " + resData.status);
    }
    _license = resData.license;
  } catch (fetchErr) {
    logger.error(`Failed to fetch license from server: ${fetchErr.message}`);
    throw new Error("License server fetch error");
  }

  try {
    const buf = Buffer.from(_license, "hex");
    const decryptedLicense = utils.crypt(PublicKey, buf, false).toString();
    const license = JSON.parse(decryptedLicense);
    logger.debug(`Decrypted license: ${JSON.stringify(license)}`);

    if (
      license.key === licenseKey &&
      license.machine === machineId &&
      license.identity === config.identity
    ) {
      if (
        license.meta.persist ||
        (license.meta.startDate < Date.now() &&
          license.meta.endDate > Date.now())
      ) {
        return true;
      } else {
        throw new Error("Invalid effect date of license");
      }
    } else {
      throw new Error("Invalid license");
    }
  } catch (decryptErr) {
    logger.error(`Failed to decrypt or validate license: ${decryptErr.message}`);
    throw new Error("License decryption/validation error");
  }
};

const start = async () => {
  await checkLicense();
  logger.info("Verified license successfully, ready to start now...");
};

module.exports = {
  PublicKey,
  checkLicense,
};

start();
