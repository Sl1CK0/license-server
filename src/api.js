"use strict";
const express = require("express");
const router = express.Router();
const config = require("../config");
const utils = require("./utils");
const model = require("./model");
const logger = require("./logger");
const errors = require("./errors");
const { LicenseKey } = require("./model");

class Handler {
  async handleLicense(req, res) {
    const { key, id: machine } = req.body;
    console.log("Processing key:", key);
    if (!utils.attrsNotNull(req.body, ["key", "id"]))
      return res.json({ status: errors.BAD_REQUEST });
    console.log("a");
    const data = LicenseKey.validate(key);
    if (!data) return res.json({ status: errors.INVALID_INPUT, Ping: "strig" });
    if (!config.stateless) {
      console.log("b");
      const licenseKey = await LicenseKey.fetch(key);
      console.log(key);
      if (!licenseKey || licenseKey.revoked == 1) {
        console.log("d");
        logger.error(`Failed to check the license key in database: ${key}`);
        console.log("c");
        return res.json({ status: errors.NULL_DATA });
      }

      let success = await LicenseKey.authorize(key, machine);
      console.log("auth");
      if (licenseKey.machine === machine) success = true;
      console.log("licenseKey.machine === machine) success = true");
      if (!success) {
        logger.error(`Used key encountered: ${key}, ${machine}`);
        return res.json({ status: errors.DUPLICATE_DATA });
      }
    }
    const license = LicenseKey.generateLicense(key, machine);
    console.log("generetate", license);
    return res.json({ status: errors.SUCCESS, license });
  }

  async revoke(req, res) {
    const { key } = req.body;
    console.log("Revoke key:", key);
    try {
      await LicenseKey.revoke(key);
      res.json({ status: errors.SUCCESS });
    } catch (error) {
      console.error("Failed to revoke license key:", error.message);
      res.status(500).json({ status: errors.SERVER_ERROR });
    }
  }

  async issue(req, res) {
    const options = req.body;
    console.log("Issue options:", options);
    try {
      const result = await LicenseKey.issue(options);
      res.json(result);
    } catch (error) {
      console.error("Failed to issue license key:", error.message);
      res.status(500).json({ status: errors.SERVER_ERROR });
    }
  }
}
console.log("exit handeler");
const handler = new Handler();
router.post("/create", handler.issue.bind(handler));
router.post("/license", handler.handleLicense.bind(handler));
router.post("/revoke", handler.revoke.bind(handler));

module.exports = { router, handler };
