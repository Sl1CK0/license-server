"use strict";
/* dependencies */
const config = require("../config");
const crypto = require("crypto");
const logger = require("./logger");
const errors = require("./errors");
const utils = require("./utils");
const fs = require("fs");
const path = require("path");
const { log } = require("console");

let dal;

if (!config.stateless) {
  dal = require("redis-async-wrapper");
  dal.init({ url: config.redis, keyPrefix: config.name });
} else {
  logger.info("Running in stateless mode, DAL not initialized.");
}

const Formats = {
  key: "LicenseKey:%s",
};

const PrivateKey = {
  key: fs.readFileSync(config.rsa_private_key).toString(),
  passphrase: config.rsa_passphrase,
};
const PublicKey = fs.readFileSync(config.rsa_public_key).toString();

const LicenseKey = dal ? new dal.Redis_Hash({ tpl: Formats.key }) : {};

LicenseKey.generateLicense = (key, machine) => {
  const license = {
    identity: config.identity,
    machine,
    key,
    meta: LicenseKey.validate(key),
  };
  const buf = Buffer.from(JSON.stringify(license), "utf8");
  const _license = utils.crypt(PrivateKey, buf, true);
  return _license.toString("hex");
};

LicenseKey.authorize = async (key, machine) => {
  return LicenseKey.hsetnx([key], "machine", machine);
};

LicenseKey.fetch = (key) => {
  return LicenseKey.hgetall([key]);
};

LicenseKey.validate = (key) => {
  const buf = Buffer.from(key, "hex");
  try {
    const _data = utils.crypt(PublicKey, buf, false);
    const data = JSON.parse(_data.toString("utf8"));
    
    if (data.identity === config.identity) {
      if (data.persist == 1) return data;
      else if (data.startDate < Date.now() && data.endDate > Date.now())
        return data;
    }
    logger.info(`Encountered invalid key ${_data}`);
  } catch (e) {
    logger.error(e.toString());
  }
};

LicenseKey.issue = async (options = {}) => {
  const meta = {
    identity: config.identity || "Software",
    persist: options.persist ? 1 : 0,
    startDate: options.startDate || Date.now(),
    endDate: options.endDate || Date.now() + config.expireAfter,
    issueDate: Date.now(),
  };
  let key;
  try {
    const buf = Buffer.from(JSON.stringify(meta), "utf8");
    key = utils.crypt(PrivateKey, buf, true).toString("hex");
    const data = { revoked: 0, issueDate: meta.issueDate };
    logger.info(`Generated key: ${key}`);
    logger.info(`Data to be set in Redis: ${JSON.stringify(data)}`);
    await LicenseKey.hmset([key], data);
    logger.info(`License key set in Redis: ${key}`);
  } catch (err) {
    logger.error(`Error in issuing license: ${err}`);
  }

  return { status: errors.SUCCESS, key };
};

LicenseKey.revoke = async (key) => {
  console.log("the key after call", key )
  if (!config.stateless) await LicenseKey.hset([key], "revoked", 1);
  return { status: errors.SUCCESS };
};

module.exports = { LicenseKey };