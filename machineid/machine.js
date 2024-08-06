const md = require('machine-digest')

const uuid = md.uuid()           // sha256 hex digest of combined info
const UUID = md.UUID()           // sha256 hex digest of only hardware UUID
const rawUUID = md.rawUUID()     // raw hardware UUID

// get summary, default make hex digest
console.log("uuid", uuid);
console.log("UUID", UUID);
console.log("rawUUID", rawUUID);

