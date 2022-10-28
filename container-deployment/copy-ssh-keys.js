var fs = require("fs")
pubKey = fs.readFileSync("/root/.ssh/id_ed25519.pub").toString()
privKey = fs.readFileSync("/root/.ssh/id_ed25519").toString()
knownHosts = fs.readFileSync("/root/.ssh/known_hosts").toString()

module.exports.SSH_PRIV_KEY = privKey
module.exports.SSH_PUB_KEY = pubKey
module.exports.SSH_KNOWN_HOSTS = knownHosts