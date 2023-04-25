var rlp = artifacts.require("RLPReader");
var helper = artifacts.require("Helper");
let RsaSha256Algorithm = artifacts.require("sig-verify-algs/RsaSha256Algorithm");
let X509ForestOfTrust = artifacts.require("X509Parse");
let DateTime = artifacts.require("ethereum-datetime/DateTime");

module.exports = function(deployer) {
    deployer.deploy(helper);
    deployer.link(helper, rlp);
    deployer.deploy(rlp);

    deployer.deploy(RsaSha256Algorithm)
    .then(() => deployer.deploy(DateTime))
    .then(() => deployer.deploy(X509ForestOfTrust, RsaSha256Algorithm.address, DateTime.address))
    .then(() => console.log("X509ForestOfTrust: " + X509ForestOfTrust.address))
    .then(() => console.log("RSA address: ", RsaSha256Algorithm.address));
    console.log("deployment successful");
};
