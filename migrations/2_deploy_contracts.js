var rlp = artifacts.require("RLPReader");
var helper = artifacts.require("Helper");
var byteutils = artifacts.require("../contracts/ensdomains/ens-contracts/BytesUtils.sol");
let RsaSha256Algorithm = artifacts.require("sig-verify-algs/RsaSha256Algorithm");
let X509ForestOfTrust = artifacts.require("X509Parse");

module.exports = function(deployer) {
    deployer.deploy(helper);
    deployer.link(helper, rlp);
    deployer.deploy(rlp);
    // deployer.deploy(byteutils);

    deployer.deploy(RsaSha256Algorithm)
    .then(() => deployer.deploy(byteutils))
    .then(() => deployer.link(byteutils, X509ForestOfTrust))
    .then(() => deployer.deploy(X509ForestOfTrust, RsaSha256Algorithm.address))
    .then(() => console.log("X509ForestOfTrust: " + X509ForestOfTrust.address))
    .then(() => console.log("RSA address: ", RsaSha256Algorithm.address));
    console.log("deployment successful");
};
