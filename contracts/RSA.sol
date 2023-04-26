pragma solidity >=0.8.0;

import "./Algorithm.sol";
import "./Asn1Decode.sol";
import "./BytesUtils.sol";
import "./RSAVerify.sol";

contract RSA {

    using BytesUtils for bytes;
    using Asn1Decode for bytes;
    using NodePtr for uint;

    bytes nodeBytes;
    bool validSig = false;

    

    function verifyWithComponents(bytes memory modulus, bytes memory exponent, bytes32 hash, bytes memory sig)
    external returns (bool)
    {
        bool ok;
        bytes memory result;

        (ok, result) = RSAVerify.rsarecover(modulus, exponent, sig);

        return ok && hash == result.readBytes32(result.length - 32);
    }


    function truncateLenPrefix(bytes memory toTruncate, uint prefixLen) private returns (bytes memory) {
        bytes memory truncated = new bytes(toTruncate.length - prefixLen);
        for (uint i = prefixLen; i < toTruncate.length; i++) {
            truncated[i - prefixLen] = toTruncate[i];
        }

        return truncated;
    }

    /**
    * @dev Extracts modulus and exponent (respectively) from a DER-encoded RSA public key
    * @param key A DER-encoded RSA public key
    */
    function extractKeyComponents(bytes memory key) public pure returns (bytes memory, bytes memory)
    {
        uint node;
        bytes32 oid;
        bytes memory modulus;
        bytes memory exponent;

        node = key.root();
        node = key.firstChildOf(node);

        // OID must be 1.2.840.113549.1.1.1 (rsaEncryption)
        oid = keccak256(key.bytesAt(key.firstChildOf(node)));
        require(oid == 0x3be606946d6f343b24d5ecdbd7e3370a5303ed54845f50f466a35f3bbeb46a45, "Invalid key");

        node = key.nextSiblingOf(node);
        node = key.rootOfBitStringAt(node);
        node = key.firstChildOf(node);
        modulus = key.uintBytesAt(node);
        node = key.nextSiblingOf(node);
        exponent = key.uintBytesAt(node);
        // nodeBytes = key.bytesAt(node);
        // modulus = truncateLenPrefix(nodeBytes, 1);
        // node = key.nextSiblingOf(node);
        // exponent = key.bytesAt(node);

        return (modulus, exponent);
    }

    /**
    * @dev Extracts modulus and exponent (respectively) from a DER-encoded RSA public key
    * @param key A DER-encoded RSA public key
    */
    function extractKeyComponents2(bytes memory key) public returns (bytes memory, bytes memory)
    {
        uint node;
        bytes32 oid;
        bytes memory nodeBytes;
        bytes memory modulus;
        bytes memory exponent;

        node = key.root();
        node = key.firstChildOf(node);

        // OID must be 1.2.840.113549.1.1.1 (rsaEncryption)
        oid = keccak256(key.bytesAt(key.firstChildOf(node)));
        require(oid == 0x3be606946d6f343b24d5ecdbd7e3370a5303ed54845f50f466a35f3bbeb46a45, "Invalid key");

        node = key.nextSiblingOf(node);
        node = key.rootOfBitStringAt(node);
        node = key.firstChildOf(node);
        nodeBytes = key.bytesAt(node);
        modulus = truncateLenPrefix(nodeBytes, 1);
        node = key.nextSiblingOf(node);
        exponent = key.bytesAt(node);

        return (modulus, exponent);
    }

    function verify(bytes memory key, bytes memory data, bytes memory sig)
    public view returns (bool)
    {
        bool ok;
        bytes memory result;
        bytes memory m;
        bytes memory e;

        (m, e) = extractKeyComponents(key);

        (ok, result) = RSAVerify.rsarecover(m, e, sig);

        return ok && sha256(data) == result.readBytes32(result.length - 32);
    }

    function verifySignature(
        bytes memory key,
        bytes memory message,
        bytes memory signature
    ) public {
        // extractKeyComponents(key);
        validSig = verify(key, message, signature);
    }

    function getBytes() public view returns (bytes memory) {
        return nodeBytes;
    }

    function isValidSig() public view returns (bool) {
        return validSig;
    }

}