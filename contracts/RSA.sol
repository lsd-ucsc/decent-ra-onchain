pragma solidity >=0.8.0 <0.9.0;


import "./asn1-decode/Asn1Decode.sol";
import "./Algorithm.sol";
import "./RSAVerify.sol";

import {BytesUtils} from "./ens-contracts/BytesUtils.sol";


contract RSA {

    using BytesUtils for bytes;
    using Asn1Decode for bytes;
    //using NodePtr for uint;

    function verifyWithComponents(
        bytes memory modulus,
        bytes memory exponent,
        bytes32 hash,
        bytes memory sig
    )
        public
        view
        returns (bool)
    {
        bool ok;
        bytes memory result;

        (ok, result) = RSAVerify.rsarecover(modulus, exponent, sig);

        return ok && hash == result.readBytes32(result.length - 32);
    }

    /**
    * @dev Extracts modulus and exponent (respectively) from a DER-encoded RSA public key
    * @param key A DER-encoded RSA public key
    */
    function extractKeyComponents(bytes memory key)
        public
        pure
        returns (bytes memory, bytes memory)
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

        return (modulus, exponent);
    }

    function verify(bytes memory key, bytes memory data, bytes memory sig)
        public
        view
        returns (bool)
    {
        bytes memory m;
        bytes memory e;

        (m, e) = extractKeyComponents(key);

        return verifyWithComponents(m, e, sha256(data), sig);
    }

}
