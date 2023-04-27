// SPDX-License-Identifier: MIT
pragma solidity >0.5.2;


import {Asn1Decode, NodePtr} from "./asn1-decode/Asn1Decode.sol";
import {Base64} from "./Base64.sol";
import {RLPReader} from "./RLPReader.sol";


interface CryptoAlgorithm {
    function verifySign(
        bytes memory key,
        bytes memory data,
        bytes memory sig
    )
        external
        view
        returns (bool);
}


/*
 * @dev Stores validated X.509 certificate chains in parent pointer trees.
 * @dev The root of each tree is a CA root certificate
 */
// contract X509Parse is Ownable {
contract X509Parse {
    // using types defined in the imported libraries
    using Asn1Decode for bytes;
    using RLPReader for RLPReader.RLPItem;

    // DER certificate
    struct Certificate {
        uint40 timestamp;
        uint160 serialNumber;
    }

    // Intel IA certificate
    struct RootCert {
        bytes pubKey;
    }

    // Intel report certificate
    struct ReportCert {
        bytes32 algType;
        bytes pubKey;
    }

    // Decent server certificate signed by Intel report certificate
    struct DecentServerCert {
        bytes1 version;
        // bytes32[] hashedKeys;
        bytes enclaveHash;
        bytes keyringHash;
        bytes pubKey;
        bytes quoteStatus;
        bytes quoteBody;
        string platformId;
        mapping (bytes32 => bool) hashedKeys;

        // ecdsa fields
        address signer;
        bytes32 r;
        bytes32 s;

    }

    // variables for the certificates
    RootCert rootCert;
    ReportCert reportCert;
    DecentServerCert serverCert;


    // constants for extensions
    bytes32 constant private OID_ATTESTATION  = 0x6982f5c89a94ffdfaaab8591c1b5f7c2f782b01e030102000000000000000000;
    bytes32 constant private OID_DATA_VERSION = 0x6982f5c89a94ffdfaaab8591c1b5f7c2f782b01e010000000000000000000000;
    bytes32 constant private OID_HASHED_KEYS  = 0x6982f5c89a94ffdfaaab8591c1b5f7c2f782b01e040000000000000000000000;
    bytes32 constant private OID_PLATFORM_ID  = 0x6982f5c89a94ffdfaaab8591c1b5f7c2f782b01e020000000000000000000000;
    bytes32 constant private OID_STD_REP_DATA = 0x6982f5c89a94ffdfaaab8591c1b5f7c2f782b01e030101000000000000000000;

    bytes32 constant private OID_ALG_RSA_SHA_256 = 0x2a864886f70d01010b0000000000000000000000000000000000000000000000;

    // valid statuses for enclave quote
    mapping(bytes => bool) private quoteStatusMap;

    // algorithm oid bytes => signature verification contract
    mapping(bytes32 => CryptoAlgorithm) private algs;



    /**************************************************************************
     *  Constructor
     *************************************************************************/

    constructor(
        address RsaSha256AlgAddr
    )
    {
        algs[OID_ALG_RSA_SHA_256] = CryptoAlgorithm(RsaSha256AlgAddr);

        // initialize enclave quote status map
        quoteStatusMap['OK'] = true;
        quoteStatusMap['CONFIGURATION_NEEDED'] = true;
        quoteStatusMap['SW_HARDENING_NEEDED'] = true;
        quoteStatusMap['CONFIGURATION_AND_SW_HARDENING_NEEDED'] = true;
    }

    /**************************************************************************
     *  Helper Functions
     *************************************************************************/

    /**
     *  Returns the node containing the public key in the DER certificate
     */
    function getPubkeyNode(bytes memory cert) private pure returns (uint) {
        uint node1;
        uint node2;

        node1 = cert.root();
        node1 = cert.firstChildOf(node1);   // tbsCertificate
        node2 = cert.firstChildOf(node1);   // version
        node2 = cert.nextSiblingOf(node2);  // serialNumber
        node2 = cert.nextSiblingOf(node2);  // signature
        node2 = cert.nextSiblingOf(node2);  // issuer
        node2 = cert.nextSiblingOf(node2);  // validity
        node2 = cert.nextSiblingOf(node2);  // subject
        node2 = cert.nextSiblingOf(node2);  // subjectPublicKeyInfo

        return node2;
    }

    /**
     *  Returns the node containing the signature in the DER certificate
     */
    function getSignatureNode(bytes memory cert) private pure returns (uint) {
        uint node1;
        uint node2;

        node1 = cert.root();
        node1 = cert.firstChildOf(node1);   // tbsCertificate
        node2 = cert.nextSiblingOf(node1);  // signatureAlgorithm
        node2 = cert.nextSiblingOf(node2);  // signatureValue

        return node2;
    }

    /*
        Returns the start position of the JSON field
    */
    function getByteStartPosition(bytes memory item, bytes memory jsonString, uint startPos) public pure returns (uint){
        require(jsonString.length >= item.length);

        bool found = false;
        uint location;
        for (uint i = startPos; i <= jsonString.length - item.length; i++) {
            bool flag = true;
            uint j;
            for (j = 0; j < item.length; j++)
                if (jsonString [i + j] != item [j]) {
                    flag = false;
                    break;
                }
            if (flag) {
                found = true;
                location = i+j+3; // skips '":"' in json string
                break;
            }
        }
        return location;
    }

    /*
        Returns the end position of the JSON field
    */
    function getByteEndPosition(uint start, bytes memory jsonString) public pure returns (uint) {
        uint end = start;
        while (end != jsonString.length && jsonString[end] != '"') {
            end++;
        }

        return end;
    }

    /*
        The nested JSON string contains the following that we need to verify
        - "isvEnclaveQuoteStatus": check whether the status is contain in the quoteStatusMap
        - "isvEnclaveQuoteBody": base64 decode the string and extract the enclave hash
        - keyring containing the hashed public keys
    */
    function validateJsonDictItems(bytes memory jsonString) public {
        // check the quote status
        bytes memory tofind = 'isvEnclaveQuoteStatus';
        uint startPosition = getByteStartPosition(tofind, jsonString, 0);
        uint endPosition = getByteEndPosition(startPosition, jsonString);


        for (uint i = startPosition; i != endPosition; i++) {
            serverCert.quoteStatus.push(jsonString[i]);
        }

        require(quoteStatusMap[serverCert.quoteStatus], "Invalid quote status");

        tofind = 'isvEnclaveQuoteBody';
        startPosition = getByteStartPosition(tofind, jsonString, endPosition);
        endPosition = getByteEndPosition(startPosition, jsonString);

        for (uint i = startPosition; i != endPosition; i++) {
            serverCert.quoteBody.push(jsonString[i]);
        }

        bytes memory decoded = Base64.decode(string(serverCert.quoteBody));

        // extract enclave hash
        startPosition = 112;
        endPosition = startPosition + 32;
        for (uint i = startPosition; i != endPosition; i++) {
            serverCert.enclaveHash.push(decoded[i]);
        }

        // extract keyring hash list
        startPosition = 368;
        endPosition = startPosition + 64;
        for (uint i = startPosition; i != endPosition; i++) {
            serverCert.keyringHash.push(decoded[i]);
        }
    }


    /**
     *  Extract the ecdsa parameters 'r' and 's' from the signature
     */
    function extractSignature(bytes memory sig) public pure returns (bytes32, bytes32){
        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(sig, 39)) // skips first 7 bytes. 0 + 7 + 32 = 39
            s := mload(add(sig, 74)) // skips 2 bytes. 39 + 3 = 42 + 32 = 74
        }
        return (r, s);
    }


    /**
        Use ecrecover to get the signer and check if it matches the one from the public key
    */
    function checkRecoveredPublicKey(bytes32 msg, bytes32 r, bytes32 s, bytes memory pubkeyBytes) public returns (bool) {
        // get the address from the public key
        bytes memory pubkey = truncateLenPrefix(pubkeyBytes, 4);  // 4 is the length of the prefix for pubkey
        bytes32 hashedPub = keccak256(pubkey);
        address pubkeysigner = address(uint160(uint256(hashedPub)));

        // try to recover signer using different v values
        // ecdsa in Ethereum uses v to recover public key
        // https://bitcoin.stackexchange.com/questions/38351/ecdsa-v-r-s-what-is-v
        bool foundSigner = false;
        address signer;
        for (uint8 v = 27; v <= 28; v++) {
            signer = ecrecover(msg, v, r, s);
            if (signer == pubkeysigner) {
                serverCert.signer = signer;
                foundSigner = true;
                break;
            }
        }

        return foundSigner;
    }


    /**
     *  Truncate the length prefix from Der encoded structure
        NOTE: this doesn't work for some reason, even though it gives the exact same result
     */
    function truncateLenPrefix(bytes memory toTruncate, uint prefixLen) private returns (bytes memory) {
        bytes memory truncated = new bytes(toTruncate.length - prefixLen);
        for (uint i = prefixLen; i < toTruncate.length; i++) {
            truncated[i - prefixLen] = toTruncate[i];
        }

        return truncated;
    }

    /**************************************************************************
     *  Functions to add certificates
     *************************************************************************/

    /**
     * Add the root certificate of IAS
     */
    function addRootCert(bytes memory cert) public {
        Certificate memory certificate;
        uint node1;
        uint node2;
        uint pubkeyNode;
        uint sigNode;
        bytes32 algType;

        certificate.timestamp = uint40(block.timestamp);

        node1 = cert.root();
        node1 = cert.firstChildOf(node1);
        node2 = cert.firstChildOf(node1);
        if (cert[NodePtr.ixs(node2)] == 0xa0) {
            node2 = cert.nextSiblingOf(node2);
        }

        // Extract serial number
        certificate.serialNumber = uint160(cert.uintAt(node2));

        // extract algorithm type
        node2 = cert.nextSiblingOf(node2);
        node2 = cert.firstChildOf(node2);
        algType = cert.bytes32At(node2);

        // extract signature
        sigNode = getSignatureNode(cert);

        // extract the public key
        pubkeyNode = getPubkeyNode(cert);
        rootCert.pubKey = cert.allBytesAt(pubkeyNode);


        // Verify signature
        require(
            algs[algType].verifySign(
                rootCert.pubKey,
                cert.allBytesAt(node1),
                cert.bytesAt(sigNode)
            ),
            "Signature doesnt match"
        );
    } // end of addRootCert


    /**
     * Add the intermediate certificate signed by root cert
     */
    function addReportCert(bytes memory cert) public {
        Certificate memory certificate;
        uint node1;
        uint node2;
        uint pubkeyNode;
        uint sigNode;

        certificate.timestamp = uint40(block.timestamp);

        node1 = cert.root();
        node1 = cert.firstChildOf(node1);
        node2 = cert.firstChildOf(node1);
        if (cert[NodePtr.ixs(node2)] == 0xa0) {
            node2 = cert.nextSiblingOf(node2);
        }
        // Extract serial number
        certificate.serialNumber = uint160(cert.uintAt(node2));

        // extract algorithm type
        node2 = cert.nextSiblingOf(node2);
        node2 = cert.firstChildOf(node2);
        reportCert.algType = cert.bytes32At(node2);

        // extract signature
        sigNode = getSignatureNode(cert);

        // Verify signature
        require(
            algs[reportCert.algType].verifySign(
                rootCert.pubKey,
                cert.allBytesAt(node1),
                cert.bytesAt(sigNode)
            ),
            "Signature doesnt match"
        );

        // extract the public key
        pubkeyNode = getPubkeyNode(cert);
        reportCert.pubKey = cert.allBytesAt(pubkeyNode);
    } // end of addReportCert



    /**
     * Add the Decent certificate signed by intermediate cert
     */
    function addDecentCert(bytes memory cert) public {
        Certificate memory certificate;
        uint node1;
        uint node2;
        uint node3;
        uint pubkeyNode;
        uint sigNode;
        bytes memory pubkeyDer;

        certificate.timestamp = uint40(block.timestamp);

        //// verify signature
        node1 = cert.root();
        node2 = cert.firstChildOf(node1);

        // extract signature
        sigNode = getSignatureNode(cert);
        (serverCert.r, serverCert.s) = extractSignature(cert.allBytesAt(sigNode));

        // get to the public key value
        pubkeyNode = getPubkeyNode(cert);
        pubkeyDer = cert.allBytesAt(pubkeyNode); // for keyring validation
        node3 = cert.firstChildOf(pubkeyNode);   // key algorithm type
        node3 = cert.nextSiblingOf(node3);       // key bytes

        // check that the signer is the same as the one from the public key
        bool validSigner = checkRecoveredPublicKey
        (
            sha256(cert.allBytesAt(node2)),      // hash of the certificate
            serverCert.r,                        // signature r
            serverCert.s,                        // signature s
            cert.allBytesAt(node3)               // public key
        );

        require(validSigner, "Invalid signature");

        // get to extensions
        node1 = getPubkeyNode(cert);             // subjectPublicKeyInfo
        node1 = cert.nextSiblingOf(node1);       // extensions

        if (cert[NodePtr.ixs(node1)] == 0xa3) {
            node1 = cert.firstChildOf(node1);
            node2 = cert.firstChildOf(node1);
            bytes32 oid;
            while (Asn1Decode.isChildOf(node2, node1)) {
                node3 = cert.firstChildOf(node2);
                oid = cert.bytes32At(node3);
                node3 = cert.nextSiblingOf(node3);

                if (oid == OID_DATA_VERSION) {
                    bytes1 certVersion = cert.bytesAt(node3)[0]; // b'1'
                    require(certVersion == '1', "Invalid version");
                    serverCert.version = certVersion;
                }

                if (oid == OID_PLATFORM_ID) {
                    bytes memory EPID = cert.bytesAt(node3);
                    serverCert.platformId = string(EPID);
                }

                if (oid == OID_ATTESTATION) {
                    bytes memory rlpBytes = cert.bytesAt(node3);
                    // [[cert1, cert2, ...], JSON dict, signature]
                    RLPReader.RLPItem[] memory list = RLPReader.toRlpItem(rlpBytes).toList();
                    RLPReader.RLPItem memory certificates = list[0];

                    // add report cert
                    addReportCert(certificates.toList()[0].toBytes());

                    // jsonDict
                    bytes memory jsonDict = list[1].toBytes();

                    // Verify signature over JSON dict
                    require(
                        algs[reportCert.algType].verifySign(
                            reportCert.pubKey,
                            jsonDict,
                            list[2].toBytes() // signature
                        ),
                        "Signature doesnt match"
                    );

                    validateJsonDictItems(jsonDict);
                }

                if (oid == OID_HASHED_KEYS) {
                    bytes memory keys = truncateLenPrefix(cert.allBytesAt(node3), 2);
                    bytes32 key;
                    for (uint bytepos = 0; bytepos < keys.length; bytepos += 32) {
                        assembly{
                            key := mload(add(add(keys, 32), bytepos))
                        }
                        serverCert.hashedKeys[key] = true;
                    }

                    // // check if public key is in hashed keys
                    bytes32 hashedPubKey = sha256(pubkeyDer);
                    require(serverCert.hashedKeys[hashedPubKey], "Public key not in hashed keys");
                }

                node2 = cert.nextSiblingOf(node2);
            }
        }
    } // end of addDecentCert

     /**************************************************************************
     *  Getters
     *************************************************************************/

    function getRootPubKey() external view returns (bytes memory) {
        return rootCert.pubKey;
    }

    function getReportPubKey() external view returns (bytes memory) {
        return reportCert.pubKey;
    }

    function getDecentServerCertPubKey() external view returns (bytes memory) {
        return serverCert.pubKey;
    }

    function getDecentServerCertVersion() external view returns (bytes1) {
        return serverCert.version;
    }

    function getDecentServerCertEpid() external view returns (string memory) {
        return serverCert.platformId;
    }

    function getDecentServerCertEnclaveHash() external view returns (bytes memory) {
        return serverCert.enclaveHash;
    }

    function getDecentServerCertKeyringHash() external view returns (bytes memory) {
        return serverCert.keyringHash;
    }

    function getR() external view returns (bytes32) {
        return serverCert.r;
    }

    function getS() external view returns (bytes32) {
        return serverCert.s;
    }


    function getSigner() external view returns (address) {
        return serverCert.signer;
    }


}