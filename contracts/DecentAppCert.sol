// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;


import {Asn1Decode} from "./asn1-decode/Asn1Decode.sol";
import {BytesUtils} from "./ens-contracts/BytesUtils.sol";
import {LibSecp256k1Sha256} from "./LibSecp256k1Sha256.sol";
import {OIDs} from "./Constants.sol";
import {X509CertNodes} from "./X509CertNodes.sol";
import {X509Extension} from "./X509Extension.sol";


library DecentAppCert {

    using Asn1Decode for bytes;
    using BytesUtils for bytes;
    using X509CertNodes for X509CertNodes.CertNodesObj;
    using LibSecp256k1Sha256 for X509CertNodes.CertNodesObj;
    using LibSecp256k1Sha256 for X509CertNodes.CertTbsNodesObj;

    //===== structs =====

    struct DecentApp {
        bool isVerified;

        address issuerKeyAddr;
        bytes32 issuerEnclaveHash;

        address appKeyAddr;
        bytes32 appEnclaveHash;
        bytes appPlatform;
        bytes appAuthList;
    }

    //===== functions =====

    function extractDecentAppKey(
        DecentApp memory self,
        bytes memory appCertDer,
        X509CertNodes.CertNodesObj memory certNodes
    )
        internal
        pure
    {
        (bytes32 keyId, bytes32 curveId) =
            certNodes.tbs.extractPubKeyAlg(appCertDer);
        require(
            keyId == OIDs.OID_KEY_EC_PUBLIC,
            "Unsupported Key type"
        );
        require(
            curveId == OIDs.OID_KEY_EC_SECP256K1,
            "Unsupported curve"
        );

        self.appKeyAddr =
            LibSecp256k1Sha256.pubKeyBytesToAddr(
                certNodes.tbs.extractPubKeyBytes(appCertDer)
            );
    }

    function verifyAppCertSign(
        DecentApp memory self,
        bytes memory appCertDer,
        X509CertNodes.CertNodesObj memory certNodes
    )
        internal
        pure
    {
        (bytes32 signR, bytes32 signS) =
            certNodes.extractSignRS(appCertDer);

        require(
            LibSecp256k1Sha256.verifySignMsg(
                self.issuerKeyAddr,
                appCertDer.allBytesAt(certNodes.tbs.root),
                signR,
                signS
            ),
            "Invalid app cert"
        );
    }

    function extractAppCertExtensions(
        DecentApp memory self,
        bytes memory appCertDer,
        X509CertNodes.CertNodesObj memory certNodes
    )
        internal
        pure
    {
        // extracting extensions
        X509Extension.ExtEntry[] memory extEntries =
            new X509Extension.ExtEntry[](5);
        extEntries[0].extnID = OIDs.OID_DECENT_EXT_VER;
        extEntries[1].extnID = OIDs.OID_DECENT_PLATFORM_ID;
        extEntries[2].extnID = OIDs.OID_DECENT_APP_HASH;
        extEntries[3].extnID = OIDs.OID_DECENT_AUTH_LIST;

        X509Extension.extractNeededExtensions(
            appCertDer,
            certNodes.tbs.extNode,
            certNodes.algTypeNode,
            extEntries
        );

        // Decent Cert version
        require(
            extEntries[0].isParsed &&
            extEntries[0].extnValue.length == 1 &&
            uint8(extEntries[0].extnValue[0]) == 49, // '1' == 49
            "Unsupported Decent ver"
        );

        // platform ID
        require(extEntries[1].isParsed, "Platform ID not found");
        self.appPlatform = extEntries[1].extnValue;

        // app enclave hash
        require(extEntries[2].isParsed, "App hash not found");
        self.appEnclaveHash = extEntries[2].extnValue.readBytes32(0);

        // app AuthList
        require(extEntries[3].isParsed, "App AuthList not found");
        self.appAuthList = extEntries[3].extnValue;
    }

    /**
     * read and verify Decent App Certificate, and thn load infos into DecentApp
     * struct
     * @param self DecentApp struct NOTE: the issuerKeyAddr
     *             field must be set before calling this function
     * @param appCertDer Decent App Certificate in DER format
     */
    function loadCert(
        DecentApp memory self,
        bytes memory appCertDer
    )
        internal
        pure
    {
        X509CertNodes.CertNodesObj memory certNodes;
        certNodes.loadCertNodes(appCertDer);

        // Check signature algorithm
        bytes32 algType;
        // algType = appCertDer.bytes32At(
        //     appCertDer.firstChildOf(certNodes.tbs.algTypeNode)
        // );
        // require(algType == OIDs.OID_ALG_ECDSA_SHA_256, "alg type mismatch");
        algType = appCertDer.bytes32At(
            appCertDer.firstChildOf(certNodes.algTypeNode)
        );
        require(algType == OIDs.OID_ALG_ECDSA_SHA_256, "alg type mismatch");

        verifyAppCertSign(self, appCertDer, certNodes);

        extractDecentAppKey(self, appCertDer, certNodes);

        extractAppCertExtensions(self, appCertDer, certNodes);
    }

}
