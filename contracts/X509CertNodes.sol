// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;


import {Asn1Decode, NodePtr} from "../libs/asn1-decode/Asn1Decode.sol";
import {X509Parser} from "../libs/x509-forest-of-trust/X509Parser.sol";


library X509CertNodes {

    using Asn1Decode for bytes;

    //===== structs =====

    struct CertTbsNodesObj {
        uint256 root;
        uint8 version;
        uint256 serialNode;
        uint256 algTypeNode;
        uint256 issuerNode;
        uint256 validityNode;
        uint256 subjectNode;
        uint256 pubKeyNode;
        uint256 extNode;
    }

    struct CertNodesObj {
        uint256 root;
        CertTbsNodesObj tbs;
        uint256 algTypeNode;
        uint256 sigNode;
    }

    //===== functions =====

    function loadTbsNodes(
        CertTbsNodesObj memory tbsNodes,
        bytes memory certDer,
        uint256 tbsRoot
    )
        internal
        pure
    {
        tbsNodes.root = tbsRoot;

        // version
        uint256 verNode = certDer.firstChildOf(tbsNodes.root);
        require(
            certDer[NodePtr.ixs(verNode)] == 0xa0,
            "invalid cert ver node"
        );
        uint256 verValNode = certDer.firstChildOf(verNode);
        uint256 ver = certDer.uintAt(verValNode);
        require(
            ver == 2,
            "cert ver must be 2"
        );
        tbsNodes.version = uint8(ver);

        // serialNumber
        tbsNodes.serialNode = certDer.nextSiblingOf(verNode);

        // signature
        tbsNodes.algTypeNode = certDer.nextSiblingOf(tbsNodes.serialNode);

        // issuer
        tbsNodes.issuerNode = certDer.nextSiblingOf(tbsNodes.algTypeNode);

        // validity
        tbsNodes.validityNode = certDer.nextSiblingOf(tbsNodes.issuerNode);

        // subject
        tbsNodes.subjectNode = certDer.nextSiblingOf(tbsNodes.validityNode);

        // subjectPublicKeyInfo
        tbsNodes.pubKeyNode = certDer.nextSiblingOf(tbsNodes.subjectNode);

        // extensions
        tbsNodes.extNode = certDer.nextSiblingOf(tbsNodes.pubKeyNode);
    }

    function loadCertNodes(
        CertNodesObj memory certNodes,
        bytes memory certDer
    )
        internal
        pure
    {
        // certificate ASN.1 root
        certNodes.root = certDer.root();

        // tbsCertificate
        uint256 tbsNode = certDer.firstChildOf(certNodes.root);
        loadTbsNodes(certNodes.tbs, certDer, tbsNode);

        // signatureAlgorithm
        certNodes.algTypeNode = certDer.nextSiblingOf(certNodes.tbs.root);

        // signatureValue
        certNodes.sigNode = certDer.nextSiblingOf(certNodes.algTypeNode);
    }

    function getValidityTimestamps(
        CertTbsNodesObj memory tbsNodes,
        bytes memory certDer
    )
        internal
        pure
        returns (uint256 notBefore, uint256 notAfter)
    {
        uint256 notBeforeNode = certDer.firstChildOf(tbsNodes.validityNode);
        uint256 notAfterNode = certDer.nextSiblingOf(notBeforeNode);

        notBefore =
            X509Parser.toTimestamp(certDer.bytesAt(notBeforeNode));

        notAfter =
            X509Parser.toTimestamp(certDer.bytesAt(notAfterNode));
    }

}
