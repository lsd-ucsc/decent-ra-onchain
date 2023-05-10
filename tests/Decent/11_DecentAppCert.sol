// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;


// This import is automatically injected by Remix
import "remix_tests.sol";

import {Asn1Decode} from "../../contracts/asn1-decode/Asn1Decode.sol";
import {DecentAppCert} from "../../contracts/DecentAppCert.sol";
import {X509CertNodes} from "../../contracts/X509CertNodes.sol";

import {TestCerts} from "../TestCerts.sol";


contract DecentAppCert_proxy {

    using Asn1Decode for bytes;
    using DecentAppCert for DecentAppCert.DecentApp;
    using X509CertNodes for X509CertNodes.CertNodesObj;

    //===== functions =====

    function extractDecentAppKeyTest() public {
        bytes memory appCertDer = TestCerts.DECENT_APP_CERT_DER;

        DecentAppCert.DecentApp memory decentApp;
        X509CertNodes.CertNodesObj memory certNodes;
        certNodes.loadCertNodes(appCertDer);

        decentApp.extractDecentAppKey(appCertDer, certNodes);

        Assert.equal(
            decentApp.appKeyAddr,
            TestCerts.DECENT_APP_CERT_KEY_ADDR,
            "appKeyAddr should be equal"
        );
    }

    function verifyAppCertSignTest() public {
        bytes memory appCertDer = TestCerts.DECENT_APP_CERT_DER;

        DecentAppCert.DecentApp memory decentApp;
        X509CertNodes.CertNodesObj memory certNodes;
        certNodes.loadCertNodes(appCertDer);

        decentApp.issuerKeyAddr = TestCerts.DECENT_SVR_CERT_KEY_ADDR;

        decentApp.verifyAppCertSign(appCertDer, certNodes);
    }

    function extractAppCertExtensionsTest() public {
        bytes memory appCertDer = TestCerts.DECENT_APP_CERT_DER;

        DecentAppCert.DecentApp memory decentApp;
        X509CertNodes.CertNodesObj memory certNodes;
        certNodes.loadCertNodes(appCertDer);

        decentApp.extractAppCertExtensions(appCertDer, certNodes);

        Assert.equal(
            keccak256(decentApp.appPlatform),
            keccak256("SGX_EPID"),
            "appPlatform not match"
        );
        Assert.equal(
            decentApp.appEnclaveHash,
            TestCerts.DECENT_APP_CERT_ENCL_HASH,
            "appEnclaveHash not match"
        );
        Assert.equal(
            keccak256(decentApp.appAuthList),
            keccak256(TestCerts.DECENT_APP_CERT_AUTHLIST),
            "appAuthList not match"
        );
    }

    function loadCertTest() public {
        bytes memory appCertDer = TestCerts.DECENT_APP_CERT_DER;

        DecentAppCert.DecentApp memory decentApp;
        decentApp.issuerKeyAddr = TestCerts.DECENT_SVR_CERT_KEY_ADDR;

        decentApp.loadCert(appCertDer);

        Assert.equal(
            decentApp.appKeyAddr,
            TestCerts.DECENT_APP_CERT_KEY_ADDR,
            "appKeyAddr should be equal"
        );
        Assert.equal(
            keccak256(decentApp.appPlatform),
            keccak256("SGX_EPID"),
            "appPlatform not match"
        );
        Assert.equal(
            decentApp.appEnclaveHash,
            TestCerts.DECENT_APP_CERT_ENCL_HASH,
            "appEnclaveHash not match"
        );
        Assert.equal(
            keccak256(decentApp.appAuthList),
            keccak256(TestCerts.DECENT_APP_CERT_AUTHLIST),
            "appAuthList not match"
        );
    }

}
