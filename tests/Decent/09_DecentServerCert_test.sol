// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {DecentServerCert_proxy} from "./09_DecentServerCert.sol";
import {IASReportCertMgr} from "../../contracts/IASReportCertMgr.sol";
import {IASRootCertMgr} from "../../contracts/IASRootCertMgr.sol";
import {TestCerts} from "../TestCerts.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract DecentServerCert_testSuit {

    //===== member variables =====

    address m_testProxyAddr;

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    function beforeAll() public {
        m_testProxyAddr = address(new DecentServerCert_proxy());
    }

    function strFindTest() public {
        try DecentServerCert_proxy(m_testProxyAddr).strFindTest() {
            Assert.ok(true, "strFindTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - strFindTest");
        }
    }

    function jsonSimpleReadValPosTest() public {
        try DecentServerCert_proxy(m_testProxyAddr).jsonSimpleReadValPosTest() {
            Assert.ok(true, "jsonSimpleReadValPosTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - jsonSimpleReadValPosTest");
        }
    }

    function verifyEPIDAttestationRepTest() public {
        IASRootCertMgr rootCertMgr =
            new IASRootCertMgr(TestCerts.IAS_ROOT_CERT_DER);
        IASReportCertMgr iasReportCertMgr =
            new IASReportCertMgr(address(rootCertMgr));

        try DecentServerCert_proxy(m_testProxyAddr).verifyEPIDAttestationRepTest(
            address(iasReportCertMgr)
        ) {
            Assert.ok(true, "verifyEPIDAttestationRepTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - verifyEPIDAttestationRepTest");
        }
    }

    function verifySelfSignTest() public {
        try DecentServerCert_proxy(m_testProxyAddr).verifySelfSignTest() {
            Assert.ok(true, "verifySelfSignTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - verifySelfSignTest");
        }
    }

    function extractDecentServerKeyTest() public {
        try DecentServerCert_proxy(m_testProxyAddr).extractDecentServerKeyTest() {
            Assert.ok(true, "extractDecentServerKeyTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - extractDecentServerKeyTest");
        }
    }

    function loadCertTest() public {
        IASRootCertMgr rootCertMgr =
            new IASRootCertMgr(TestCerts.IAS_ROOT_CERT_DER);
        IASReportCertMgr iasReportCertMgr =
            new IASReportCertMgr(address(rootCertMgr));

        try DecentServerCert_proxy(m_testProxyAddr).loadCertTest(
            address(iasReportCertMgr)
        ) {
            Assert.ok(true, "loadCertTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - loadCertTest");
        }
    }

}
