// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {DecentAppCert_proxy} from "./11_DecentAppCert.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract DecentAppCert_testSuit {

    //===== member variables =====

    address m_testProxyAddr;

    //===== functions =====

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    function beforeAll() public {
        m_testProxyAddr = address(new DecentAppCert_proxy());
    }

    function extractDecentAppKeyTest() public {
        try DecentAppCert_proxy(m_testProxyAddr).extractDecentAppKeyTest() {
            Assert.ok(true, "extractDecentAppKeyTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - extractDecentAppKeyTest");
        }
    }

    function verifyAppCertSignTest() public {
        try DecentAppCert_proxy(m_testProxyAddr).verifyAppCertSignTest() {
            Assert.ok(true, "verifyAppCertSignTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - verifyAppCertSignTest");
        }
    }

    function extractAppCertExtensionsTest() public {
        try DecentAppCert_proxy(m_testProxyAddr).extractAppCertExtensionsTest() {
            Assert.ok(true, "extractAppCertExtensionsTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - extractAppCertExtensionsTest");
        }
    }

}
