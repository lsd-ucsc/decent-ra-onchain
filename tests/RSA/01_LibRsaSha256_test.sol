// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {LibRsaSha256_proxy} from "./01_LibRsaSha256.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract LibRsaSha256_testSuite {

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    function beforeAll() public {
    }

    function extractComponentsTest() public {
        LibRsaSha256_proxy proxy = new LibRsaSha256_proxy();
        try proxy.extractComponentsTest() {
            Assert.ok(true, "extractComponentsTest should pass");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch {
            Assert.ok(false, "unexpected error - extractComponentsTest");
        }
    }

    function verifyWithComponentsTest() public {
        LibRsaSha256_proxy proxy = new LibRsaSha256_proxy();
        try proxy.verifyWithComponentsTest() {
            Assert.ok(true, "verifyWithComponentsTest should pass");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch {
            Assert.ok(false, "unexpected error - verifyWithComponentsTest");
        }
    }

    function verifySignMsgTest() public {
        LibRsaSha256_proxy proxy = new LibRsaSha256_proxy();
        try proxy.verifySignMsgTest() {
            Assert.ok(true, "verifySignMsgTest should pass");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch {
            Assert.ok(false, "unexpected error - verifySignMsgTest");
        }
    }

}
