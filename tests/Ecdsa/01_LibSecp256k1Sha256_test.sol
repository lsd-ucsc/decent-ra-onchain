// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {LibSecp256k1Sha256} from "../../contracts/LibSecp256k1Sha256.sol";
import {LibSecp256k1Sha256_proxy} from "./01_LibSecp256k1Sha256.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract LibSecp256k1Sha256_testSuite {

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    function beforeAll() public {
    }

    function extractPubKeyAlgTest() public {
        LibSecp256k1Sha256_proxy proxy = new LibSecp256k1Sha256_proxy();
        try proxy.extractPubKeyAlgTest() {
            Assert.ok(true, "extractPubKeyAlgTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - extractPubKeyAlgTest");
        }
    }

    function extractSignRSTest() public {
        LibSecp256k1Sha256_proxy proxy = new LibSecp256k1Sha256_proxy();
        try proxy.extractSignRSTest() {
            Assert.ok(true, "extractSignRSTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - extractSignRSTest");
        }
    }

    function extractPubKeyBytesTest() public {
        LibSecp256k1Sha256_proxy proxy = new LibSecp256k1Sha256_proxy();
        try proxy.extractPubKeyBytesTest() {
            Assert.ok(true, "extractPubKeyBytesTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - extractPubKeyBytesTest");
        }
    }

    function determineRecoverIdTest() public {
        Assert.equal(
            LibSecp256k1Sha256.determineRecoverId(false, false, false),
            27,
            "Uncompressed Lower X Even Y should be 27"
        );
        Assert.equal(
            LibSecp256k1Sha256.determineRecoverId(false, false, true),
            28,
            "Uncompressed Lower X Odd Y should be 28"
        );
        Assert.equal(
            LibSecp256k1Sha256.determineRecoverId(false, true, false),
            29,
            "Uncompressed Higher X Even Y should be 29"
        );
        Assert.equal(
            LibSecp256k1Sha256.determineRecoverId(false, true, true),
            30,
            "Uncompressed Higher X Odd Y should be 30"
        );

        Assert.equal(
            LibSecp256k1Sha256.determineRecoverId(true, false, false),
            31,
            "Compressed Lower X Even Y should be 31"
        );
        Assert.equal(
            LibSecp256k1Sha256.determineRecoverId(true, false, true),
            32,
            "Compressed Lower X Odd Y should be 32"
        );
        Assert.equal(
            LibSecp256k1Sha256.determineRecoverId(true, true, false),
            33,
            "Compressed Higher X Even Y should be 33"
        );
        Assert.equal(
            LibSecp256k1Sha256.determineRecoverId(true, true, true),
            34,
            "Compressed Higher X Odd Y should be 34"
        );
    }

    function pubKeyBytesToAddrTest() public {
        LibSecp256k1Sha256_proxy proxy = new LibSecp256k1Sha256_proxy();
        try proxy.pubKeyBytesToAddrTest() {
            Assert.ok(true, "pubKeyBytesToAddrTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - pubKeyBytesToAddrTest");
        }
    }

    function verifySignMsgTest() public {
        LibSecp256k1Sha256_proxy proxy = new LibSecp256k1Sha256_proxy();
        try proxy.verifySignMsgTest() {
            Assert.ok(true, "verifySignMsgTest should not throw");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory /*lowLevelData*/) {
            Assert.ok(false, "unexpected error - verifySignMsgTest");
        }
    }

}
