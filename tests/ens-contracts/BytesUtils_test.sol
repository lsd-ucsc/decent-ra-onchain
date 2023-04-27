// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {BytesUtils} from "../../contracts/ens-contracts/BytesUtils.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract BytesUtils_testSuite {

    bytes constant TEST_INPUT_BYTES_128 =
        hex"11223344556677889900AABBCCDDEEFF"  // 16 bytes
        hex"21223344556677889900AABBCCDDEEFF"  // 32 bytes
        hex"31223344556677889900AABBCCDDEEFF"  // 48 bytes
        hex"41223344556677889900AABBCCDDEEFF"  // 64 bytes
        hex"51223344556677889900AABBCCDDEEFF"  // 80 bytes
        hex"61223344556677889900AABBCCDDEEFF"  // 96 bytes
        hex"71223344556677889900AABBCCDDEEFF"  // 112 bytes
        hex"81223344556677889900AABBCCDDEEFF"; // 128 bytes

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    function beforeAll() public {
    }

    function testSubstringSafe() public {
        bytes memory b = TEST_INPUT_BYTES_128;

        // length aligned to 32 bytes
        {
            bytes memory expected =
                hex"31223344556677889900AABBCCDDEEFF"  // 16 bytes
                hex"41223344556677889900AABBCCDDEEFF"; // 32 bytes

            try BytesUtils.substringSafe(b, 32, 32)
                returns (bytes memory actual)
            {
                Assert.equal(
                    keccak256(actual),
                    keccak256(expected),
                    "substringSafe mismatch"
                );
            } catch Error(string memory reason) {
                Assert.ok(false, reason);
            } catch (bytes memory lowLevelData) {
                Assert.ok(false, "unexpected error - aligned substringSafe");
            }
        }

        // length not aligned to 32 bytes
        {

            bytes memory expected =
                hex"31223344556677889900AABBCCDDEEFF"  // 16 bytes
                hex"41223344556677889900AABBCCDDEEFF"  // 32 bytes
                hex"51223344556677889900AABBCCDDEEFF"; // 48 bytes

            try BytesUtils.substringSafe(b, 32, 48)
                returns (bytes memory actual)
            {
                Assert.equal(
                    keccak256(actual),
                    keccak256(expected),
                    "substringSafe mismatch"
                );
            } catch Error(string memory reason) {
                Assert.ok(false, reason);
            } catch (bytes memory lowLevelData) {
                Assert.ok(false, "unexpected error - unaligned substringSafe");
            }
        }
    }

    function testSubstringFast() public {
        bytes memory b = TEST_INPUT_BYTES_128;

        // length aligned to 32 bytes
        {
            bytes memory expected =
                hex"31223344556677889900AABBCCDDEEFF"  // 16 bytes
                hex"41223344556677889900AABBCCDDEEFF"; // 32 bytes

            try BytesUtils.substringFast(b, 32, 32)
                returns (bytes memory actual)
            {
                Assert.equal(
                    keccak256(actual),
                    keccak256(expected),
                    "substringFast mismatch"
                );
            } catch Error(string memory reason) {
                Assert.ok(false, reason);
            } catch (bytes memory lowLevelData) {
                Assert.ok(false, "unexpected error - aligned substringFast");
            }
        }

        // length not aligned to 32 bytes
        {
            bytes memory expected =
                hex"31223344556677889900AABBCCDDEEFF"  // 16 bytes
                hex"41223344556677889900AABBCCDDEEFF"  // 32 bytes
                hex"51223344556677889900AABBCCDDEEFF"; // 48 bytes

            try BytesUtils.substringFast(b, 32, 48)
                returns (bytes memory actual)
            {
                Assert.equal(
                    keccak256(actual),
                    keccak256(expected),
                    "substringFast mismatch"
                );
            } catch Error(string memory reason) {
                Assert.ok(false, reason);
            } catch (bytes memory lowLevelData) {
                Assert.ok(false, "unexpected error - unaligned substringFast");
            }
        }
    }

    function testSubstringUnsafe() public {

        bytes memory b = TEST_INPUT_BYTES_128;

        // length aligned to 32 bytes
        {
            bytes memory expected =
                hex"31223344556677889900AABBCCDDEEFF"  // 16 bytes
                hex"41223344556677889900AABBCCDDEEFF"; // 32 bytes

            try BytesUtils.substringUnsafe(b, 32, 32)
                returns (bytes memory actual)
            {
                Assert.equal(
                    keccak256(actual),
                    keccak256(expected),
                    "substringUnsafe mismatch"
                );
            } catch Error(string memory reason) {
                Assert.ok(false, reason);
            } catch (bytes memory lowLevelData) {
                Assert.ok(false, "unexpected error - aligned substringUnsafe");
            }
        }

        // length not aligned to 32 bytes
        {

            bytes memory expected =
                hex"31223344556677889900AABBCCDDEEFF"  // 16 bytes
                hex"41223344556677889900AABBCCDDEEFF"  // 32 bytes
                hex"51223344556677889900AABBCCDDEEFF"; // 48 bytes

            try BytesUtils.substringUnsafe(b, 32, 48)
                returns (bytes memory actual)
            {
                Assert.equal(
                    keccak256(actual),
                    keccak256(expected),
                    "substringUnsafe mismatch"
                );
            } catch Error(string memory reason) {
                Assert.ok(false, reason);
            } catch (bytes memory lowLevelData) {
                Assert.ok(false, "unexpected error - unaligned substringUnsafe");
            }
        }
    }

}
