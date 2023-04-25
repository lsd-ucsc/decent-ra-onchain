// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

import "remix_tests.sol"; // this import is automatically injected by Remix.

import "../contracts/RLPReader.sol";

contract RLPTest {
    using RLPReader for RLPReader.RLPItem;

    function beforeAll () public {
    }

    function rlpTest() external {
        uint i = 1337;
		bytes memory rlpBytes = abi.encodePacked(i);
		RLPReader.RLPItem memory item = RLPReader.toRlpItem(rlpBytes);
        uint val = RLPReader.toUint(item);

		Assert.equal(val, uint(1337), "rlp value not equal");
	}
}