// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {RLPReader} from "../../libs/Solidity-RLP/contracts/RLPReader.sol";


contract RLPTest {
    using RLPReader for RLPReader.RLPItem;


    function beforeAll () public {
    }

    function rlpTest1() external {
        uint i = 1337;
        bytes memory rlpBytes = abi.encodePacked(i);
        RLPReader.RLPItem memory item = RLPReader.toRlpItem(rlpBytes);
        uint val = RLPReader.toUint(item);

        Assert.equal(val, uint(1337), "rlp value not equal");
    }
}
