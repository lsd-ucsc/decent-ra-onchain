// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;


library LibParamPassing {
    struct Struct1 {
        uint256 a;
        uint256 b;
    }

    function pubMemFunc(Struct1 memory s) public pure returns (uint256) {
        s.a = 1;
        s.b = 2;
        return 3;
    }

    function externMemFunc(Struct1 memory s) external pure returns (uint256) {
        s.a = 1;
        s.b = 2;
        return 3;
    }

    function internMemFunc(Struct1 memory s) internal pure returns (uint256) {
        s.a = 1;
        s.b = 2;
        return 3;
    }

    function privMemFunc(Struct1 memory s) private pure returns (uint256) {
        s.a = 1;
        s.b = 2;
        return 3;
    }

    function internMemFunc(bytes memory b) internal pure returns (uint256) {
        b;
        return 3;
    }

    function externMemFunc(bytes memory b) external pure returns (uint256) {
        b;
        return 3;
    }

    function externCallFunc(bytes calldata b) external pure returns (uint256) {
        b;
        return 3;
    }
}


contract ContraParamPassing {
    struct Struct1 {
        uint256 a;
        uint256 b;
    }

    constructor() {}

    function pubMemFunc(Struct1 memory s) public pure returns (uint256) {
        s.a = 1;
        s.b = 2;
        return 3;
    }

    function externMemFunc(Struct1 memory s) external pure returns (uint256) {
        s.a = 1;
        s.b = 2;
        return 3;
    }

    function internMemFunc(Struct1 memory s) internal pure returns (uint256) {
        s.a = 1;
        s.b = 2;
        return 3;
    }

    function privMemFunc(Struct1 memory s) private pure returns (uint256) {
        s.a = 1;
        s.b = 2;
        return 3;
    }

    // calldata is immutable
    // function externCallFunc(Struct1 calldata s) external pure returns (uint256) {
    //     s.a = 1;
    //     s.b = 2;
    //     return 3;
    // }
}
