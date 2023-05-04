// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;


import {IASRootCert} from "./IASRootCert.sol";


contract IASRootCertMgr {

    using IASRootCert for IASRootCert.IASRootCertObj;

    //===== Member variables =====
    IASRootCert.IASRootCertObj private m_rootCert;

    //===== Constructor =====

    constructor(bytes memory certDer) {
        m_rootCert = IASRootCert.loadCert(certDer);
    }

    //===== Functions =====

    function getNotAfter() external view returns (uint256) {
        return m_rootCert.notAfter;
    }

}
