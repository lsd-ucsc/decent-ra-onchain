// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

library TestCerts {

    //===== IAS Root Certificate =====

    bytes constant IAS_ROOT_CERT_DER =
        hex"3082054b308203b3a003020102020900d107765d32a3b094300d06092a864886"
        hex"f70d01010b0500307e310b3009060355040613025553310b300906035504080c"
        hex"0243413114301206035504070c0b53616e746120436c617261311a3018060355"
        hex"040a0c11496e74656c20436f72706f726174696f6e3130302e06035504030c27"
        hex"496e74656c20534758204174746573746174696f6e205265706f727420536967"
        hex"6e696e672043413020170d3136313131343135333733315a180f323034393132"
        hex"33313233353935395a307e310b3009060355040613025553310b300906035504"
        hex"080c0243413114301206035504070c0b53616e746120436c617261311a301806"
        hex"0355040a0c11496e74656c20436f72706f726174696f6e3130302e0603550403"
        hex"0c27496e74656c20534758204174746573746174696f6e205265706f72742053"
        hex"69676e696e67204341308201a2300d06092a864886f70d01010105000382018f"
        hex"003082018a02820181009f3c647eb5773cbb512d2732c0d7415ebb55a0fa9ede"
        hex"2e649199e6821db910d53177370977466a6a5e4786ccd2ddebd4149d6a2f6325"
        hex"529dd10cc98737b0779c1a07e29c47a1ae004948476c489f45a5a15d7ac8ecc6"
        hex"acc645adb43d87679df59c093bc5a2e9696c5478541b979e754b573914be55d3"
        hex"2ff4c09ddf27219934cd990527b3f92ed78fbf29246abecb71240ef39c2d7107"
        hex"b447545a7ffb10eb060a68a98580219e36910952683892d6a5e2a80803193e40"
        hex"7531404e36b315623799aa825074409754a2dfe8f5afd5fe631e1fc2af380890"
        hex"6f28a790d9dd9fe060939b125790c5805d037df56a99531b96de69de33ed226c"
        hex"c1207d1042b5c9ab7f404fc711c0fe4769fb9578b1dc0ec469ea1a25e0ff9914"
        hex"886ef2699b235bb4847dd6ff40b606e6170793c2fb98b314587f9cfd257362df"
        hex"eab10b3bd2d97673a1a4bd44c453aaf47fc1f2d3d0f384f74a06f89c089f0da6"
        hex"cdb7fceee8c9821a8e54f25c0416d18c46839a5f8012fbdd3dc74d256279adc2"
        hex"c0d55aff6f0622425d1b0203010001a381c93081c630600603551d1f04593057"
        hex"3055a053a051864f687474703a2f2f7472757374656473657276696365732e69"
        hex"6e74656c2e636f6d2f636f6e74656e742f43524c2f5347582f41747465737461"
        hex"74696f6e5265706f72745369676e696e6743412e63726c301d0603551d0e0416"
        hex"041478437b76a67ebcd0af7e4237eb357c3b8701513c301f0603551d23041830"
        hex"16801478437b76a67ebcd0af7e4237eb357c3b8701513c300e0603551d0f0101"
        hex"ff04040302010630120603551d130101ff040830060101ff020100300d06092a"
        hex"864886f70d01010b05000382018100785f2d60c5c80af42a797610213915da82"
        hex"c9b29e89e0902a25a6c75b16091c68ab204aae711889492c7e1e320911455a8f"
        hex"c13442312e77a63994d99795c8ea4576823cea8ad1e191cfa862fab8a932d3d9"
        hex"b0535a0702d0555f74e520e30330f33480e7adc9d7c81e20703142bf00c528a8"
        hex"0b463381fd602a82c7035281aae59562ccb5334ea8903e650b010681f5ce8eb6"
        hex"2eac9c414988243aec92f25bf13cdff7ebcc298ee51bba5a3538b66b26cbc45a"
        hex"51de003cad306531ad7cf5d4ef0f8805d1b9133d24135ab3c4641a2f8808349d"
        hex"7333295e0e76ee4bc5227232628efa80d79d92ab4e3d1120f3fb5ad119cd8d54"
        hex"4aa1d4a6865e6b57beac5771307e2e3cb9070da47b4bfc8869e01413ea093541"
        hex"de8a792811b74636c5e91452cf0cee59f2fb404acd0bc584cb9c835404734c0e"
        hex"7ec6605cdfcf2ff439b6d4719f702f0e0c3fa04fdb12a6cb2ad1ab1c9af1f8f4"
        hex"c3a08edd72a32b0bb5d0ad256ffd159a683b2a5a1f1d11fa62532f03d754caef"
        hex"0da5735a1e5a884c7e89d91218c9d7";

    bytes constant IAS_ROOT_CERT_TBS =
        hex"308203b3a003020102020900d107765d32a3b094300d06092a864886f70d0101"
        hex"0b0500307e310b3009060355040613025553310b300906035504080c02434131"
        hex"14301206035504070c0b53616e746120436c617261311a3018060355040a0c11"
        hex"496e74656c20436f72706f726174696f6e3130302e06035504030c27496e7465"
        hex"6c20534758204174746573746174696f6e205265706f7274205369676e696e67"
        hex"2043413020170d3136313131343135333733315a180f32303439313233313233"
        hex"353935395a307e310b3009060355040613025553310b300906035504080c0243"
        hex"413114301206035504070c0b53616e746120436c617261311a3018060355040a"
        hex"0c11496e74656c20436f72706f726174696f6e3130302e06035504030c27496e"
        hex"74656c20534758204174746573746174696f6e205265706f7274205369676e69"
        hex"6e67204341308201a2300d06092a864886f70d01010105000382018f00308201"
        hex"8a02820181009f3c647eb5773cbb512d2732c0d7415ebb55a0fa9ede2e649199"
        hex"e6821db910d53177370977466a6a5e4786ccd2ddebd4149d6a2f6325529dd10c"
        hex"c98737b0779c1a07e29c47a1ae004948476c489f45a5a15d7ac8ecc6acc645ad"
        hex"b43d87679df59c093bc5a2e9696c5478541b979e754b573914be55d32ff4c09d"
        hex"df27219934cd990527b3f92ed78fbf29246abecb71240ef39c2d7107b447545a"
        hex"7ffb10eb060a68a98580219e36910952683892d6a5e2a80803193e407531404e"
        hex"36b315623799aa825074409754a2dfe8f5afd5fe631e1fc2af3808906f28a790"
        hex"d9dd9fe060939b125790c5805d037df56a99531b96de69de33ed226cc1207d10"
        hex"42b5c9ab7f404fc711c0fe4769fb9578b1dc0ec469ea1a25e0ff9914886ef269"
        hex"9b235bb4847dd6ff40b606e6170793c2fb98b314587f9cfd257362dfeab10b3b"
        hex"d2d97673a1a4bd44c453aaf47fc1f2d3d0f384f74a06f89c089f0da6cdb7fcee"
        hex"e8c9821a8e54f25c0416d18c46839a5f8012fbdd3dc74d256279adc2c0d55aff"
        hex"6f0622425d1b0203010001a381c93081c630600603551d1f045930573055a053"
        hex"a051864f687474703a2f2f7472757374656473657276696365732e696e74656c"
        hex"2e636f6d2f636f6e74656e742f43524c2f5347582f4174746573746174696f6e"
        hex"5265706f72745369676e696e6743412e63726c301d0603551d0e041604147843"
        hex"7b76a67ebcd0af7e4237eb357c3b8701513c301f0603551d2304183016801478"
        hex"437b76a67ebcd0af7e4237eb357c3b8701513c300e0603551d0f0101ff040403"
        hex"02010630120603551d130101ff040830060101ff020100";

    uint256 constant IAS_ROOT_CERT_NOT_BEFORE = 1479137851;
    uint256 constant IAS_ROOT_CERT_NOT_AFTER  = 2524607999;

    bytes constant IAS_ROOT_CERT_KEY_DER =
        hex"308201a2300d06092a864886f70d01010105000382018f003082018a02820181"
        hex"009f3c647eb5773cbb512d2732c0d7415ebb55a0fa9ede2e649199e6821db910"
        hex"d53177370977466a6a5e4786ccd2ddebd4149d6a2f6325529dd10cc98737b077"
        hex"9c1a07e29c47a1ae004948476c489f45a5a15d7ac8ecc6acc645adb43d87679d"
        hex"f59c093bc5a2e9696c5478541b979e754b573914be55d32ff4c09ddf27219934"
        hex"cd990527b3f92ed78fbf29246abecb71240ef39c2d7107b447545a7ffb10eb06"
        hex"0a68a98580219e36910952683892d6a5e2a80803193e407531404e36b3156237"
        hex"99aa825074409754a2dfe8f5afd5fe631e1fc2af3808906f28a790d9dd9fe060"
        hex"939b125790c5805d037df56a99531b96de69de33ed226cc1207d1042b5c9ab7f"
        hex"404fc711c0fe4769fb9578b1dc0ec469ea1a25e0ff9914886ef2699b235bb484"
        hex"7dd6ff40b606e6170793c2fb98b314587f9cfd257362dfeab10b3bd2d97673a1"
        hex"a4bd44c453aaf47fc1f2d3d0f384f74a06f89c089f0da6cdb7fceee8c9821a8e"
        hex"54f25c0416d18c46839a5f8012fbdd3dc74d256279adc2c0d55aff6f0622425d"
        hex"1b0203010001";

    bytes constant IAS_ROOT_CERT_KEY_MOD =
        hex"9f3c647eb5773cbb512d2732c0d7415ebb55a0fa9ede2e649199e6821db910d5"
        hex"3177370977466a6a5e4786ccd2ddebd4149d6a2f6325529dd10cc98737b0779c"
        hex"1a07e29c47a1ae004948476c489f45a5a15d7ac8ecc6acc645adb43d87679df5"
        hex"9c093bc5a2e9696c5478541b979e754b573914be55d32ff4c09ddf27219934cd"
        hex"990527b3f92ed78fbf29246abecb71240ef39c2d7107b447545a7ffb10eb060a"
        hex"68a98580219e36910952683892d6a5e2a80803193e407531404e36b315623799"
        hex"aa825074409754a2dfe8f5afd5fe631e1fc2af3808906f28a790d9dd9fe06093"
        hex"9b125790c5805d037df56a99531b96de69de33ed226cc1207d1042b5c9ab7f40"
        hex"4fc711c0fe4769fb9578b1dc0ec469ea1a25e0ff9914886ef2699b235bb4847d"
        hex"d6ff40b606e6170793c2fb98b314587f9cfd257362dfeab10b3bd2d97673a1a4"
        hex"bd44c453aaf47fc1f2d3d0f384f74a06f89c089f0da6cdb7fceee8c9821a8e54"
        hex"f25c0416d18c46839a5f8012fbdd3dc74d256279adc2c0d55aff6f0622425d1b";

    bytes constant IAS_ROOT_CERT_KEY_EXP = hex"010001";

    bytes32 constant IAS_ROOT_CERT_HASH =
        hex"6f8fceab18f6e70fd4e0c8c9ae15713eccb153c304af33fea4b7b5eedd26cc01";

    bytes constant IAS_ROOT_CERT_SIGN =
        hex"785f2d60c5c80af42a797610213915da82c9b29e89e0902a25a6c75b16091c68"
        hex"ab204aae711889492c7e1e320911455a8fc13442312e77a63994d99795c8ea45"
        hex"76823cea8ad1e191cfa862fab8a932d3d9b0535a0702d0555f74e520e30330f3"
        hex"3480e7adc9d7c81e20703142bf00c528a80b463381fd602a82c7035281aae595"
        hex"62ccb5334ea8903e650b010681f5ce8eb62eac9c414988243aec92f25bf13cdf"
        hex"f7ebcc298ee51bba5a3538b66b26cbc45a51de003cad306531ad7cf5d4ef0f88"
        hex"05d1b9133d24135ab3c4641a2f8808349d7333295e0e76ee4bc5227232628efa"
        hex"80d79d92ab4e3d1120f3fb5ad119cd8d544aa1d4a6865e6b57beac5771307e2e"
        hex"3cb9070da47b4bfc8869e01413ea093541de8a792811b74636c5e91452cf0cee"
        hex"59f2fb404acd0bc584cb9c835404734c0e7ec6605cdfcf2ff439b6d4719f702f"
        hex"0e0c3fa04fdb12a6cb2ad1ab1c9af1f8f4c3a08edd72a32b0bb5d0ad256ffd15"
        hex"9a683b2a5a1f1d11fa62532f03d754caef0da5735a1e5a884c7e89d91218c9d7";

    string constant IAS_ROOT_CERT_NAME_CN =
        "Intel SGX Attestation Report Signing CA";
    string constant IAS_ROOT_CERT_NAME_C = "US";
    string constant IAS_ROOT_CERT_NAME_L = "Santa Clara";
    string constant IAS_ROOT_CERT_NAME_ST = "CA";
    string constant IAS_ROOT_CERT_NAME_O = "Intel Corporation";

    //===== IAS Report Certificate =====

    bytes constant IAS_REPORT_CERT_DER =
        hex"308204a130820309a003020102020900d107765d32a3b096300d06092a864886"
        hex"f70d01010b0500307e310b3009060355040613025553310b300906035504080c"
        hex"0243413114301206035504070c0b53616e746120436c617261311a3018060355"
        hex"040a0c11496e74656c20436f72706f726174696f6e3130302e06035504030c27"
        hex"496e74656c20534758204174746573746174696f6e205265706f727420536967"
        hex"6e696e67204341301e170d3136313132323039333635385a170d323631313230"
        hex"3039333635385a307b310b3009060355040613025553310b300906035504080c"
        hex"0243413114301206035504070c0b53616e746120436c617261311a3018060355"
        hex"040a0c11496e74656c20436f72706f726174696f6e312d302b06035504030c24"
        hex"496e74656c20534758204174746573746174696f6e205265706f727420536967"
        hex"6e696e6730820122300d06092a864886f70d01010105000382010f003082010a"
        hex"0282010100a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040fad"
        hex"6de093511d74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd1f"
        hex"f5b9b864296c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d4244"
        hex"286fcdd4bf64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2dbaf"
        hex"2d42bb7b244f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704cd"
        hex"99598c275e7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af21c"
        hex"c2417061fbd2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484cfc"
        hex"81941e15f55881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666cf7"
        hex"6a368978b50203010001a381a43081a1301f0603551d2304183016801478437b"
        hex"76a67ebcd0af7e4237eb357c3b8701513c300e0603551d0f0101ff0404030206"
        hex"c0300c0603551d130101ff0402300030600603551d1f045930573055a053a051"
        hex"864f687474703a2f2f7472757374656473657276696365732e696e74656c2e63"
        hex"6f6d2f636f6e74656e742f43524c2f5347582f4174746573746174696f6e5265"
        hex"706f72745369676e696e6743412e63726c300d06092a864886f70d01010b0500"
        hex"03820181006708b61b5c2bd215473e2b46af99284fbb939d3f3b152c996f1a6a"
        hex"f3b329bd220b1d3b610f6bce2e6753bded304db21912f385256216cfcba456bd"
        hex"96940be892f5690c260d1ef84f1606040222e5fe08e5326808212a447cfdd64a"
        hex"46e94bf29f6b4b9a721d25b3c4e2f62f58baed5d77c505248f0f801f9fbfb7fd"
        hex"752080095cee80938b339f6dbb4e165600e20e4a718812d49d9901e310a9b51d"
        hex"66c79909c6996599fae6d76a79ef145d9943bf1d3e35d3b42d1fb9a45cbe8ee3"
        hex"34c166eee7d32fcdc9935db8ec8bb1d8eb3779dd8ab92b6e387f0147450f1e38"
        hex"1d08581fb83df33b15e000a59be57ea94a3a52dc64bdaec959b3464c91e725bb"
        hex"daea3d99e857e380a23c9d9fb1ef58e9e42d71f12130f9261d7234d6c37e2b03"
        hex"dba40dfdfb13ac4ad8e13fd3756356b6b50015a3ec9580b815d87c2cef715cd2"
        hex"8df00bbf2a3c403ebf6691b3f05edd9143803ca085cff57e053eec2f8fea46ea"
        hex"778a68c9be885bc28225bc5f309be4a2b74d3a03945319dd3c7122fed6ff53bb"
        hex"8b8cb3a03c";

    bytes constant IAS_REPORT_CERT_TBS =
        hex"30820309a003020102020900d107765d32a3b096300d06092a864886f70d0101"
        hex"0b0500307e310b3009060355040613025553310b300906035504080c02434131"
        hex"14301206035504070c0b53616e746120436c617261311a3018060355040a0c11"
        hex"496e74656c20436f72706f726174696f6e3130302e06035504030c27496e7465"
        hex"6c20534758204174746573746174696f6e205265706f7274205369676e696e67"
        hex"204341301e170d3136313132323039333635385a170d32363131323030393336"
        hex"35385a307b310b3009060355040613025553310b300906035504080c02434131"
        hex"14301206035504070c0b53616e746120436c617261311a3018060355040a0c11"
        hex"496e74656c20436f72706f726174696f6e312d302b06035504030c24496e7465"
        hex"6c20534758204174746573746174696f6e205265706f7274205369676e696e67"
        hex"30820122300d06092a864886f70d01010105000382010f003082010a02820101"
        hex"00a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040fad6de09351"
        hex"1d74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd1ff5b9b864"
        hex"296c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d4244286fcdd4"
        hex"bf64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2dbaf2d42bb7b"
        hex"244f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704cd99598c27"
        hex"5e7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af21cc2417061"
        hex"fbd2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484cfc81941e15"
        hex"f55881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666cf76a368978"
        hex"b50203010001a381a43081a1301f0603551d2304183016801478437b76a67ebc"
        hex"d0af7e4237eb357c3b8701513c300e0603551d0f0101ff0404030206c0300c06"
        hex"03551d130101ff0402300030600603551d1f045930573055a053a051864f6874"
        hex"74703a2f2f7472757374656473657276696365732e696e74656c2e636f6d2f63"
        hex"6f6e74656e742f43524c2f5347582f4174746573746174696f6e5265706f7274"
        hex"5369676e696e6743412e63726c";

    uint256 constant IAS_REPORT_CERT_NOT_BEFORE = 1479807418;
    uint256 constant IAS_REPORT_CERT_NOT_AFTER  = 1795167418;

    bytes constant IAS_REPORT_CERT_KEY_DER =
        hex"30820122300d06092a864886f70d01010105000382010f003082010a02820101"
        hex"00a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040fad6de09351"
        hex"1d74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd1ff5b9b864"
        hex"296c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d4244286fcdd4"
        hex"bf64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2dbaf2d42bb7b"
        hex"244f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704cd99598c27"
        hex"5e7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af21cc2417061"
        hex"fbd2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484cfc81941e15"
        hex"f55881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666cf76a368978"
        hex"b50203010001";

    bytes constant IAS_REPORT_CERT_KEY_MOD =
        hex"a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040fad6de093511d"
        hex"74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd1ff5b9b86429"
        hex"6c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d4244286fcdd4bf"
        hex"64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2dbaf2d42bb7b24"
        hex"4f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704cd99598c275e"
        hex"7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af21cc2417061fb"
        hex"d2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484cfc81941e15f5"
        hex"5881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666cf76a368978b5";

    bytes constant IAS_REPORT_CERT_KEY_EXP = hex"010001";

    bytes32 constant IAS_REPORT_CERT_HASH =
        hex"13472863bcbe2462fb4312ddda9d77ca41575d79760881eb1d2d6c9be2c40094";

    bytes constant IAS_REPORT_CERT_SIGN =
        hex"6708b61b5c2bd215473e2b46af99284fbb939d3f3b152c996f1a6af3b329bd22"
        hex"0b1d3b610f6bce2e6753bded304db21912f385256216cfcba456bd96940be892"
        hex"f5690c260d1ef84f1606040222e5fe08e5326808212a447cfdd64a46e94bf29f"
        hex"6b4b9a721d25b3c4e2f62f58baed5d77c505248f0f801f9fbfb7fd752080095c"
        hex"ee80938b339f6dbb4e165600e20e4a718812d49d9901e310a9b51d66c79909c6"
        hex"996599fae6d76a79ef145d9943bf1d3e35d3b42d1fb9a45cbe8ee334c166eee7"
        hex"d32fcdc9935db8ec8bb1d8eb3779dd8ab92b6e387f0147450f1e381d08581fb8"
        hex"3df33b15e000a59be57ea94a3a52dc64bdaec959b3464c91e725bbdaea3d99e8"
        hex"57e380a23c9d9fb1ef58e9e42d71f12130f9261d7234d6c37e2b03dba40dfdfb"
        hex"13ac4ad8e13fd3756356b6b50015a3ec9580b815d87c2cef715cd28df00bbf2a"
        hex"3c403ebf6691b3f05edd9143803ca085cff57e053eec2f8fea46ea778a68c9be"
        hex"885bc28225bc5f309be4a2b74d3a03945319dd3c7122fed6ff53bb8b8cb3a03c";

    string constant IAS_REPORT_CERT_NAME_CN =
        "Intel SGX Attestation Report Signing";
    string constant IAS_REPORT_CERT_NAME_C = "US";
    string constant IAS_REPORT_CERT_NAME_L = "Santa Clara";
    string constant IAS_REPORT_CERT_NAME_ST = "CA";
    string constant IAS_REPORT_CERT_NAME_O = "Intel Corporation";

    // Decent Server Certificate

    bytes constant DECENT_SVR_CERT_DER =
        hex"30820e8530820e29a003020102022100bcb9320d098d90043c701c9a6fb51af7"
        hex"3fc0ec5dceb5b019ff4e5f1b050b5bf6300c06082a8648ce3d04030205003081"
        hex"843153305106035504030c4a3242323933413742354346464330434439303031"
        hex"4534323336343545323830444345364337333530313233453537433844453733"
        hex"3337333844393835314236375f536563703235366b3131163014060355040a0c"
        hex"0d446563656e74456e636c61766531153013060355040b0c0c446563656e7453"
        hex"6572766572301e170d3232303130313030303030305a170d3232303130313030"
        hex"303030305a3081843153305106035504030c4a32423239334137423543464643"
        hex"3043443930303145343233363435453238304443453643373335303132334535"
        hex"374338444537333337333844393835314236375f536563703235366b31311630"
        hex"14060355040a0c0d446563656e74456e636c61766531153013060355040b0c0c"
        hex"446563656e745365727665723056301006072a8648ce3d020106052b8104000a"
        hex"03420004a7354ba6e1ff9ccdc480e86b5bdbb7b626cf809da86e9f4a1b648df7"
        hex"7c3e1bebdc701843d7ccb9917431fab88ec01789582f65a06b8cbeb169efb7d2"
        hex"354831eda3820c6930820c65300f0603551d130101ff040530030101ff300e06"
        hex"03551d0f0101ff0404030201ce301106096086480186f8420101040403020007"
        hex"301a06156982f5c89a94ffdfaaab8591c1b5f7c2f782b01e0104013130210615"
        hex"6982f5c89a94ffdfaaab8591c1b5f7c2f782b01e0204085347585f4550494430"
        hex"5906156982f5c89a94ffdfaaab8591c1b5f7c2f782b01e040440436b1e0092c4"
        hex"1144116cedadcbeb3996cb2b22dc5d2429d61bac67d9ea829c96f1e85721407c"
        hex"cba565945bc6f8a5de67920ed63395ce146abc26ba03507c84b1305b06176982"
        hex"f5c89a94ffdfaaab8591c1b5f7c2f782b01e0301010440c6c66ce0f0d9388218"
        hex"667b11a5cc5cdff94a8309d29bf664f859de63cd496be2000000000000000000"
        hex"000000000000000000000000000000000000000000000030820b3606176982f5"
        hex"c89a94ffdfaaab8591c1b5f7c2f782b01e03010204820b19f90b16f904a8b904"
        hex"a5308204a130820309a003020102020900d107765d32a3b096300d06092a8648"
        hex"86f70d01010b0500307e310b3009060355040613025553310b30090603550408"
        hex"0c0243413114301206035504070c0b53616e746120436c617261311a30180603"
        hex"55040a0c11496e74656c20436f72706f726174696f6e3130302e06035504030c"
        hex"27496e74656c20534758204174746573746174696f6e205265706f7274205369"
        hex"676e696e67204341301e170d3136313132323039333635385a170d3236313132"
        hex"303039333635385a307b310b3009060355040613025553310b30090603550408"
        hex"0c0243413114301206035504070c0b53616e746120436c617261311a30180603"
        hex"55040a0c11496e74656c20436f72706f726174696f6e312d302b06035504030c"
        hex"24496e74656c20534758204174746573746174696f6e205265706f7274205369"
        hex"676e696e6730820122300d06092a864886f70d01010105000382010f00308201"
        hex"0a0282010100a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040f"
        hex"ad6de093511d74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd"
        hex"1ff5b9b864296c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d42"
        hex"44286fcdd4bf64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2db"
        hex"af2d42bb7b244f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704"
        hex"cd99598c275e7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af2"
        hex"1cc2417061fbd2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484c"
        hex"fc81941e15f55881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666c"
        hex"f76a368978b50203010001a381a43081a1301f0603551d230418301680147843"
        hex"7b76a67ebcd0af7e4237eb357c3b8701513c300e0603551d0f0101ff04040302"
        hex"06c0300c0603551d130101ff0402300030600603551d1f045930573055a053a0"
        hex"51864f687474703a2f2f7472757374656473657276696365732e696e74656c2e"
        hex"636f6d2f636f6e74656e742f43524c2f5347582f4174746573746174696f6e52"
        hex"65706f72745369676e696e6743412e63726c300d06092a864886f70d01010b05"
        hex"0003820181006708b61b5c2bd215473e2b46af99284fbb939d3f3b152c996f1a"
        hex"6af3b329bd220b1d3b610f6bce2e6753bded304db21912f385256216cfcba456"
        hex"bd96940be892f5690c260d1ef84f1606040222e5fe08e5326808212a447cfdd6"
        hex"4a46e94bf29f6b4b9a721d25b3c4e2f62f58baed5d77c505248f0f801f9fbfb7"
        hex"fd752080095cee80938b339f6dbb4e165600e20e4a718812d49d9901e310a9b5"
        hex"1d66c79909c6996599fae6d76a79ef145d9943bf1d3e35d3b42d1fb9a45cbe8e"
        hex"e334c166eee7d32fcdc9935db8ec8bb1d8eb3779dd8ab92b6e387f0147450f1e"
        hex"381d08581fb83df33b15e000a59be57ea94a3a52dc64bdaec959b3464c91e725"
        hex"bbdaea3d99e857e380a23c9d9fb1ef58e9e42d71f12130f9261d7234d6c37e2b"
        hex"03dba40dfdfb13ac4ad8e13fd3756356b6b50015a3ec9580b815d87c2cef715c"
        hex"d28df00bbf2a3c403ebf6691b3f05edd9143803ca085cff57e053eec2f8fea46"
        hex"ea778a68c9be885bc28225bc5f309be4a2b74d3a03945319dd3c7122fed6ff53"
        hex"bb8b8cb3a03cb905657b226e6f6e6365223a2244434541374246433936384631"
        hex"31394343463735354244453844423142373633222c226964223a223237323632"
        hex"3134323139363434333138363530383031373633303338303039323031343238"
        hex"222c2274696d657374616d70223a22323032332d30342d32345431383a33313a"
        hex"30352e353333313834222c2276657273696f6e223a342c226570696450736575"
        hex"646f6e796d223a22534f4e2f437a3774504148454634663747624b367244774c"
        hex"2f6f4d58756d497576466e2b7246516c5354555a41764948584f48556e574154"
        hex"794b6543624358562b30795a3563436f7373796a526a34665a6d397341466c35"
        hex"626d42464e4f4f4d4d2f536734684c523165375237692b4865646b63346a3551"
        hex"75346e3779484c342f3363692f6d61496335523256475630314b424f30487962"
        hex"416d6232504a6a5332747867424d7753534e773d222c2261647669736f727955"
        hex"524c223a2268747470733a2f2f73656375726974792d63656e7465722e696e74"
        hex"656c2e636f6d222c2261647669736f7279494473223a5b22494e54454c2d5341"
        hex"2d3030313631222c22494e54454c2d53412d3030323139222c22494e54454c2d"
        hex"53412d3030323839222c22494e54454c2d53412d3030333334222c22494e5445"
        hex"4c2d53412d3030363135225d2c22697376456e636c61766551756f7465537461"
        hex"747573223a22434f4e46494755524154494f4e5f414e445f53575f4841524445"
        hex"4e494e475f4e4545444544222c22706c6174666f726d496e666f426c6f62223a"
        hex"2231353032303036353030303030383030303031333133303230343031303130"
        hex"3730303030303030303030303030303030303030443030303030433030303030"
        hex"3030323030303030303030303030303043343246453830433844433143423236"
        hex"4535334445313339413045313041304431463139303342434142324531343030"
        hex"3544443745464138304136323231324632333241364442444539353033453531"
        hex"4533383745373631453330464342374434313942394444383845353630383739"
        hex"43444533394344344139414546303535384344222c22697376456e636c617665"
        hex"51756f7465426f6479223a22416741424145494d4141414e4141304141414141"
        hex"41466844324c6c6644616855675046753070486d536430414141414141414141"
        hex"4141414141414141414141414578502f2f774543414141414141414141414141"
        hex"4141414141414141414141414141414141414141414141414141414141414141"
        hex"4141414141414141414141414277414141414141414141484141414141414141"
        hex"414373704f6e74632f38444e6b41486b493252654b41334f62484e51456a3558"
        hex"794e357a4e7a6a5a6852746e4141414141414141414141414141414141414141"
        hex"41414141414141414141414141414141414141414141434431786e6e6665724b"
        hex"4648443275765971545864444138695a32326b434435787737683338434d664f"
        hex"6e67414141414141414141414141414141414141414141414141414141414141"
        hex"4141414141414141414141414141414141414141414141414141414141414141"
        hex"4141414141414141414141414141414141414141414141414141414141414141"
        hex"4141414141414141414141414141414141414141414141414141414141414141"
        hex"4141414141414141414141414141414141414141414141414141414141414141"
        hex"4141414141414141414141414141414141414141414141414141414141414141"
        hex"4141414141414141414141414141414141414141414142575469366b2b515a69"
        hex"57463275586647734c6c45384b38345532626c2f427a49454153416d3139576c"
        hex"7a77414141414141414141414141414141414141414141414141414141414141"
        hex"414141414141414141414141227db9010029dda58b778c77c067b6117e6690e8"
        hex"7eaf2e03398ca49b092be3203f1046d0a754c85a078f032b2ca335949421a1e1"
        hex"f8ba271ae1e2e52c613f6633767b1d92bf6ddc6ad52947b109d1e530d08d5e2b"
        hex"237c90504250a890b3fb52fcd7a2cf2864851dc671acd85ce1177ee64635606d"
        hex"31e48263af7ca6f170a8a547eaf60edc79973f18d8c317a0da8c829992bc5125"
        hex"d97ef5d549bac744d4c311c670b4852af08b05a01dc3891254ea1c326e92c5d1"
        hex"6cc23c93856f456aef0f1f92739f48430b6a26717a390e84cac53d437c09a531"
        hex"02e8d9a2d0504f9658ec35b1da9e834675006daa676194139b326daeb335b20a"
        hex"4077c94281d057769366f22c93c2671e19300c06082a8648ce3d040302050003"
        hex"4800304502204bc3cbb7afb2c51764d6df5b7082301238b41046f771890eb4bb"
        hex"c3a889d9f126022100f0474d61b6ab1ec87c27726c0dec24edfe96cbb003d5bf"
        hex"3e7799220f22b3b888";

    bytes constant DECENT_SVR_CERT_KEY_BYTES =
        hex"a7354ba6e1ff9ccdc480e86b5bdbb7b626cf809da86e9f4a1b648df77c3e1beb"
        hex"dc701843d7ccb9917431fab88ec01789582f65a06b8cbeb169efb7d2354831ed";

    address constant DECENT_SVR_CERT_KEY_ADDR =
        0xd11169Fe26A678dFb634C67aC85C05ccd796dAEd;

    bytes32 constant DECENT_SVR_CERT_SIGN_R =
        hex"4bc3cbb7afb2c51764d6df5b7082301238b41046f771890eb4bbc3a889d9f126";
    bytes32 constant DECENT_SVR_CERT_SIGN_S =
        hex"f0474d61b6ab1ec87c27726c0dec24edfe96cbb003d5bf3e7799220f22b3b888";

}
