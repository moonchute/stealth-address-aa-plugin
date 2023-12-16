// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {StealthAggreagteSignature} from "src/StealthAggreagteSignature.sol";

contract AggregateSignatureTest is Test {
    function test_agg_sig() external {
        uint256 stealthPub = 0x1a09c453b60710538bf2533bc802a30ec603bdf1b50d6e4f951d21377a33d980;
        uint256 dhPub = 0xfe09ef5fcbdfbb9140d3251c737a259680161930d7ccd710d07dbde821016012;
        uint8 stealthPrefix = 0x02;
        uint8 dhPrefix = 0x03;

        bytes32 message = bytes32(uint256(0x102030405060708090a));
        bytes32 r = 0xe0e561015cf21e87005c4806d924d8834b54d592826297cb4d0daea7111af4d8;
        bytes32 s = 0x533fa93c2409ccd8cfaf2867967092d039ee0bfaab1d30e4cdb51d6a3d6214b6;
        bytes memory sig = abi.encodePacked(r, s);

        bool verified = StealthAggreagteSignature.validateAggregatedSignature(stealthPub, dhPub, stealthPrefix, dhPrefix, message, sig);
        assertTrue(verified);
    }
}
