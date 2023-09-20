// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import {EllipticCurve} from "src/EllipticCurve.sol";

abstract contract StealthAddressUtil is Test {
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    function getStealthAddress(VmSafe.Wallet memory ownerWallet)
        public
        returns (
            uint256 stealthPub,
            uint256 dhPub,
            uint256 stealthPrefix,
            uint256 dhPrefix,
            address stealthAddress,
            uint256 stealthPri
        )
    {
        VmSafe.Wallet memory ephemeralWallet = vm.createWallet(uint256(keccak256(bytes("ephemeral"))));

        (uint256 sharedSecretX, uint256 sharedSecretY) =
            EllipticCurve.ecMul(ephemeralWallet.privateKey, ownerWallet.publicKeyX, ownerWallet.publicKeyY, AA, PP);
        uint256 hashSecret = uint256(keccak256(abi.encode(sharedSecretX, sharedSecretY)));
        (uint256 pubX, uint256 pubY) = EllipticCurve.ecMul(hashSecret, GX, GY, AA, PP);
        (uint256 stealthPubX, uint256 stealthPubY) =
            EllipticCurve.ecAdd(ownerWallet.publicKeyX, ownerWallet.publicKeyY, pubX, pubY, AA, PP);
        stealthAddress = address(uint160(uint256(keccak256(abi.encode(stealthPubX, stealthPubY)))));

        (uint256 dhkx, uint256 dhky) =
            EllipticCurve.ecMul(hashSecret, ownerWallet.publicKeyX, ownerWallet.publicKeyY, AA, PP);
        return (stealthPubX, dhkx, stealthPubY % 2 + 2, dhky % 2 + 2, stealthAddress, hashSecret);
    }
}
