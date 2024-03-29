// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {StealthAddressUtil} from "./utils/StealthAddressUtil.sol";
import {StealthAddressRegistryModule, StealthStorage} from "src/biconomy/StealthAddressRegistryModule.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";

import "forge-std/Test.sol";
import "forge-std/Vm.sol";

contract BiconomyStealthAddressRegistryModuleTest is Test, StealthAddressUtil {
    StealthAddressRegistryModule stealthModule;
    address smartAccount;

    uint256 stealthPub = 0xfa59d070a31544e15b6aa78871a8ab992c156f7872afda11ef167d3a62aae579;
    uint256 dhPub = 0xf8bbfd03091689755e3ded692647c7e37dd286022656897203b15952b9e6413c;
    uint256 ephemeralPub = 0xfa59d070a31544e15b6aa78871a8ab992c156f7872afda11ef167d3a62aae579;

    uint8 stealthPrefix = 0x02;
    uint8 dhPrefix = 0x03;
    uint8 ephemeralPPrefix = 0x03;

    address stealthAddress = 0x31F945ac4E24cD1e34443777Fd62Bc70558C694D;

    function setUp() public {
        stealthModule = new StealthAddressRegistryModule();
        smartAccount = address(uint160(uint256(keccak256(bytes("smartAccount")))));
        vm.prank(smartAccount);
        stealthModule.initForSmartAccount(
            stealthAddress, stealthPub, dhPub, ephemeralPub, stealthPrefix, dhPrefix, ephemeralPPrefix
        );
    }

    function test_init_module() external {
        VmSafe.Wallet memory wallet = vm.createWallet(uint256(keccak256(bytes("1"))));
        (
            uint256 wStealthPub,
            uint256 wDhPub,
            uint256 wStealthPrefix,
            uint256 wDhPrefix,
            address wStealthAddress,
            uint256 wEphemeralPub,
            uint256 wEphemeralPrefix,
        ) = getStealthAddress(wallet);
        address mockedSmartAccount = address(uint160(uint256(keccak256(bytes("mockedSmartAccount")))));
        vm.prank(mockedSmartAccount);
        stealthModule.initForSmartAccount(
            wStealthAddress,
            wStealthPub,
            wDhPub,
            wEphemeralPub,
            uint8(wStealthPrefix),
            uint8(wDhPrefix),
            uint8(wEphemeralPrefix)
        );
        StealthStorage memory ss = stealthModule.getStealthAddress(mockedSmartAccount);

        uint256 expectedStealthb = ss.stealthPubkey;
        uint256 expectedDhk = ss.dhkey;
        address expectedStealthAddress = ss.stealthAddress;
        uint8 expectedStealthPrefix = ss.stealthPubkeyPrefix;
        uint8 expectedDhPrefix = ss.dhkeyPrefix;
        assertEq(expectedStealthb, wStealthPub);
        assertEq(expectedDhk, wDhPub);
        assertEq(expectedStealthAddress, wStealthAddress);
        assertEq(expectedStealthPrefix, wStealthPrefix);
        assertEq(expectedDhPrefix, wDhPrefix);
    }

    function test_stealth_validate_userop() external {
        bytes32 message = bytes32(uint256(0x102030405060708090a));
        uint8 v = 27;
        bytes32 r = bytes32(0xa0407c76bd3ea4167ef3ec0006cb27e6ee453e306d7413b675289b645e4ba62b);
        bytes32 s = bytes32(0x858ac7986fdc7a1d5bb2720d700437967f5146868a5162bd2cc7e95f7ad2067d);
        bytes memory sig = abi.encodePacked(bytes1(0x00), r, s, v);
        bytes memory sigAddress = abi.encode(sig, stealthModule);

        UserOperation memory userOp = UserOperation({
            sender: smartAccount,
            nonce: 0,
            initCode: bytes(""),
            callData: bytes(""),
            callGasLimit: 1,
            verificationGasLimit: 1,
            preVerificationGas: 1,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: bytes(""),
            signature: sigAddress
        });
        vm.prank(smartAccount);
        uint256 validationData = stealthModule.validateUserOp(userOp, message);
        assertEq(validationData, uint256(0));
    }

    function test_stealth_validate_userop_aggsig() external {
        bytes32 message = bytes32(uint256(0x102030405060708090a));
        bytes32 r = bytes32(0xe1e8bd51f720ede3e522d54d9837f2c39e0f38c742b19c19a519ce9e349f1faa);
        bytes32 s = bytes32(0x2327f9b2a155d03842ff832a4c846f749ed0815b0ff1b89f7bd7a06e6d431ced);
        bytes memory sig = abi.encodePacked(uint8(0x01), r, s);
        bytes memory sigAddress = abi.encode(sig, stealthModule);

        UserOperation memory userOp = UserOperation({
            sender: smartAccount,
            nonce: 0,
            initCode: bytes(""),
            callData: bytes(""),
            callGasLimit: 1,
            verificationGasLimit: 1,
            preVerificationGas: 1,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: bytes(""),
            signature: sigAddress
        });
        vm.prank(smartAccount);
        uint256 validationData = (stealthModule.validateUserOp(userOp, message));
        assertEq(validationData, uint256(0));
    }

    function test_stealth_validate_sig() external {
        bytes32 message = bytes32(uint256(0x102030405060708090a));
        uint8 v = 27;
        bytes32 r = bytes32(0xa0407c76bd3ea4167ef3ec0006cb27e6ee453e306d7413b675289b645e4ba62b);
        bytes32 s = bytes32(0x858ac7986fdc7a1d5bb2720d700437967f5146868a5162bd2cc7e95f7ad2067d);
        bytes memory sig = abi.encodePacked(uint8(0x00), r, s, v);

        vm.prank(address(smartAccount));
        bytes4 validationData = stealthModule.isValidSignature(message, sig);
        assertEq(validationData, bytes4(0x1626ba7e));
    }

    function test_stealth_validate_sig_aggsig() external {
        bytes32 message = bytes32(uint256(0x102030405060708090a));
        bytes32 r = bytes32(0xe1e8bd51f720ede3e522d54d9837f2c39e0f38c742b19c19a519ce9e349f1faa);
        bytes32 s = bytes32(0x2327f9b2a155d03842ff832a4c846f749ed0815b0ff1b89f7bd7a06e6d431ced);
        bytes memory aggSig = abi.encodePacked(uint8(0x01), r, s);

        vm.prank(smartAccount);
        bytes4 validationData = stealthModule.isValidSignature(message, aggSig);
        assertEq(validationData, bytes4(0x1626ba7e));
    }

    function test_fail_wrong_sig() external {
        bytes32 message = bytes32(uint256(0x102030405060708090));
        uint8 v = 27;
        bytes32 r = bytes32(0xa0407c76bd3ea4167ef3ec0006cb27e6ee453e306d7413b675289b645e4ba62b);
        bytes32 s = bytes32(0x858ac7986fdc7a1d5bb2720d700437967f5146868a5162bd2cc7e95f7ad2067d);
        bytes memory sig = abi.encodePacked(uint8(0x00), r, s, v);

        vm.prank(address(smartAccount));
        bytes4 validationData = stealthModule.isValidSignature(message, sig);
        assertEq(validationData, bytes4(0xffffffff));
    }

    function test_fail_wrong_aggsig() external {
        bytes32 message = bytes32(uint256(0x102030405060708090));
        bytes32 r = bytes32(0xe1e8bd51f720ede3e522d54d9837f2c39e0f38c742b19c19a519ce9e349f1faa);
        bytes32 s = bytes32(0x2327f9b2a155d03842ff832a4c846f749ed0815b0ff1b89f7bd7a06e6d431ced);
        bytes memory aggSig = abi.encodePacked(uint8(0x01), r, s);

        vm.prank(smartAccount);
        bytes4 validationData = stealthModule.isValidSignature(message, aggSig);
        assertEq(validationData, bytes4(0xffffffff));
    }

    function test_fail_wrong_userop_sig() external {
        bytes32 message = bytes32(uint256(0x102030405060708090));
        uint8 v = 27;
        bytes32 r = bytes32(0xa0407c76bd3ea4167ef3ec0006cb27e6ee453e306d7413b675289b645e4ba62b);
        bytes32 s = bytes32(0x858ac7986fdc7a1d5bb2720d700437967f5146868a5162bd2cc7e95f7ad2067d);
        bytes memory sig = abi.encodePacked(bytes1(0x00), r, s, v);
        bytes memory sigAddress = abi.encode(sig, stealthModule);

        UserOperation memory userOp = UserOperation({
            sender: smartAccount,
            nonce: 0,
            initCode: bytes(""),
            callData: bytes(""),
            callGasLimit: 1,
            verificationGasLimit: 1,
            preVerificationGas: 1,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: bytes(""),
            signature: sigAddress
        });
        vm.prank(smartAccount);
        uint256 validationData = stealthModule.validateUserOp(userOp, message);
        assertEq(validationData, uint256(1));
    }

    function test_fail_wrong_userop_aggsig() external {
        bytes32 message = bytes32(uint256(0x1020304050607080901));
        bytes32 r = bytes32(0xe1e8bd51f720ede3e522d54d9837f2c39e0f38c742b19c19a519ce9e349f1faa);
        bytes32 s = bytes32(0x2327f9b2a155d03842ff832a4c846f749ed0815b0ff1b89f7bd7a06e6d431ced);
        bytes memory sig = abi.encodePacked(uint8(0x01), r, s);
        bytes memory sigAddress = abi.encode(sig, stealthModule);

        UserOperation memory userOp = UserOperation({
            sender: smartAccount,
            nonce: 0,
            initCode: bytes(""),
            callData: bytes(""),
            callGasLimit: 1,
            verificationGasLimit: 1,
            preVerificationGas: 1,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: bytes(""),
            signature: sigAddress
        });
        vm.prank(smartAccount);
        uint256 validationData = (stealthModule.validateUserOp(userOp, message));
        assertEq(validationData, uint256(1));
    }
}
