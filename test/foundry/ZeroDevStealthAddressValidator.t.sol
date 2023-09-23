// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "kernel/factory/KernelFactory.sol";
import {StealthAddressValidator} from "src/zerodev/StealthAddressValidator.sol";
import {KernelTestBase} from "kernel-test/utils/ERC4337Utils.sol";
import "forge-std/console2.sol";
import "forge-std/Vm.sol";
import {StealthAddressUtil} from "./utils/StealthAddressUtil.sol";

contract ZeroDevStealthAddressValidatorTest is KernelTestBase, StealthAddressUtil {
    uint256 stealthPub = 0xfa59d070a31544e15b6aa78871a8ab992c156f7872afda11ef167d3a62aae579;
    uint256 dhPub = 0xf8bbfd03091689755e3ded692647c7e37dd286022656897203b15952b9e6413c;
    uint8 stealthPrefix = 0x02;
    uint8 dhPrefix = 0x03;
    address stealthAddress = 0x31F945ac4E24cD1e34443777Fd62Bc70558C694D;

    function setUp() public {
        _initialize();
        defaultValidator = IKernelValidator(address(new StealthAddressValidator()));
        kernel = Kernel(
            payable(
                address(
                    factory.createAccount(
                        address(kernelImpl),
                        abi.encodeWithSelector(
                            KernelStorage.initialize.selector,
                            defaultValidator,
                            abi.encodePacked(stealthAddress, stealthPub, dhPub, stealthPrefix, dhPrefix)
                        ),
                        0
                    )
                )
            )
        );
    }

    function test_enable_validator() external {
        VmSafe.Wallet memory wallet = vm.createWallet(uint256(keccak256(bytes("1"))));
        (uint256 wStealthPub, uint256 wDhPub, uint256 wStealthPrefix, uint256 wDhPrefix, address wStealthAddress,) =
            getStealthAddress(wallet);

        address mockedKernel = address(uint160(uint256(keccak256(bytes("mockedKernel")))));

        vm.prank(mockedKernel);
        defaultValidator.enable(
            abi.encodePacked(wStealthAddress, wStealthPub, wDhPub, uint8(wStealthPrefix), uint8(wDhPrefix))
        );
        (
            uint256 expectedStealthPb,
            uint256 expectedDhk,
            address expectedStealthAddress,
            uint8 expectedStealthPbPrefix,
            uint8 expectedDhPrefix
        ) = StealthAddressValidator(address(defaultValidator)).stealthAddressValidatorStorage(address(mockedKernel));
        assertEq(expectedStealthPb, wStealthPub);
        assertEq(expectedDhk, wDhPub);
        assertEq(expectedStealthAddress, wStealthAddress);
        assertEq(expectedStealthPbPrefix, wStealthPrefix);
        assertEq(expectedDhPrefix, wDhPrefix);
    }

    function test_create_kernel() external {
        VmSafe.Wallet memory wallet = vm.createWallet(uint256(keccak256(bytes("1"))));
        (uint256 wStealthPub, uint256 wDhPub, uint256 wStealthPrefix, uint256 wDhPrefix, address wStealthAddress,) =
            getStealthAddress(wallet);

        address createdKernel = address(
            factory.createAccount(
                address(kernelImpl),
                abi.encodeWithSelector(
                    KernelStorage.initialize.selector,
                    defaultValidator,
                    abi.encodePacked(wStealthAddress, wStealthPub, wDhPub, uint8(wStealthPrefix), uint8(wDhPrefix))
                ),
                0
            )
        );
        (
            uint256 expectedStealthPb,
            uint256 expectedDhk,
            address expectedStealthAddress,
            uint8 expectedStealthPbPrefix,
            uint8 expectedDhPrefix
        ) = StealthAddressValidator(address(defaultValidator)).stealthAddressValidatorStorage(createdKernel);
        assertEq(expectedStealthPb, wStealthPub);
        assertEq(expectedDhk, wDhPub);
        assertEq(expectedStealthAddress, wStealthAddress);
        assertEq(expectedStealthPbPrefix, wStealthPrefix);
        assertEq(expectedDhPrefix, wDhPrefix);
    }

    function test_stealth_validate_userop() external {
        bytes32 message = bytes32(uint256(0x102030405060708090a));
        uint8 v = 27;
        bytes32 r = bytes32(0xa0407c76bd3ea4167ef3ec0006cb27e6ee453e306d7413b675289b645e4ba62b);
        bytes32 s = bytes32(0x858ac7986fdc7a1d5bb2720d700437967f5146868a5162bd2cc7e95f7ad2067d);
        bytes memory sig = abi.encodePacked(uint8(0x00), r, s, v);

        vm.prank(address(kernel));
        UserOperation memory userOp = UserOperation({
            sender: address(kernel),
            nonce: 0,
            initCode: bytes(""),
            callData: bytes(""),
            callGasLimit: 1,
            verificationGasLimit: 1,
            preVerificationGas: 1,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: bytes(""),
            signature: sig
        });
        (ValidAfter validAfter, ValidUntil validUntil, address result) =
            parseValidationData(defaultValidator.validateUserOp(userOp, message, 0));
        assertEq(result, address(0));
    }

    function test_stealth_validate_userop_aggsig() external {
        bytes32 message = bytes32(uint256(0x102030405060708090a));
        bytes32 r = bytes32(0xe1e8bd51f720ede3e522d54d9837f2c39e0f38c742b19c19a519ce9e349f1faa);
        bytes32 s = bytes32(0x2327f9b2a155d03842ff832a4c846f749ed0815b0ff1b89f7bd7a06e6d431ced);
        bytes memory sig = abi.encodePacked(uint8(0x01), r, s);

        vm.prank(address(kernel));
        UserOperation memory userOp = UserOperation({
            sender: address(kernel),
            nonce: 0,
            initCode: bytes(""),
            callData: bytes(""),
            callGasLimit: 1,
            verificationGasLimit: 1,
            preVerificationGas: 1,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: bytes(""),
            signature: sig
        });
        (ValidAfter validAfter, ValidUntil validUntil, address result) =
            parseValidationData(defaultValidator.validateUserOp(userOp, message, 0));
        assertEq(result, address(0));
    }

    function test_stealth_validate_sig() external {
        bytes32 message = bytes32(uint256(0x102030405060708090a));
        uint8 v = 27;
        bytes32 r = bytes32(0xa0407c76bd3ea4167ef3ec0006cb27e6ee453e306d7413b675289b645e4ba62b);
        bytes32 s = bytes32(0x858ac7986fdc7a1d5bb2720d700437967f5146868a5162bd2cc7e95f7ad2067d);
        bytes memory sig = abi.encodePacked(uint8(0x00), r, s, v);

        vm.prank(address(kernel));
        (ValidAfter validAfter, ValidUntil validUntil, address result) =
            parseValidationData(defaultValidator.validateSignature(message, sig));
        assertEq(result, address(0));
    }

    function test_stealth_validate_sig_aggsig() external {
        bytes32 message = bytes32(uint256(0x102030405060708090a));
        bytes32 r = bytes32(0xe1e8bd51f720ede3e522d54d9837f2c39e0f38c742b19c19a519ce9e349f1faa);
        bytes32 s = bytes32(0x2327f9b2a155d03842ff832a4c846f749ed0815b0ff1b89f7bd7a06e6d431ced);
        bytes memory aggSig = abi.encodePacked(uint8(0x01), r, s);

        vm.prank(address(kernel));
        (ValidAfter validAfter, ValidUntil validUntil, address result) =
            parseValidationData(defaultValidator.validateSignature(message, aggSig));
        assertEq(result, address(0));
    }

    function test_fail_wrong_sig() external {
        bytes32 message = bytes32(uint256(0x102030405060708090));
        uint8 v = 27;
        bytes32 r = bytes32(0xa0407c76bd3ea4167ef3ec0006cb27e6ee453e306d7413b675289b645e4ba62b);
        bytes32 s = bytes32(0x858ac7986fdc7a1d5bb2720d700437967f5146868a5162bd2cc7e95f7ad2067d);
        bytes memory sig = abi.encodePacked(uint8(0x00), r, s, v);

        vm.prank(address(kernel));
        (ValidAfter validAfter, ValidUntil validUntil, address result) =
            parseValidationData(defaultValidator.validateSignature(message, sig));
        assertEq(result, address(1));
    }

    function test_fail_wrong_aggsig() external {
        bytes32 message = bytes32(uint256(0x102030405060708090));
        bytes32 r = bytes32(0xe1e8bd51f720ede3e522d54d9837f2c39e0f38c742b19c19a519ce9e349f1faa);
        bytes32 s = bytes32(0x2327f9b2a155d03842ff832a4c846f749ed0815b0ff1b89f7bd7a06e6d431ced);
        bytes memory aggSig = abi.encodePacked(uint8(0x01), r, s);

        vm.prank(address(kernel));
        (ValidAfter validAfter, ValidUntil validUntil, address result) =
            parseValidationData(defaultValidator.validateSignature(message, aggSig));
        assertEq(result, address(1));
    }
}
