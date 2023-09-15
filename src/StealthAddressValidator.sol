// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "kernel/interfaces/IValidator.sol";

struct StealthAddressValidatorStorage {
    uint256 aggPubkey;
    uint256 dhkey;
    address stealthAddress;
    uint8 aggPubkeyPrefix;
    uint8 dhkeyPrefix;
}

contract StealthAddressValidator is IKernelValidator {
    event StealthAddressChanged(
        address indexed kernel, address indexed oldStealthAddress, address indexed newStealthAddress
    );

    mapping(address => StealthAddressValidatorStorage) public stealthAddressValidatorStorage;

    function disable(bytes calldata) external payable override {
        address stealthAddress;
        delete stealthAddressValidatorStorage[msg.sender];
        emit StealthAddressChanged(msg.sender, stealthAddress, address(0));
    }

    function enable(bytes calldata _data) external payable override {
        address stealthAddress = address(bytes20(_data[0:20]));
        uint256 stealthAddressAggPubkey = uint256(bytes32(_data[20:52]));
        uint256 stealthAddressDhkey = uint256(bytes32(_data[52:84]));
        uint8 stealthAddressAggPubkeyPrefix = uint8(_data[84]);
        uint8 stealthAddressDhkeyPrefix = uint8(_data[85]);

        address oldStealthAddress = stealthAddressValidatorStorage[msg.sender].stealthAddress;
        stealthAddressValidatorStorage[msg.sender] = StealthAddressValidatorStorage({
            aggPubkey: stealthAddressAggPubkey,
            dhkey: stealthAddressDhkey,
            stealthAddress: stealthAddress,
            aggPubkeyPrefix: stealthAddressAggPubkeyPrefix,
            dhkeyPrefix: stealthAddressDhkeyPrefix
        });
        emit StealthAddressChanged(msg.sender, oldStealthAddress, stealthAddress);
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingFunds)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        bytes1 memory mode = userOp.signature[0];
        // 0x00: signature from spending key
        // 0x01: aggregated signature from owner and shared secret
        if (mode == 0x00) {
            address stealthAddress = stealthAddressValidatorStorage[_userOp.sender].stealthAddress;
            bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
            if (owner == ECDSA.recover(hash, _userOp.signature)) {
                return ValidationData.wrap(0);
            }
            if (owner != ECDSA.recover(_userOpHash, _userOp.signature)) {
                return SIG_VALIDATION_FAILED;
            }
        } else if (mode == 0x01) {} else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function validateSignature(bytes32 _hash, bytes calldata _signature)
        external
        view
        override
        returns (ValidationData validationData)
    {
        bytes1 memory mode = _signature[0];
        // 0x00: signature from spending key
        // 0x01: aggregated signature from owner and shared secret
        if (mode == 0x00) {
            address stealthAddress = stealthAddressValidatorStorage[msg.sender].stealthAddress;
            bytes32 hash = ECDSA.toEthSignedMessageHash(_hash);
            if (owner == ECDSA.recover(hash, _signature)) {
                return ValidationData.wrap(0);
            }
            if (owner != ECDSA.recover(_hash, _signature)) {
                return SIG_VALIDATION_FAILED;
            }
        } else if (mode == 0x01) {} else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        return stealthAddressValidatorStorage[caller].stealthAddress == _caller;
    }
}
