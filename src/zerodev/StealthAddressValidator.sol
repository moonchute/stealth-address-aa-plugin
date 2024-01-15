// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "kernel/interfaces/IValidator.sol";
import "solady/utils/ECDSA.sol";
import {StealthAggreagteSignature} from "../StealthAggreagteSignature.sol";

/**
 * @dev Storage structure for Stealth Address Registry Module.
 * StealthPubkey, dhkey are used in aggregated signature.
 * EphemeralPubkey is used to recover private key of stealth address.
 */
struct StealthAddressValidatorStorage {
    uint256 stealthPubkey;
    uint256 dhkey;
    uint256 ephemeralPubkey;
    address stealthAddress;
    uint8 stealthPubkeyPrefix;
    uint8 dhkeyPrefix;
    uint8 ephemeralPrefix;
}

/**
 * @title Stealth Address Validator for ZeroDev Kernel.
 * @dev Performs verifications for stealth address signed userOps.
 * @author Justin Zen - <justin@moonchute.xyz>
 */
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
        uint256 stealthAddressPubkey = uint256(bytes32(_data[20:52]));
        uint256 stealthAddressDhkey = uint256(bytes32(_data[52:84]));
        uint8 stealthAddressPubkeyPrefix = uint8(_data[84]);
        uint8 stealthAddressDhkeyPrefix = uint8(_data[85]);
        uint256 ephemeralPubkey = uint256(bytes32(_data[86:118]));
        uint8 ephemeralPrefix = uint8(_data[118]);

        address oldStealthAddress = stealthAddressValidatorStorage[msg.sender].stealthAddress;
        stealthAddressValidatorStorage[msg.sender] = StealthAddressValidatorStorage({
            stealthPubkey: stealthAddressPubkey,
            dhkey: stealthAddressDhkey,
            ephemeralPubkey: ephemeralPubkey,
            stealthAddress: stealthAddress,
            stealthPubkeyPrefix: stealthAddressPubkeyPrefix,
            dhkeyPrefix: stealthAddressDhkeyPrefix,
            ephemeralPrefix: ephemeralPrefix
        });
        emit StealthAddressChanged(msg.sender, oldStealthAddress, stealthAddress);
    }

    /**
     * @dev Validates userOperation
     * @param _userOp User Operation to be validated.
     * @param _userOpHash Hash of the User Operation to be validated.
     * @return validationData 0 if signature is valid, SIG_VALIDATION_FAILED otherwise.
     */
    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        bytes1 mode = _userOp.signature[0];
        StealthAddressValidatorStorage storage stealthData = stealthAddressValidatorStorage[_userOp.sender];
        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);

        // 0x00: signature from spending key
        // 0x01: aggregated signature from owner and shared secret
        if (mode == 0x00) {
            address stealthAddress = stealthData.stealthAddress;
            if (stealthAddress == ECDSA.recover(hash, _userOp.signature[1:])) {
                return ValidationData.wrap(0);
            }
            if (stealthAddress != ECDSA.recover(_userOpHash, _userOp.signature[1:])) {
                return SIG_VALIDATION_FAILED;
            }
        } else if (mode == 0x01) {
            if (
                StealthAggreagteSignature.validateAggregatedSignature(
                    stealthData.stealthPubkey,
                    stealthData.dhkey,
                    stealthData.stealthPubkeyPrefix,
                    stealthData.dhkeyPrefix,
                    hash,
                    _userOp.signature[1:]
                )
            ) return ValidationData.wrap(0);
            return StealthAggreagteSignature.validateAggregatedSignature(
                stealthData.stealthPubkey,
                stealthData.dhkey,
                stealthData.stealthPubkeyPrefix,
                stealthData.dhkeyPrefix,
                _userOpHash,
                _userOp.signature[1:]
            ) ? ValidationData.wrap(0) : SIG_VALIDATION_FAILED;
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    /**
     * @dev Returns the the magic value of EIP-1271.
     * @param _hash The hash of the data signed.
     * @param _signature The signature of the data.
     * @return validationData The validation data.
     */
    function validateSignature(bytes32 _hash, bytes calldata _signature)
        external
        view
        override
        returns (ValidationData validationData)
    {
        bytes1 mode = _signature[0];
        StealthAddressValidatorStorage storage stealthData = stealthAddressValidatorStorage[msg.sender];
        bytes32 hash = ECDSA.toEthSignedMessageHash(_hash);

        // 0x00: signature from spending key
        // 0x01: aggregated signature from owner and shared secret
        if (mode == 0x00) {
            address stealthAddress = stealthData.stealthAddress;
            if (stealthAddress == ECDSA.recover(hash, _signature[1:])) {
                return ValidationData.wrap(0);
            }
            if (stealthAddress != ECDSA.recover(_hash, _signature[1:])) {
                return SIG_VALIDATION_FAILED;
            }
        } else if (mode == 0x01) {
            if (
                StealthAggreagteSignature.validateAggregatedSignature(
                    stealthData.stealthPubkey,
                    stealthData.dhkey,
                    stealthData.stealthPubkeyPrefix,
                    stealthData.dhkeyPrefix,
                    hash,
                    _signature[1:]
                )
            ) return ValidationData.wrap(0);
            return StealthAggreagteSignature.validateAggregatedSignature(
                stealthData.stealthPubkey,
                stealthData.dhkey,
                stealthData.stealthPubkeyPrefix,
                stealthData.dhkeyPrefix,
                _hash,
                _signature[1:]
            ) ? ValidationData.wrap(0) : SIG_VALIDATION_FAILED;
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        return stealthAddressValidatorStorage[_caller].stealthAddress == _caller;
    }
}
