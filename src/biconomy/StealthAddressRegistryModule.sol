// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {BaseAuthorizationModule} from "biconomy/modules/BaseAuthorizationModule.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import {StealthAggreagteSignature} from "../StealthAggreagteSignature.sol";

struct StealthStorage {
    uint256 stealthPubkey;
    uint256 dhkey;
    address stealthAddress;
    uint8 stealthPubkeyPrefix;
    uint8 dhkeyPrefix;
}

contract StealthAddressRegistryModule is BaseAuthorizationModule {
    using ECDSA for bytes32;

    string public constant NAME = "Stealth Address Registry Module";
    string public constant VERSION = "0.1.0";
    mapping(address => StealthStorage) internal _smartAccountStealth;

    error AlreadyInitedForSmartAccount(address smartAccount);
    error ZeroAddressNotAllowedAsStealthAddress();

    function initForSmartAccount(
        address stealthAddress,
        uint256 stealthPubkey,
        uint256 dhkey,
        uint8 stealthPubkeyPrefix,
        uint8 dhkeyPrefix
    ) external returns (address) {
        if (_smartAccountStealth[msg.sender].stealthAddress != address(0)) {
            revert AlreadyInitedForSmartAccount(msg.sender);
        }
        if (stealthAddress == address(0)) revert ZeroAddressNotAllowedAsStealthAddress();
        _smartAccountStealth[msg.sender] =
            StealthStorage(stealthPubkey, dhkey, stealthAddress, stealthPubkeyPrefix, dhkeyPrefix);
        return address(this);
    }

    function getStealthAddress(address smartAccount) external view returns (StealthStorage memory) {
        return _smartAccountStealth[smartAccount];
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        virtual
        returns (uint256 validationData)
    {
        bytes1 mode = userOp.signature[0];

        // 0x00: signature from spending key
        // 0x01: aggregated signature from owner and shared secret
        if (mode == 0x00) {
            if (!_verifySignature(userOpHash, userOp.signature[1:], userOp.sender)) {
                return SIG_VALIDATION_FAILED;
            }
        } else if (mode == 0x01) {
            if (!_verifyAggregateSignature(userOpHash, userOp.signature[1:], userOp.sender)) {
                return SIG_VALIDATION_FAILED;
            }
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function isValidSignature(bytes32 dataHash, bytes memory moduleSignature)
        public
        view
        virtual
        override
        returns (bytes4)
    {
        bytes1 mode = moduleSignature[0];
        assembly {
            let len := mload(moduleSignature)
            mstore(add(moduleSignature, 0x01), sub(len, 1))
            moduleSignature := add(moduleSignature, 0x01)
        }

        // 0x00: signature from spending key
        // 0x01: aggregated signature from owner and shared secret
        if (mode == 0x00) {
            if (_verifySignature(dataHash, moduleSignature, msg.sender)) {
                return EIP1271_MAGIC_VALUE;
            }
            return bytes4(0xffffffff);
        } else if (mode == 0x01) {
            if (_verifyAggregateSignature(dataHash, moduleSignature, msg.sender)) {
                return EIP1271_MAGIC_VALUE;
            }
            return bytes4(0xffffffff);
        } else {
            return bytes4(0xffffffff);
        }
    }

    function _verifySignature(bytes32 dataHash, bytes memory signature, address smartAccount)
        internal
        view
        returns (bool)
    {
        address stealthAddress = _smartAccountStealth[smartAccount].stealthAddress;
        bytes32 hash = ECDSA.toEthSignedMessageHash(dataHash);

        if (stealthAddress == hash.recover(signature)) {
            return true;
        }
        if (stealthAddress != dataHash.recover(signature)) {
            return false;
        }
        return true;
    }

    function _verifyAggregateSignature(bytes32 dataHash, bytes memory signature, address smartAccount)
        internal
        view
        returns (bool)
    {
        StealthStorage storage stealthData = _smartAccountStealth[smartAccount];
        return StealthAggreagteSignature.validateAgg(
            stealthData.stealthPubkey,
            stealthData.dhkey,
            stealthData.stealthPubkeyPrefix,
            stealthData.dhkeyPrefix,
            dataHash,
            signature
        );
    }
}
