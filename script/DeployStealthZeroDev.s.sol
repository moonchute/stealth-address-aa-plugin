// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/zerodev/StealthAddressValidator.sol";
import "forge-std/Script.sol";

contract DeployStealthZeroDev is Script {
    function run() external {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);

        new StealthAddressValidator();
        vm.stopBroadcast();
    }
}
