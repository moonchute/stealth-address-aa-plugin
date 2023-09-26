// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "src/biconomy/StealthAddressRegistryModule.sol";
import "forge-std/Script.sol";

contract DeployStealthBiconomy is Script {
    function run() external {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);

        new StealthAddressRegistryModule();
        vm.stopBroadcast();
    }
}
