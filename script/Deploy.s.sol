// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../contracts/OmoValidationAdapter.sol";

/// Usage:
///   forge script script/Deploy.s.sol:Deploy \
///     --rpc-url robinhood \
///     --private-key $DEPLOYER_KEY \
///     --broadcast
///
/// Requires REGISTRY_ADDRESS and OPERATOR_ADDRESS env vars set before running.
contract Deploy is Script {
    function run() external {
        address registry = vm.envAddress("REGISTRY_ADDRESS");
        address operator = vm.envAddress("OPERATOR_ADDRESS");

        vm.startBroadcast();
        OmoValidationAdapter adapter = new OmoValidationAdapter(registry, operator);
        vm.stopBroadcast();

        console2.log("OmoValidationAdapter deployed at:", address(adapter));
    }
}
