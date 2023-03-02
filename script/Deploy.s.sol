// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import {Script} from "forge-std/Script.sol";

import {Bridge} from "src/core/Bridge.sol";

/// @notice A very simple deployment script
contract Deploy is Script {
    /// @notice The main script entrypoint
    /// @return bridge The deployed contract
    function run() external returns (Bridge bridge) {
        vm.startBroadcast();
        bridge = new Bridge();
        vm.stopBroadcast();
    }
}
