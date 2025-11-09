// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {anchoringCommit} from "../src/anchoringCommit.sol";

contract anchoringCommitScript is Script {
    anchoringCommit public anchoring;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        anchoring = new anchoringCommit(0); // change to 99 to test functionality

        vm.stopBroadcast();
    }
}
