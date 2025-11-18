// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {verifyReceipt} from "../src/verifyReceipt.sol";

contract verifyReceiptScrit is Script {
    verifyReceipt public receipt;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        receipt = new verifyReceipt(0); // change to 99 to test functionality

        vm.stopBroadcast();
    }
}
