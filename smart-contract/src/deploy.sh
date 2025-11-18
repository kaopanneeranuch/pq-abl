#!/bin/bash

forge script ../script/anchoring-commit.s.sol --private-key $PRIVATE_KEY --rpc-url http://localhost:8545 --broadcast
forge script ../script/verify-receipt.s.sol --private-key $PRIVATE_KEY --rpc-url http://localhost:8545 --broadcast
