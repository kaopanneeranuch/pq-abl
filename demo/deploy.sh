#!/bin/bash

forge script /Users/natapat/Documents/somchart_v2/code/pq-abl/smart-contract/script/anchoring-commit.s.sol --private-key $PRIVATE_KEY --rpc-url http://localhost:8545 --broadcast
forge script /Users/natapat/Documents/somchart_v2/code/pq-abl/smart-contract/script/verify-receipt.s.sol --private-key $PRIVATE_KEY --rpc-url http://localhost:8545 --broadcast
