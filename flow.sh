#!/bin/bash

find ./log -type f -exec ./sha3sum_arm64 256 {} \; > log_hash # use ./sha3sum from SHA3IUF b/c it's faster than traditional linux sha3sum
touch temp_proof temp_root
./merkle-tree-arm64
