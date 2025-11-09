#!/bin/bash

# find ./log -type f -exec ./sha3sum_arm64 256 {} \; > log_digest # use ./sha3sum from SHA3IUF b/c it's faster than traditional linux sha3sum
# find ./logs -type f -exec ./sha3sum_arm64 256 {} \; | cut -d ' ' -f1 > log_digest # f1 = get first column then write to log_digest , cut doesn't affect compute time.
find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > log_digest # make all find sort and faster hash
# touch temp_proof temp_root
./merkle-tree-arm64 compute ./log_digest
cp temp_proof proof_digest
./merkle-tree-arm64 verify temp_proof log_digest temp_root
# ./merkle-tree-arm64 compute ./proof_digest
