#!/bin/bash

# find ./log -type f -exec ./sha3sum_arm64 256 {} \; > log_digest # use ./sha3sum from SHA3IUF b/c it's faster than traditional linux sha3sum
# find ./logs -type f -exec ./sha3sum_arm64 256 {} \; | cut -d ' ' -f1 > log_digest # f1 = get first column then write to log_digest , cut doesn't affect compute time.
# gen log
python3 gen_log.py -n 1000 -e 1 --start-days 30 --prefix log
# make all find sort and faster hash
find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > log_digest 
# tar gzip all logs/ to "epoch1.tar.gz" and remove
tar -czvf epoch1.tar.gz ./logs/* 
rm -rf ./logs
# upload to ipfs and assign cid to environment variable name IPFS_LOG_CID
IPFS_CT_CID=$(ipfs add epoch1.tar.gz | awk '{ print $2 }') 
# compute log digest -> gete temp_proof temp_root
./merkle-tree-arm64 compute ./log_digest
IPFS_PROOF_CID=$(ipfs add temp_proof | awk '{ print $2 }')
IPFS_ROOT_CID=$(ipfs add temp_root | awk '{ print $2 }')
# remove temp
rm temp_proof temp_root

#
# upload all fork to smart contract
cast send $CONTRACT_ADDR "createRecordMap(string,string,string)" $IPFS_ROOT_CID $IPFS_PROOF_CID $IPFS_CT_CID --private-key $PRIVATE_KEY 

# get all fork from blockchain and write first record to env var (2, 4, 6) , second = 8, 10, 12
cast call $CONTRACT_ADDR "getAllInfoCurrentMapper()((string,string,string)[])" --private-key $PRIVATE_KEY | awk -F'"' '{print $2, $4, $6}' | column -t > temp_env
GET_IPFS_ROOT_CID=$(cat temp_env| awk '{ print $1 }')
GET_IPFS_PROOF_CID=$(cat temp_env| awk '{ print $1 }')
GET_IPFS_CT_CID=$(cat temp_env| awk '{ print $1 }')
#
# # ipfs get data
ipfs get $GET_IPFS_PROOF_CID -o ./epoch1_proof
ipfs get $GET_IPFS_ROOT_CID -o ./epoch1_root
ipfs get $GET_IPFS_CT_CID -o ./epoch1.tar.gz
tar -xzvf ./epoch1.tar.gz
find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > epoch1_digest 
# #
./merkle-tree-arm64 verify ./epoch1_proof ./epoch1_digest ./epoch1_root
# # touch temp_proof temp_root
# # cp temp_proof proof_digest
# # ./merkle-tree-arm64 compute ./proof_digest
