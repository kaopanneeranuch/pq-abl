#!/bin/bash

# find ./log -type f -exec ./sha3sum_arm64 256 {} \; > log_digest # use ./sha3sum from SHA3IUF b/c it's faster than traditional linux sha3sum
# find ./logs -type f -exec ./sha3sum_arm64 256 {} \; | cut -d ' ' -f1 > log_digest # f1 = get first column then write to log_digest , cut doesn't affect compute time.
# gen log
echo "#### Generating logs ####"
python3 gen_log.py -n 1000 -e 1 --start-days 30 --prefix log

# make all find sort and faster hash
echo "#### Prehash before go to merkle tree ####"
time find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > log_digest 
#
# tar gzip all logs/ to "epoch1.tar.gz" and remove
# create temp_filename since tar can't handle args 100000 digest
# with records > 100000
# beware when unzip
# echo "Gzip logs digest and remove"
# ls ./logs > temp_filename
# cd ./logs
# tar -cz -T ../temp_filename -f ../epoch1.tar.gz
# cd -
# rm -rf ./logs
# rm temp_filename

# with records < 10000 : When unzip will unzip in dir -> logs
echo "#### Gzip logs digest and remove ####"
tar -czf ./epoch1.tar.gz ./logs/*
rm -rf ./logs
#
# # upload to ipfs and assign cid to environment variable name IPFS_LOG_CID
echo "Uploading zipped log digest to IPFS and put CID into global variable"
IPFS_CT_CID=$(ipfs add epoch1.tar.gz | awk '{ print $2 }') 
#
# # compute log digest -> gete temp_proof temp_root
echo "Compute log digest to get proof and root"
./merkle-tree-arm64 compute ./log_digest
#
# # store both root and proof into ipfs
echo "Uploading both root and proof into IPFS and put CID into global variable"
IPFS_PROOF_CID=$(ipfs add temp_proof | awk '{ print $2 }')
IPFS_ROOT_CID=$(ipfs add temp_root | awk '{ print $2 }')
#
# # remove temp
echo "Remove all unused temporary file"
rm temp_proof temp_root log_digest 
