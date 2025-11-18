#!/bin/bash

# find ./log -type f -exec ./sha3sum_arm64 256 {} \; > log_digest # use ./sha3sum from SHA3IUF b/c it's faster than traditional linux sha3sum
# find ./logs -type f -exec ./sha3sum_arm64 256 {} \; | cut -d ' ' -f1 > log_digest # f1 = get first column then write to log_digest , cut doesn't affect compute time.
# gen log
echo "#### Generating logs ####"
echo "-------------------------"
python3 gen_log.py -n 1000 --epoch-duration 30
sleep 5

# make all find sort and faster hash
echo "#### Prehash before go to merkle tree ####"
echo "------------------------------------------"
find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > log_digest 
sleep 5

# tar gzip all logs/ to "epoch1.tar.gz" and remove
echo "#### Gzip logs digest and remove ####"
echo "-------------------------------------"
tar -czvf epoch1.tar.gz ./logs/* 
rm -rf ./logs
sleep 5

# upload to ipfs and assign cid to environment variable name IPFS_CT_CID
echo "#### Uploading zipped log digest to IPFS and put CID into global variable ####"
echo "------------------------------------------------------------------------------"
IPFS_CT_CID=$(ipfs add epoch1.tar.gz | awk '{ print $2 }') 
sleep 5

# compute log digest -> gete temp_proof temp_root
echo "#### Compute log digest to get proof and root ####"
echo "--------------------------------------------------"
./merkle compute ./log_digest
sleep 5

# store proof into ipfs
echo "#### Uploading proof into IPFS and put CID into global variable ####"
echo "--------------------------------------------------------------------"
IPFS_PROOF_CID=$(ipfs add temp_proof | awk '{ print $2 }')
ROOT=$(cat temp_root)
sleep 5


# remove temp
echo "#### Remove all unused temporary file ####"
echo "------------------------------------------"
rm temp_proof temp_root log_digest
sleep 5

#
# upload all fork to smart contract
echo "#### Anchoring to blockchain ####"
echo "---------------------------------"
cast send $ANCHORCONTRACT_ADDR "createRecordMap(string,string,string)" $ROOT $IPFS_PROOF_CID $IPFS_CT_CID --private-key $PRIVATE_KEY 
sleep 5

# get all fork from blockchain and write first record to env var (2, 4, 6) , second = 8, 10, 12
echo "#### Get anchored data from blockchain ####"
echo "-------------------------------------------"
cast call $ANCHORCONTRACT_ADDR "getAllInfoCurrentMapper()((string,string,string)[])" --private-key $PRIVATE_KEY | awk -F'"' '{print $2, $4, $6}' | column -t > temp_env
GET_ROOT=$(cat temp_env| awk '{ print $1 }')
GET_IPFS_PROOF_CID=$(cat temp_env| awk '{ print $2 }')
GET_IPFS_CT_CID=$(cat temp_env| awk '{ print $3 }')
sleep 5
#
# # ipfs get data
#
echo $GET_ROOT > ./epoch1_root
ipfs get $GET_IPFS_PROOF_CID -o ./epoch1_proof
ipfs get $GET_IPFS_CT_CID -o ./epoch1.tar.gz
tar -xzvf ./epoch1.tar.gz
find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > epoch1_digest 
# #
#
# Verify
echo "#### Verify CT, Proof ####"
echo "--------------------------"
./merkle verify ./epoch1_proof ./epoch1_digest ./epoch1_root > temp_verify
tail -2 temp_verify
sleep 5

# store verify receipt to ipfs
echo "#### Uploading verify receipt into IPFS and put CID into global variable ####"
echo "-----------------------------------------------------------------------------"
IPFS_RECEIPT_CID=$(ipfs add temp_verify | awk '{ print $2 }')
sleep 5

# upload evidence to blockchain
echo "#### Uploading evidence to blockchain ####"
echo "------------------------------------------"
cast send $RECEIPTCONTRACT_ADDR "createReceipt(string,string)" $IPFS_RECEIPT_CID $IPFS_CT_CID --private-key $PRIVATE_KEY 
sleep 5
# 
# # touch temp_proof temp_root
# # cp temp_proof proof_digest
# # ./merkle compute ./proof_digest
