# make all find sort and faster hash
echo "#### Prehash before go to merkle tree ####"
echo "------------------------------------------"
find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > log_digest 
echo "------------------------------------------"
echo ""

# compute log digest -> gete temp_proof temp_root
echo "#### Compute log digest to get proof and root ####"
echo "--------------------------------------------------"
./merkle compute ./log_digest
echo "--------------------------------------------------"
echo ""

# store proof into ipfs
echo "#### Uploading proof into IPFS and put CID into global variable ####"
echo "--------------------------------------------------------------------"
IPFS_PROOF_CID=$(ipfs add temp_proof | awk '{ print $2 }')
echo "IPFS proof CID: is $IPFS_PROOF_CID"
ROOT=$(cat temp_root)
echo "--------------------------------------------------------------------"
echo ""

# tar gzip all logs/ to "epoch1.tar.gz" and remove
echo "#### Gzip logs digest and remove ####"
echo "-------------------------------------"
tar -czvf epoch1.tar.gz ./logs/* 
rm -rf ./logs
echo "-------------------------------------"
echo ""

# upload to ipfs and assign cid to environment variable name IPFS_CT_CID
echo "#### Uploading zipped log digest to IPFS and put CID into global variable ####"
echo "------------------------------------------------------------------------------"
IPFS_CT_CID=$(ipfs add epoch1.tar.gz | awk '{ print $2 }') 
echo "IPFS ct CID is : $IPFS_CT_CID"
echo "------------------------------------------------------------------------------"
echo ""

# remove temp
echo "#### Remove all unused temporary file ####"
echo "------------------------------------------"
rm temp_proof temp_root log_digest epoch1.tar.gz
echo "------------------------------------------"
echo ""


# upload all fork to smart contract
echo "#### Anchoring to blockchain ####"
echo "---------------------------------"
cast send $ANCHORCONTRACT_ADDR "createRecordMap(string,string,string)" $ROOT $IPFS_PROOF_CID $IPFS_CT_CID --private-key $PRIVATE_KEY 
echo "---------------------------------"
echo ""
