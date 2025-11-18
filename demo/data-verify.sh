# Verify
echo "#### Verify CT, Proof ####"
echo "--------------------------"
./merkle verify ./epoch1_proof ./epoch1_digest ./epoch1_root > temp_verify
tail -2 temp_verify
# sleep 5

# store verify receipt to ipfs
echo "#### Uploading verify receipt into IPFS and put CID into global variable ####"
echo "-----------------------------------------------------------------------------"
IPFS_RECEIPT_CID=$(ipfs add temp_verify | awk '{ print $2 }')
# sleep 5

# upload evidence to blockchain
echo "#### Uploading evidence to blockchain ####"
echo "------------------------------------------"
cast send $RECEIPTCONTRACT_ADDR "createReceipt(string,string)" $IPFS_RECEIPT_CID $IPFS_CT_CID --private-key $PRIVATE_KEY 
# sleep 5
