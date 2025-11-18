# get all fork from blockchain and write first record to env var (2, 4, 6) , second = 8, 10, 12
echo "#### Get anchored data from blockchain ####"
echo "-------------------------------------------"
cast call $ANCHORCONTRACT_ADDR "getAllInfoCurrentMapper()((string,string,string)[])" --private-key $PRIVATE_KEY | awk -F'"' '{print $2, $4, $6}' | column -t > temp_env
GET_ROOT=$(cat temp_env| awk '{ print $1 }')
GET_IPFS_PROOF_CID=$(cat temp_env| awk '{ print $2 }')
GET_IPFS_CT_CID=$(cat temp_env| awk '{ print $3 }')
# sleep 5
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
