# echo "#### Prehash before go to merkle tree ####"
# find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > log_digest 
# echo ""

echo "#### Compute log digest to get proof and root ####"
./merkle-tree-arm64 compute ./log_digest
echo ""

echo "#### Verify num ####"
./merkle-tree-arm64 verity ./temp_proof ./log_digest ./temp_root
echo ""

# rm temp_proof temp_root log_digest 
