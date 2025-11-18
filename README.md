## Dependencies
    - cargo
    - sha3sum
    - anvil
## Pre-setup

### Build Merkel-tree
```
bash build.sh
```

### Start Local Blockchain
```
anvil
```
### Copy shown private-key and declare global variable
```
export PRIVATE_KEY="<private-key>"
```

### Deploy smart-contact
```
forge script smart-contract/script/anchoring-commit.s.sol --private-key $PRIVATE_KEY --rpc-url http://localhost:8545 --broadcast
forge script smart-contract/script/verify-receipt.s.sol --private-key $PRIVATE_KEY --rpc-url http://localhost:8545 --broadcast
```
### Copy smart-contract address and declare global variable
```
export ANCHORCONTRACT_ADDR="<anchorContract address>"
export RECEIPTCONTRACT_ADDR="<receiptContract address>"
```

## Usage Flow
### gen log
```
echo "Generating logs"
python3 gen_log.py -n 10000 -e 1 --start-days 30 --prefix log

```

### Make all find sort and faster hash
```
echo "Prehash before go to merkle tree"
find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > log_digest 
```

### Tar gzip all logs/ to "epoch1.tar.gz" and remove
```
echo "Gzip logs digest and remove"
tar -czvf epoch1.tar.gz ./logs/* 
rm -rf ./logs
```

### Upload to ipfs and assign cid to environment variable name IPFS_LOG_CID
```
echo "Uploading zipped log digest to IPFS and put CID into global variable"
IPFS_CT_CID=$(ipfs add epoch1.tar.gz | awk '{ print $2 }') 
```

### Compute log digest -> gete temp_proof temp_root
```
echo "Compute log digest to get proof and root"
./merkle-tree-arm64 compute ./log_digest
```

### Store proof into ipfs
```
echo "Uploading proof into IPFS and put CID into global variable"
IPFS_PROOF_CID=$(ipfs add temp_proof | awk '{ print $2 }')
ROOT=$(cat temp_root)
```

### Remove temp
```
echo "Remove all unused temporary file"
rm temp_proof temp_root log_digest
```

### Upload all fork to smart contract
```
cast send $ANCHORCONTRACT_ADDR "createRecordMap(string,string,string)" $ROOT $IPFS_PROOF_CID $IPFS_CT_CID --private-key $PRIVATE_KEY 
```

### Get all fork from blockchain and write first record to env var (2, 4, 6) , second = 8, 10, 12
```
cast call $ANCHORCONTRACT_ADDR "getAllInfoCurrentMapper()((string,string,string)[])" --private-key $PRIVATE_KEY | awk -F'"' '{print $2, $4, $6}' | column -t > temp_env
GET_ROOT=$(cat temp_env| awk '{ print $1 }')
GET_IPFS_PROOF_CID=$(cat temp_env| awk '{ print $2 }')
GET_IPFS_CT_CID=$(cat temp_env| awk '{ print $3 }')
```

### Ipfs get data
```
echo $GET_ROOT > ./epoch1_root
ipfs get $GET_IPFS_PROOF_CID -o ./epoch1_proof
ipfs get $GET_IPFS_CT_CID -o ./epoch1.tar.gz
tar -xzvf ./epoch1.tar.gz
find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > epoch1_digest 
```
### Merkle-tree verify
```
./merkle-tree-arm64 verify ./epoch1_proof ./epoch1_digest ./epoch1_root > temp_verify
```

## Benchmark
```
bash mockup_ver.sh
```
