#!bin/bash
# cd merkle-tree && cargo build --release && cp ./target/release/merkle-tree ../merkle-tree-arm64 && cd - && bash test.sh
 cd merkle-tree 
 cargo build --release 
 cp ./target/release/merkle-tree ../merkle-tree-arm64 
 cd - 
 # bash test.sh

