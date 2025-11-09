#!/bin/bash
# cast send $CONTRACT_ADDR "createRecord(string,string)" "0x111111" "0x222222" --private-key $PRIVATE_KEY 
# cast send $CONTRACT_ADDR "createRecord(string,string)" "0x333333" "0x444444" --private-key $PRIVATE_KEY
cast send $CONTRACT_ADDR "createRecordMap(string,string)" "a371bc626a53fc7a5d3930ff49d46083e9138ba6e7dfa320b4966682ee1f3b83" "QmeHY3xMtqpvRuGTutrcEToLnPLZxaTBHuJq2K7pUtSVSo" --private-key $PRIVATE_KEY 
# cast send $CONTRACT_ADDR "createRecordMap(string,string)" "0x333333" "0x444444" --private-key $PRIVATE_KEY
cast call $CONTRACT_ADDR "getAllInfoCurrentMapper()((string,string)[])" --private-key $PRIVATE_KEY # use struct member type instead if abi not load 
cast call $CONTRACT_ADDR "getInfoByMapperIndex(uint256)((string, string)[])" 0  --private-key $PRIVATE_KEY
# cast call $CONTRACT_ADDR "getAllInfo()(MetaLogs[])" --private-key $PRIVATE_KEY # if abi load correctly
# cast call $CONTRACT_ADDR "getAllInfo()" --private-key $PRIVATE_KEY > buff
# cast call $CONTRACT_ADDR "decode(bytes)(bytes)" $(cat buff) --private-key $PRIVATE_KEY 
