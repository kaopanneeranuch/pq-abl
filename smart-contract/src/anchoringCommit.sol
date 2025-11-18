// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// Map to Array of stuct -> each push to 100 members
// recTracker for 100 members if meet then reset ot 0
// recTracker for map index -> increase every 100 record of arrays per mapping

contract anchoringCommit {
    uint16 private recTracker; // keep track record per mapper
    uint256 private mapperIndex; // mapper index
    uint16 private constant RECORDLIMIT = 1000; // record limit per mapper
    structRecord[] public fork;
    mapping(uint256 => structRecord[]) public mapper; // create hash table map key(uint256) -> value(structRecord[]) -> store in storage/permanently in blockchain

    struct structRecord { // create struct
        string root;
        string proofCid;
        string ctCid;
        uint256 timestamp;
    }
    constructor (uint16 init) {
        recTracker = init;
        mapperIndex = 0;
    }

    function getCounter() public view returns (uint16){ // cast call $CONTRACT_ADDR "getCounter()(int)" --private-key $PRIVATE_KEY
        return recTracker;
    }

    function getMapperCounter() public view returns (uint256){
        return mapperIndex;
    }
    
    function createRecordMap(string calldata _rootHash, string calldata _proofCid, string calldata _ctCid) public { // use calldata because we don't need to modify parameter if want to modify use memory instead
        if (recTracker >= RECORDLIMIT){ // if record meet limit increase mapper index and reset log tracker.
            mapperIndex += 1;
            recTracker = 0;
            delete fork; // empty arrays
        }

        fork.push(structRecord({root: _rootHash, proofCid: _proofCid, ctCid: _ctCid, timestamp: block.timestamp}));
        mapper[mapperIndex] = fork;
        recTracker += 1;
    }

    // This function will return all info in array that store here which might be costly for longterm
    function getAllInfoCurrentMapper() public view returns (structRecord[] memory){
        return mapper[mapperIndex];
    }

    function getInfoByMapperIndex(uint256 _index) public view returns (structRecord[] memory){
        if (_index <= mapperIndex){
            return mapper[_index];
        }
    }

    // get current block number
    function getBlockNumber() public view returns (uint256){ 
        return block.number;
    }

    // get block hash by block number
    function getBlockHash(uint256 _num) public view returns (bytes32){ 
        return blockhash(_num);
    }

    function getNumEpoch() public view returns (uint16){
        return recTracker;
    }

}
