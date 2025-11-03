/*
This code is based on the opensource (Apache 2.0 license) that can be found her:
https://github.com/evadawnley/global/blob/main/crates/utility/src/hashing.rs
*/
/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
use std::fmt;
use sha3::{Digest, Sha3_256};

// Define the hash size (32 bytes for SHA3-256).
const HASH_SIZE: usize = 32;

#[derive(Clone)]
pub struct Hash([u8; HASH_SIZE]);

// Implement Debug to display hashes in hexadecimal format.
impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl Hash {
    /// Create a new `Hash` from a fixed-size array of 32 bytes.
    pub fn new(data: [u8; HASH_SIZE]) -> Hash {
        Hash(data)
    }

    /// Create an empty `Hash` initialized to zero.
    pub fn new_empty() -> Hash {
        Hash([0; HASH_SIZE])
    }

    /// Get the hash as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert the hash to a hexadecimal string.
    pub fn to_hex_string(&self) -> String {
        self.0.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

    /// Create a `Hash` from a slice of bytes, ensuring the length is 32.
    pub fn from_bytes(bytes: &[u8]) -> Result<Hash, &'static str> {
        if bytes.len() != HASH_SIZE {
            return Err("Invalid hash length");
        }
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(bytes);
        Ok(Hash(hash))
    }

    /// Compute a SHA3-256 hash of the input data.
    pub fn compute_hash(data: &[u8]) -> Hash {

        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let sha3_256_hash = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&sha3_256_hash);
        Hash(hash)
    }
}

/// Compute the Merkle root from a list of hashes.
pub fn compute_root(hashes: &[Hash]) -> Hash {
    let mut nodes: Vec<Hash> = hashes.to_vec();
    let mut length = nodes.len();
    let mut is_lowestpair = true;

    while length > 1 {
        let mut i = 0;
        while i < length {
            let left = &nodes[i];
            let right = if i + 1 < length { &nodes[i + 1] } else { &nodes[i] };
            nodes[i / 2] = *compute_hash_tree_branch(left, right);
            // Check for the lowest pair if yes do print out
            if is_lowestpair{
                println!("Merkle Proof : {}", nodes[i / 2].to_hex_string());
            }
            i += 2;
        }
        is_lowestpair = false; // turn lowest pair to false
        length = (length + 1) / 2;
    }

    nodes[0].clone()
}

/// Compute the hash of two child nodes.
fn compute_hash_tree_branch(left: &Hash, right: &Hash) -> Box<Hash> {
    let mut hash_concat: [u8; HASH_SIZE * 2] = [0; HASH_SIZE * 2];
    hash_concat[..HASH_SIZE].copy_from_slice(left.as_bytes());
    hash_concat[HASH_SIZE..].copy_from_slice(right.as_bytes());
    let result = Hash::compute_hash(&hash_concat);
    Box::new(result)
}

fn main() {
    // Example data for the Merkle tree.
    let data = vec![
        b"Block 1".to_vec(),
        b"Block 2".to_vec(),
        b"Block 3".to_vec(),
        b"Block 4".to_vec(),
    ];

    // Compute the hashes for the leaves.
    let leaf_hashes: Vec<Hash> = data.into_iter()
        .map(|d| Hash::compute_hash(&d))
        .collect();

    // Compute the Merkle root.
    let merkle_root = compute_root(&leaf_hashes);

    // Output the results.
    // println!("Merkle Root: {:?}", merkle_root);
    println!("Merkle Root (Hex): {}", merkle_root.to_hex_string());
}
