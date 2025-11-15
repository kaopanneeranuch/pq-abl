/*
This code is based on the opensource (Apache 2.0 license) that can be found her:

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

// https://medium.com/@p4524888/building-a-merkle-tree-root-computation-in-rust-c6b9731102aa
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{prelude::*, BufReader},
    path::Path,
    env,
    time::Instant};
use sha3::{Digest, Sha3_256};
use hex;

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
pub fn compute_root_proof(hashes: &[Hash]) -> Hash {
    let mut nodes: Vec<Hash> = hashes.to_vec();
    let mut length = nodes.len();
    let mut is_lowestpair = true;

    while length > 1 {
        let mut i = 0;
        while i < length {
            let left = &nodes[i];
            // println!("Left node: {:?}", left);
            let right = if i + 1 < length { &nodes[i + 1] } else { &nodes[i] };
            // println!("Right node: {:?}", right);
            nodes[i / 2] = *compute_hash_tree_branch(left, right);
            // Check for the lowest pair if yes do print out
            if is_lowestpair{
                // println!("index: {}", i);
                // println!("Merkle Proof : {}", nodes[i / 2].to_hex_string());
                let mut file_proof = OpenOptions::new()
                    .write(true)
                    .append(true)
                    .open("temp_proof")
                    .unwrap();
                if let Err(e) = writeln!(file_proof, "{}", nodes[i/2].to_hex_string()){
                    eprintln!("Counldn't write proof to file: {}", e)
                }
            }
            // println!();
            i += 2;
        }
        is_lowestpair = false; // turn lowest pair to false
        length = (length + 1) / 2;
    }

    nodes[0].clone()
}

// Verify proof
pub fn verify_proof_root(ct_digest: &[Hash], proof: &[Hash], root: &[Hash]) -> bool {
    let mut nodes: Vec<Hash> = ct_digest.to_vec();
    let mut length = nodes.len(); 
    let mut proof_nodes: Vec<Hash> = proof.to_vec();
    let mut is_lowestpair = true;
    let mut pair_count = 0;
    let mut tamper_rec: Vec<_> = Vec::new();
    // Open temp_verify to write the verify result.
    // let mut file_verify = OpenOptions::new()
    //     .write(true)
    //     .append(true)
    //     .open("temp_verify")
    //     .unwrap();
    while length > 1{
        let mut i = 0;
        while i < length {
            // check wether nodes is in even to create pair or not
            let digest_left = &nodes[i];
            let digest_right = if i + 1 < length { &nodes[i + 1] } else { &nodes[i] };

            // the proof will re-compute after lowest pair is checked -> when pass the first
            // itteration and length/2 which equal to proof size -> to get root
            if !is_lowestpair {
                let proof_left = &proof_nodes[i];
                let proof_right = if i + 1 < length { &proof_nodes[i + 1] } else { &proof_nodes[i] };
                proof_nodes[i / 2] = *compute_hash_tree_branch(proof_left, proof_right);
            }
            // recompute proof hash
            // Check for the lowest pair if yes do print out
            if is_lowestpair{

                // proof is in the lowest pair.
                nodes[i / 2] = *compute_hash_tree_branch(digest_left, digest_right);
                print!("Verify digest pair with proof {} : " , (pair_count + 1));
                // compare i proof with new compute proof (from digest)
                if proof[pair_count].as_bytes() == nodes[i / 2].as_bytes() {
                    println!("Valid");
                    // if let Err(e) = writeln!(file_verify, "Verify digest pair with proof {} : Valid", pair_count + 1){
                    //     eprintln!("Counldn't write to file: {}", e)
                    //     }
                // we compute and check hash digest with proof with only the lowest pair b/c our
                }
                else {
                    println!("Invalid");
                    // if let Err(e) = writeln!(file_verify, "Verify digest pair with proof {} : Invalid", pair_count){
                    //     eprintln!("Counldn't write to file: {}", e)
                    //     }
                    tamper_rec.push(pair_count + 1);
                    // break;
                }
                pair_count += 1;
            }
            i += 2;
        }
        is_lowestpair = false; // turn lowest pair to false
        length = (length + 1) / 2;
        // after 
        if length == 1{
            if root[0].as_bytes() == proof_nodes[0].as_bytes(){
                println!("Verify proof: Valid");
                // if let Err(e) = writeln!(file_verify, "Verify proof : Invalid"){
                //     eprintln!("Counldn't write to file: {}", e)
                //     }
                if tamper_rec.len() > 1{
                    print!("The digest that got tampered is in pair: ");
                    // if let Err(e) = write!(file_verify, "The digest that got tampered is in pair : "){
                    //     eprintln!("Counldn't write to file: {}", e)
                    // }
                    let tamper_rec_len = tamper_rec.len();
                    for i in 0..tamper_rec_len {
                        print!("{}, ", tamper_rec[i]);
                        // write!(file_verify, "{}, ", temper_rec[i]);
                    }
                    println!();
                }
            }
            else {
                println!("Verify proof : Invalid proof, proof got tamper!");
            }
        }
    }
    return true;
}

/// Compute the hash of two child nodes.
fn compute_hash_tree_branch(left: &Hash, right: &Hash) -> Box<Hash> {
    let mut hash_concat: [u8; HASH_SIZE * 2] = [0; HASH_SIZE * 2];
    hash_concat[..HASH_SIZE].copy_from_slice(left.as_bytes());
    hash_concat[HASH_SIZE..].copy_from_slice(right.as_bytes());
    let result = Hash::compute_hash(&hash_concat);
    Box::new(result)
}

fn lines_from_file(filename: impl AsRef<Path>) -> Vec<String> {
    let file = File::open(filename).expect("no such file");
    let buf = BufReader::new(file);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .collect()
}

fn decode(lines: Vec<String>) -> Vec<Hash>{
    let mut hash_vec: Vec<_> = Vec::new(); // initialize vector
    for line in lines {
    // Trim whitespace just in case (like newlines in your output)
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() {
            continue;
        }
        // 1. Decode the hex string into raw bytes
        let decoded_bytes = hex::decode(trimmed_line)
            .expect("Failed to decode hex string from file");
        // 2. Create a Hash object directly from those bytes
        let hash = Hash::from_bytes(&decoded_bytes)
            .expect("Invalid hash length in file");
        hash_vec.push(hash);
    }
    return hash_vec;
}

fn main() {
    // Example data for the Merkle tree.
    let args:  Vec<String> = env::args().collect();
    let arg_len = args.len();
    if arg_len < 3 {
        println!("The argument is not met");
    }
    else{
        let feature = &args[1];
        if feature == "compute" {
            let _start_compute = Instant::now();
            let digest_path = &args[2];
            let _create_root_file = File::create("temp_root");
            let _create_proof_file = File::create("temp_proof");
            let lines = lines_from_file(digest_path); // read line
            let leaf_hashes = decode(lines);
            // println!("Line: {:?}", lines);
            let merkle_root = compute_root_proof(&leaf_hashes);

            // Output the results.
            // println!("Merkle Root: {:?}", merkle_root);
            println!("Merkle Root (Hex): {}", merkle_root.to_hex_string());
            let mut file_root = OpenOptions::new()
                .write(true)
                .append(true)
                .open("temp_root")
                .unwrap();
            if let Err(e) = writeln!(file_root, "{}", merkle_root.to_hex_string()){
                eprintln!("Counldn't write to file: {}", e)
                }
            let end_compute = Instant::now();
            let _elapsed_compute = end_compute.duration_since(_start_compute);
            println!("The merkle tree creation took: {:?}", _elapsed_compute);
        }
        else if feature == "verify" {
            if arg_len != 5{
                println!("The argument missing:");
            }
            else{
                let _create_root_file = File::create("temp_verify");
                let _start_verity = Instant::now();
                let ver_proof = &args[2];
                let ver_digest = &args[3];
                let ver_root = &args[4];

                let root_verify = lines_from_file(ver_root);
                let digest_verify = lines_from_file(ver_digest);
                let proof_verify = lines_from_file(ver_proof);

                let hash_proof = decode(proof_verify);
                let hash_digest = decode(digest_verify);
                let hash_root = decode(root_verify);
                verify_proof_root(&hash_digest, &hash_proof, &hash_root);
                let end_verify = Instant::now();
                let _elapsed_verify = end_verify.duration_since(_start_verity);

                println!("The verification took: {:?}", _elapsed_verify);
            }
        }
    }
}
