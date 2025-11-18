use bloomfilter::Bloom; // import bloom filter as Bloom ?
//
use std::{
    fs::{ File, OpenOptions},
    path::Path,
    io::{prelude::*, BufReader}
    };
    
    
fn lines_from_file(filename: impl AsRef<Path>) -> Vec<String> {
    let file = File::open(filename).expect("no such file");
    let buf = BufReader::new(file);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .collect()
}
fn main() {
    let num_items = 100;
    let fp_rate = 0.001;
    let seed = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let mut bloom = Bloom::new_for_fp_rate_with_seed(num_items, fp_rate, &seed).unwrap(); // we can
    // Buffer that will load to bloom bit array, normally should be in run time, but I don't know
    // how to do it by now.
    let buffer = lines_from_file("./root_buffer"); // read line
    for buff in buffer {
        bloom.set(&buff);   // insert buffer of root in the bloom filter bitarray
    }
    // open write appedn file
    let mut verified_root = OpenOptions::new()
        .write(true)
        .append(true)
        .open("./verified_root") // open and appedn verified_root , this will be clear every time
        // using bash script
        .unwrap();

    let verify = lines_from_file("./root_verify"); // read root that fetch from blockchain
    for ver in verify {
       if bloom.check(&ver){
            if let Err(e) = writeln!(verified_root, "{}", ver){ // write all root that exist/ valid
                // to ./verified_root
                eprintln!("Counldn't write veried rootproof to file: {}", e)
            }
        };
    }
    
    // debug
    //
    // save stage now since bloom filter is set seed.
    // bloom.set(&"1");
    // println!("{}", (bloom.check(&"")));
    // println!("{}", (bloom.check(&"abcedfg")));
    // println!("{}", (bloom.is_empty()));
    // println!("{}", (bloom.number_of_hash_functions()));
    // println!("{:?}", (bloom.to_bytes()));
    // println!("{:?}", (bloom.into_bytes()));
    // println!("{:?}", bloom);

}
