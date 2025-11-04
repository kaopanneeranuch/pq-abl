use bloomfilter::Bloom; // import bloom filter as Bloom ?
fn main() {
    let num_items = 100;
    let fp_rate = 0.001;
    let seed = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let mut bloom = Bloom::new_for_fp_rate_with_seed(num_items, fp_rate, &seed).unwrap(); // we can
    // save stage now since bloom filter is set seed.
    bloom.set(&"b2de55a3620d6d88bf5d7e561b247260449978c70b99ced7a1eb3c7288dba086");   // insert 10 in the bloom filter
    // bloom.set(&"1");
    println!("{}", (bloom.check(&"b2de55a3620d6d88bf5d7e561b247260449978c70b99ced7a1eb3c7288dba086")));
    println!("{}", (bloom.check(&"abcedfg")));
    println!("{}", (bloom.is_empty()));
    println!("{}", (bloom.number_of_hash_functions()));
    println!("{:?}", (bloom.to_bytes()));
    println!("{:?}", (bloom.into_bytes()));
    // println!("{:?}", bloom);

}
