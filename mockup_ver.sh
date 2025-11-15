for num in 10 50 100 500 1000 5000 10000 25000 50000
do 
    echo "#### Generating $num logs ####"
    python3 gen_log.py -n $num -e 1 --start-days 30 --prefix log
    echo ""


    echo "#### Prehash before go to merkle tree ####"
    time find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > log_digest 
    echo ""

    echo "#### Compute log digest to get proof and root ####"
    ./merkle-tree-x86 compute ./log_digest
    echo ""


    echo "#### Verify $num ####"
    ./merkle-tree-x86 verify ./temp_proof ./log_digest ./temp_root > temp_verify
    echo ""

    tail -1 temp_verify

    echo "#### Delete all logs file ####"
    rm -rf ./logs
    echo ""

    echo "#### Cleaning $num environment ####"
    rm temp_proof temp_root log_digest temp_verify
    sleep 2
done
