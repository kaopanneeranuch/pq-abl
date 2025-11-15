for num in 10 50 100 500 1000 5000 10000 50000 100000
do 
    $num
    echo "#### Generating $num logs ####"
    python3 gen_log.py -n $num -e 1 --start-days 30 --prefix log
    echo ""


    echo "#### Prehash before go to merkle tree ####"
    time find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > log_digest 
    echo ""

    echo "#### Compute log digest to get proof and root ####"
    ./merkle-tree-arm64 compute ./log_digest
    echo ""

    echo "#### Delete all logs file ####"
    rm -rf ./logs
    echo ""

    echo "#### Verify $num ####"
    ./merkle-tree-arm64 verity ./temp_proof ./log_digest ./temp_root
    echo ""

    rm temp_proof temp_root log_digest 
    sleep 2
done
