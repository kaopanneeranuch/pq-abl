echo "#### Generating $1 logs ####"
python3 gen_log.py -n $1 -e 1 --start-days 30 --prefix log

echo "#### Prehash ####"
find ./logs -type f -print0 | sort -z | xargs -r0 sha3sum -a 256 | awk '{ print $1 }' > log_digest 

