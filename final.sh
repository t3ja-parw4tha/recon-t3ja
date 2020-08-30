#!/bin/bash

echo "Looking for HTTP request smugglig"
python3 /opt/tools/smuggler.py -u alive.txt | tee -a smuggler_op.txt



echo "####Starting Naabu For Port Scanning####"
for i in $(cat $CUR_DIR/ip.txt);do naabu -silent -host $i -json;done | tee -a $CUR_DIR/ports.txt


echo "checking for subdomain takeovers"
subjack -w $CUR_DIR/all.txt -t 100 -timeout 30 -o takeover.txt -ssl


echo "####Starting Github Subdomain Scanning #####"
mkdir $CUR_DIR/github_recon
for i in {1..5};do python3 ~/tools/github-subdomains.py -t $github_token -d $1 | tee -a $CUR_DIR/github_recon/github_subs.txt ;done
python3 ~/tools/github-endpoints.py -d $1 -t $github_token -s -r | tee -a $CUR_DIR/github_recon/github_endpoints.txt


echo "Starting FFUF"
mkdir $CUR_DIR/ffuf_op
for i in $(cat alive.txt)
do
    ffufop=$(echo $i | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g')
    ffuf -u $i/FUZZ -w ~/tools/dirsearch/db/dicc.txt -mc 200 -t 100 -fs 0 -o ffuf_op/$ffufop.html -of html
done
gospider -S $CUR_DIR/alive.txt --depth 3 --no-redirect -t 50 -c 3 -o gospider_out
