
##!/bin/bash

#running findomain
echo "Running findomain"
findomain -t $1 -u $1.txt

#starting sublist3r
echo "Running Sublist3r"
python /opt/tools/subdomain-enum/Sublist3r/sublist3r.py -d $1 -v -o subs.txt
cat subs.txt | tee -a $1.txt
rm subs.txt

#running amass
echo "Running Amass"
amass enum --passive -d $1 | tee -a $1.txt

#running assetfinder
echo "Running assetfinder"
assetfinder --subs-only $1 | tee -a $1.txt

#running subfinder
echo "Running Subfinder"
subfinder -d $1 -recursive | tee -a $1.txt

#running censys
echo "Running censys"
python3 /opt/tools/censys-subdomain-finder/censys_subdomain_finder.py $1 | tee -a $1.txt

#running github-subdomains.py
echo "Running Gthub-subdomains.py"
python3 /opt/tools/subdomain-enum/github-subdomains.py -t $github_subdomains_token -d $1 | sort -u >> $1.txt
sleep 5
python3 /opt/tools/subdomain-enum/github-subdomains.py -t $github_subdomains_token -d $1 | sort -u >> $1.txt
sleep 5
python3 /opt/tools/subdomain-enum/github-subdomains.py -t $github_subdomains_token -d $1 | sort -u >> $1.txt

#running rapiddns
curl -s "https://rapiddns.io/subdomain/$domain?full=1" | grep -oP '_blank">\K[^<]*' | grep -v http | sort -u | tee -a $1.txt
	

#running bufferover
echo "######Starting bufferover######"
curl -ss https://dns.bufferover.run/dns?q=.$1 | jq '.FDNS_A[]' | sed 's/^\".*.,//g' | sed 's/\"$//g'  | sort -u | tee -a $1.txt

#removing duplicate entries
echo "Removing dupes"
sort -u $1.txt -o all.txt
rm $1.txt

#running shuffledns
echo "#####starting shuffledns#####"
shuffledns -d $1 -list all.txt -r /opt/tools/subdomain-enum/subbrute/resolvers.txt | tee -a bruteforced.txt
cat bruteforced.txt | tee -a all.txt
rm bruteforced.txt

#checking ip's from amass
echo "#####checking ip's alive#####"
amass enum -active -d all.txt -ip | tee -a ips.txt
cat ips.txt | awk '{print $1}' | tee -a op.txt
cat op.txt | sort -u | tee -a all.txt
rm op.txt

#running massdns 
echo "#####running massdns#####"
massdns -r /opt/tools/subdomain-enum/subbrute/resolvers.txt -t A -o S -w output.txt all.txt 
cat output.txt | cut -d" " -f3 | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | tee -a ips.txt


#removing duplicate entries
sort -u all.txt -o all.txt 

#checking for alive domains
echo "Checking for alive domains...."
cat all.txt | httprobe --prefer-https >> httprobe.txt
cat all.txt | httpx -title -content-length -status-code | tee -a httpx.txt

rm output.txt


#formatting the data to json
#cat alive.txt | python -c "import sys; import json; print (json.dumps({'domains':list(sys.stdin)}))" > alive.json
#cat domains.txt | python -c "import sys; import json; print (json.dumps({'domains':list(sys.stdin)}))" > domains.json








