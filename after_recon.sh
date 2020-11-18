##!/bin/bash


##usage - ./after_recon.sh all.txt  (where all.txt is obtained from recon.sh)

if [ ! -d "wayback-data" ]; then
	mkdir wayback-data
fi

if [ ! -d "dirsearch" ]; then
	mkdir dirsearch
fi
for script in $(cat httprobe.txt);do python3 /opt/tools/dir-fuzz/dirsearch/dirsearch.py -e * -u $script -i 200,402,403,302,500 | tee -a dirsearch/$script.txt



echo -e "\e[91m-------------------gau Scan Started--------------------------------------------------\e[0m"
cat httprobe.txt | gau | tee -a wayback-data/gau.txt

echo -e "\e[91m-------------------hakrawler Started-------------------------------------------------\e[0m"
cat httprobe.txt | hakrawler -depth 3 -plain | tee wayback-data/hakrawler.txt

echo -e "\e[91m-------------------waybackurls Scan Started------------------------------------------\e[0m"
waybackurls $1 | tee -a wayback-data/wb.txt
  
# Grouping endpoints
cat wayback-data/gau.txt wayback-data/wb.txt wayback-data/hakrawler.txt | sort -u > wayback-data/waybackurls.txt
rm wayback-data/gau.txt
rm wayback-data/wb.txt
rm wayback-data/hakrawler.txt

cat wayback-data/waybackurls.txt | unfurl --unique keys | tee -a  wayback-data/unique_keys.txt
cat wayback-data/waybackurls.txt | grep -P "\w+\.js(\?|$)" | sort -u | tee -a wayback-data/js.txt
cat wayback-data/waybackurls.txt | grep -P "\w+\.php(\?|$)" | sort -u | tee -a  wayback-data/phpurls.txt
cat wayback-data/waybackurls.txt | grep -P "\w+\.aspx(\?|$)" | sort -u | tee -a  wayback-data/aspxurls.txt
cat wayback-data/waybackurls.txt | grep -P "\w+\.jsp(\?|$)" | sort -u | tee -a  wayback-data/jspurls.txt
cat wayback-data/waybackurls.txt | kxss | sed 's/=.*/=/'| sed 's/URL: //'| dalfox pipe -b https://teja2510.xss.ht


scanSuspect(){
  echo -e "\e[91m-------------------looking for vulnerable endpoints----------------------------------\e[0m"
  mkdir paramlist
  cat wayback-data/waybackurls.txt | gf redirect > paramlist/redirect.txt
  cat wayback-data/waybackurls.txt | gf ssrf > paramlist/ssrf.txt
  cat wayback-data/waybackurls.txt | gf rce > paramlist/rce.txt
  cat wayback-data/waybackurls.txt | gf idor > paramlist/idor.txt
  cat wayback-data/waybackurls.txt | gf sqli > paramlist/sqli.txt
  cat wayback-data/waybackurls.txt | gf lfi > paramlist/lfi.txt
  cat wayback-data/waybackurls.txt | gf ssti > paramlist/ssti.txt
  cat wayback-data/waybackurls.txt | gf debug_logic > paramlist/debug_logic.txt
  cat wayback-data/waybackurls.txt | gf interestingsubs > paramlist/interestingsubs.txt
  cat wayback-data/waybackurls.txt | grep "=" | tee domainParam.txt

  #this is the worst way!!!
  #ls $dir/paramlist/ > $dir/gf-endpoints.txt && cat $dir/gf-endpoints.txt | while read endpoints; do echo $endpoints; cat $dir/paramlist/$endpoints; done
  #echo -e \e[91m-------------------Gf patters Scan Completed------------------------------------------------\e[0m"
}



if [ ! -d "js" ]; then
	mkdir js
fi

cat httprobe.txt | subjs | tee -a js/js.txt
cat wayback-data/js.txt >> js/js.txt
cat js/js.txt | sort -u > js/jsurls.txt
rm js/js.txt
rm wayback-data/js.txt

cd js
cat jsurls.txt | concurl -c 5
cat ../wayback-data/waybackurls.txt |egrep -iv '\.json'|grep -iE '\.js'|antiburl|awk '{print $4}' | xargs -I %% bash -c 'python3 /opt/tools/secretfinder/SecretFinder.py -i %% -o cli' 2> /dev/null | tee -a secrets.txt
cat jsurls.txt |egrep -iv '\.json'|grep -iE '\.js'|anti-burl|awk '{print $4}' | xargs -I %% bash -c 'python3 /opt/tools/secretfinder/SecretFinder.py -i %% -o cli' 2> /dev/null | tee -a secrets.txt
cat jsurls.txt | while read url;do python3 /opt/tools/content-discovery/JS/LinkFinder/linkfinder.py -d -i $url -o cli;done > endpoints.txt
cd ..

echo -e "\e[91m-------------------creating custom wordlists------------------------------------------\e[0m"
for script in $(cat js/jsurls.txt);do python3 ~/teja/scripts/getjswords.py $script | sort -u |tee -a jswordlist.txt ;done

mkdir fuzzresults
for script in $(cat httprobe.txt);do ffuf -c -w jswordlist.txt -u $script/FUZZ -mc 200,402,403,302,500 -maxtime 300 -timeout 2 | tee -a fuzzresults/$script.txt | tnotify "fuzzing is done"

python3 ~/tools/theHarvester/theHarvester.py -d mypaytm.com -l 500 -b google

python3 ~/tools/GitDorker/GitDorker.py -tf ~/tools/GitDorker/TOKENSFILE -q $1 -d ~/tools/GitDorker/dorks/alldorks.txt -o gitdorks.txt

nuclei_auto(){
        echo "Starting Nuclei"
        mkdir nuclei_op
        nuclei -l httprobe.txt -t "/opt/tools/nuclei-templates/cves/" -c 60 -o nuclei_op/cves.txt
        nuclei -l httprobe.txt -t "/opt/tools/nuclei-templates/files/" -c 60 -o nuclei_op/files.txt
        nuclei -l httprobe.txt -t "/opt/tools/nuclei-templates/panels/" -c 60 -o nuclei_op/panels.txt
        nuclei -l httprobe.txt -t "/opt/tools/nuclei-templates/security-misconfiguration/" -c 60 -o nuclei_op/security-misconfiguration.txt
        nuclei -l httprobe.txt -t "/opt/tools/nuclei-templates/technologies/" -c 60 -o nuclei_op/technologies.txt
        nuclei -l httprobe.txt -t "/opt/tools/nuclei-templates/tokens/" -c 60 -o nuclei_op/tokens.txt
        nuclei -l httprobe.txt -t "/opt/tools/nuclei-templates/vulnerabilities/" -c 60 -o nuclei_op/vulnerabilities.txt
}



