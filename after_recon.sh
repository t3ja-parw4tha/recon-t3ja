##!/bin/bash

if [ ! -d "wayback-data" ]; then
	mkdir wayback-data
fi

mkdir wayback-data
echo -e "\e[91m-------------------gau Scan Started--------------------------------------------------\e[0m"
cat httprobe.txt | xargs -n1 -P4 -I{} gau -subs {} | tee -a wayback-data/gau.txt

echo -e "\e[91m-------------------hakrawler Started-------------------------------------------------\e[0m"
cat all.txt | hakrawler -depth 3 -plain | tee wayback-data/hakrawler.txt

echo -e "\e[91m-------------------waybackurls Scan Started------------------------------------------\e[0m"
cat all.txt | xargs -n1 -P4 -I{} waybackurls {} | tee -a wayback-data/wb.txt
  
# Grouping endpoints
cat wayback-data/gau.txt wayback-data/wb.txt wayback-data/hakrawler.txt | sort -u > wayback-data/waybackurls.txt
rm wayback-data/gau.txt
rm wayback-data/wb.txt
rm wayback-data/hakrawler.txt

cat wayback-data/waybackurls.txt | unfurl --unique keys | tee -a  $CUR_DIR/wayback-data/unique_keys.txt
cat wayback-data/waybackurls.txt | grep -P "\w+\.js(\?|$) | sort -u" | tee -a $CUR_DIR/wayback-data/jsurls.txt
cat wayback-data/waybackurls.txt | grep -P "\w+\.php(\?|$) | sort -u" | tee -a  $CUR_DIR/wayback-data/phpurls.txt
cat wayback-data/waybackurls.txt | grep -P "\w+\.aspx(\?|$) | sort -u" | tee -a  $CUR_DIR/wayback-data/aspxurls.txt
cat wayback-data/waybackurls.txt | grep -P "\w+\.jsp(\?|$) | sort -u" | tee -a  $CUR_DIR/wayback-data/jspurls.txt


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



mkdir js
cat $CUR_DIR/httprobe.txt | subjs| tee -a js/js.txt
cd js
cat js.txt | concurl -c 5
cat ../waybackurls.txt |egrep -iv '\.json'|grep -iE '\.js'|antiburl|awk '{print $4}' | xargs -I %% bash -c 'python3 /opt/tools/secretfinder/SecretFinder.py -i %% -o cli' 2> /dev/null | tee -a secrets.txt
cat $CUR_DIR/js.txt |egrep -iv '\.json'|grep -iE '\.js'|antiburl|awk '{print $4}' | xargs -I %% bash -c 'python3 /opt/tools/secretfinder/SecretFinder.py -i %% -o cli' 2> /dev/null | tee -a secrets.txt
cat js.txt | while read url;do python3 /opt/tools/content-discovery/JS/LinkFinder/linkfinder.py -d -i $url -o cli;done > exdpoints.txt
cd



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

