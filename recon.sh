
##!/bin/bash

if [ ! -d "third-levels" ]; then
	mkdir third-levels
fi

if [ ! -d "functions" ]; then
	mkdir functions
fi


GREEN="\033[1;32m"
BLUE="\033[1;36m"
RED="\033[1;31m"
RESET="\033[0m"

#running findomain
echo -e "${RED}Running findomain......${RESET}"
findomain -t $1 -u $1.txt

#starting sublist3r
echo -e "${RED}Running Sublist3r.......${RESET}"
python /opt/tools/subdomain-enum/Sublist3r/sublist3r.py -d $1 -v -o subs.txt
cat subs.txt | tee -a $1.txt
rm subs.txt

#running amass
echo -e "${RED}Running Amass.......${RESET}"
amass enum --passive -d $1 | tee -a $1.txt

#running assetfinder
echo -e "${RED}Running assetfinder.......${RESET}"
assetfinder --subs-only $1 | tee -a $1.txt

#running subfinder
echo -e "${RED}Running Subfinder.......${RESET}"
subfinder -d $1 -recursive | tee -a $1.txt

#running censys
echo -e "${RED}Running censys......${RESET}"
python3 /opt/tools/subdomain-enum/censys-subdomain-finder/censys_subdomain_finder.py $1 | tee -a $1.txt

#running chaos
echo -e "${RED}Running Chaos......${RESET}"
chaos -d $1 -silent | tee -a $1.txt

#removing duplicate entries
echo -e "${BLUE}Removing dupes.......${RESET}"
sort -u $1.txt -o all.txt
rm $1.txt
cd functions

	curl -s "https://crt.sh/?q=%25.$1&output=json"| jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u | grep -o "\w.*$1" > crt_$1.txt
	echo -e "${GREEN}[+] Crt.sh Over => $(wc -l crt_$1.txt|awk '{ print $1}')${RESET}"

	curl -s "http://web.archive.org/cdx/search/cdx?url=*.$1/*&output=text&fl=original&collapse=urlkey" | sort | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' |sort -u > warchive_$1.txt
	echo -e "${GREEN}[+] Web.Archive.org Over => $(wc -l warchive_$1.txt|awk '{ print $1}')${RESET}"

	curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u > dnsbuffer_$1.txt
	curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u >> dnsbuffer_$1.txt 
	curl -s "https://tls.bufferover.run/dns?q=.$1" | jq -r .Results 2>/dev/null | cut -d ',' -f3 |grep -o "\w.*$1"| sort -u >> dnsbuffer_$1.txt 
	sort -u dnsbuffer_$1.txt -o dnsbuffer_$1.txt
	echo -e "${GREEN}[+] Dns.bufferover.run Over => $(wc -l dnsbuffer_$1.txt|awk '{ print $1}')${RESET}"

	curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1"|jq -r '.subdomains' 2>/dev/null |grep -o "\w.*$1" > threatcrowd_$1.txt
	echo -e "${GREEN}[+] Threatcrowd.org Over => $(wc -l threatcrowd_$1.txt|awk '{ print $1}')${RESET}"

	curl -s "https://api.hackertarget.com/hostsearch/?q=$1"|grep -o "\w.*$1"> hackertarget_$1.txt
	echo -e "${GREEN}[+] Hackertarget.com Over => $(wc -l hackertarget_$1.txt | awk '{ print $1}')${RESET}"


	curl -s "https://certspotter.com/api/v0/certs?domain=$1" | jq -r '.[].dns_names[]' 2>/dev/null | grep -o "\w.*$1" | sort -u > certspotter_$1.txt
	echo -e "${GREEN}[+] Certspotter.com Over => $(wc -l certspotter_$1.txt | awk '{ print $1}')${RESET}"

	curl -s "https://jldc.me/anubis/subdomains/$1" | jq -r '.' 2>/dev/null | grep -o "\w.*$1" > anubisdb_$1.txt
	echo -e "${GREEN}[+] Anubis-DB(jonlu.ca) Over => $(wc -l anubisdb_$1.txt|awk '{ print $1}')${RESET}"

	curl -s "https://www.virustotal.com/ui/domains/$1/subdomains?limit=40"|jq -r '.' 2>/dev/null |grep id|grep -o "\w.*$1"|cut -d '"' -f3|egrep -v " " > virustotal_$1.txt
	echo -e "${GREEN}[+] Virustotal Over => $(wc -l virustotal_$1.txt|awk '{ print $1}')${RESET}"

	curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns"|jq '.passive_dns[].hostname' 2>/dev/null |grep -o "\w.*$1"|sort -u > alienvault_$1.txt
	echo -e "${GREEN}[+] Alienvault(otx) Over => $(wc -l alienvault_$1.txt|awk '{ print $1}')${RESET}"

	curl -s "https://urlscan.io/api/v1/search/?q=domain:$1"|jq '.results[].page.domain' 2>/dev/null |grep -o "\w.*$1"|sort -u > urlscan_$1.txt
	echo -e "${GREEN}[+] Urlscan.io Over => $(wc -l urlscan_$1.txt|awk '{ print $1}')${RESET}"


	curl -s "https://api.threatminer.org/v2/domain.php?q=$1&rt=5" | jq -r '.results[]' 2>/dev/null |grep -o "\w.*$1"|sort -u > threatminer_$1.txt
	echo -e "${GREEN}[+] Threatminer Over => $(wc -l threatminer_$1.txt|awk '{ print $1}')${RESET}"

	 curl -s "https://ctsearch.entrust.com/api/v1/certificates?fields=subjectDN&domain=$1&includeExpired=false&exactMatch=false&limit=5000" | jq -r '.[].subjectDN' 2>/dev/null |sed 's/cn=//g'|grep -o "\w.*$1"|sort -u > entrust_$1.txt
	echo -e "${GREEN}[+] Entrust.com Over => $(wc -l entrust_$1.txt|awk '{ print $1}')${RESET}"


    curl -s "https://riddler.io/search/exportcsv?q=pld:$1"| grep -o "\w.*$1"|awk -F, '{print $6}'|sort -u > riddler_$1.txt
	#curl -s "https://riddler.io/search/exportcsv?q=pld:$1"|cut -d "," -f6|grep $1|sort -u >riddler_$1.txt
	echo -e "${GREEN}[+] Riddler.io Over => $(wc -l riddler_$1.txt|awk '{ print $1}')${RESET}"


	cmdtoken=$(curl -ILs https://dnsdumpster.com | grep csrftoken | cut -d " " -f2 | cut -d "=" -f2 | tr -d ";")
	curl -s --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$cmdtoken&targetip=$1" --cookie "csrftoken=$cmdtoken; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com > dnsdumpster.html

	cat dnsdumpster.html|grep "https://api.hackertarget.com/httpheaders"|grep -o "\w.*$1"|cut -d "/" -f7|sort -u > dnsdumper_$1.txt
	rm dnsdumpster.html
	echo -e "${GREEN}[+] Dnsdumpster Over => $(wc -l dnsdumper_$1.txt|awk '{ print $1}')${RESET}"

	curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep -oaEi "https?://[^\"\\'> ]+" | grep $1 | cut -d "/" -f3 | sort -u >rapiddns_$1.txt
	echo -e "${GREEN}[+] Rapiddns Over => $(wc -l rapiddns_$1.txt|awk '{ print $1}')${RESET}"


cd ../
cat functions/*.txt >> all.txt
rm -rf functions

sort -u all.txt -o all.txt

#compiling 3rd level domains
cat all.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u >> third-level.txt

echo -e "${BLUE}Gathering full third-level domains with assetfinder,sublist3r...${RESET}"
for domain in $(cat third-level.txt); do sublist3r -d $domain -o third-levels/$domain.txt;done
for domain in $(cat third-level.txt); do assetfinder --subs-only $domain | tee -a third-levels/$domain.txt;done
cat third-levels/*.txt | sort -u >> all.txt

#running shuffledns
echo -e "${BLUE}#####starting shuffledns#####${RESET}"
shuffledns -d $1 -list all.txt -r /opt/tools/subdomain-enum/subbrute/resolvers.txt | tee -a bruteforced.txt
cat bruteforced.txt | tee -a all.txt
rm bruteforced.txt

#checking ip's from amass
echo -e "${BLUE}#####checking ip's alive#####${RESET}"
amass enum -active -d all.txt -ip | tee -a ips.txt
cat ips.txt | awk '{print $1}' | tee -a op.txt
cat op.txt | sort -u | tee -a all.txt
rm op.txt

#running massdns 
echo -e "${BLUE}#####running massdns#####${RESET}"
massdns -r /opt/tools/subdomain-enum/subbrute/resolvers.txt -t A -o S -w output.txt all.txt 
cat output.txt | cut -d" " -f3 | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | tee -a ips.txt


#removing duplicate entries
sort -u all.txt -o all.txt 

#checking for alive domains
echo -e "${BLUE}Checking for alive domains....${RESET}"
cat all.txt | httprobe --prefer-https >> httprobe.txt
cat all.txt | httpx -title -content-length -status-code | tee -a httpx.txt

rm -rf third-levels

#formatting the data to json
#cat alive.txt | python -c "import sys; import json; print (json.dumps({'domains':list(sys.stdin)}))" > alive.json
#cat domains.txt | python -c "import sys; import json; print (json.dumps({'domains':list(sys.stdin)}))" > domains.json








