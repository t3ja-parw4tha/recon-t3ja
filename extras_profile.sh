#!/bin/bash

wafDetect(){
  #wafw00f
  wafw00f -i $dir/live_subdomains.txt -o $dir/waf.txt
}

corsDetect(){
  #corsy
  python3 ~/tools/Corsy/corsy.py -i $dir/live_subdomains.txt -o $dir/corsy.json
}


mkdir scripts
mkdir scriptsresponse
mkdir endpoints
mkdir responsebody
mkdir headers

jsep()
{
response(){
echo "Gathering Response"       
        for x in $(cat alive.txt)
do
        NAME=$(echo $x | awk -F/ '{print $3}')
        curl -X GET -H "X-Forwarded-For: evil.com" $x -I > "headers/$NAME" 
        curl -s -X GET -H "X-Forwarded-For: evil.com" -L $x > "responsebody/$NAME"
done
}

jsfinder(){
echo "Gathering JS Files"       
for x in $(ls "responsebody")
do
        printf "\n\n${RED}$x${NC}\n\n"
        END_POINTS=$(cat "responsebody/$x" | grep -Eoi "src=\"[^>]+></script>" | cut -d '"' -f 2)
        for end_point in $END_POINTS
        do
                len=$(echo $end_point | grep "http" | wc -c)
                mkdir "scriptsresponse/$x/" > /dev/null 2>&1
                URL=$end_point
                if [ $len == 0 ]
                then
                        URL="https://$x$end_point"
                fi
                file=$(basename $end_point)
                curl -X GET $URL -L > "scriptsresponse/$x/$file"
                echo $URL >> "scripts/$x"
        done
done
}

endpoints()
{
echo "Gathering Endpoints"
for domain in $(ls scriptsresponse)
do
        #looping through files in each domain
        mkdir endpoints/$domain
        for file in $(ls scriptsresponse/$domain)
        do
                ruby /opt/tools/content-discovery/JS/relative-url-extractor/extract.rb scriptsresponse/$domain/$file >> endpoints/$domain/$file 
        done
done

}
response
jsfinder
endpoints
}
jsep

cat endpoints/*/* | sort -u | tee -a endpoints.txt




for i in $(cat alive.txt);do ffuf -u $i/FUZZ -w ~/tools/dirsearch/db/dicc.txt -mc 200 -t 60 ;done| tee -a ffuf_op.txt








