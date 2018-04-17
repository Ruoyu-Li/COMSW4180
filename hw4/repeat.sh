#!/bin/bash
# command line args are <number of times send get> <sleepinterval between gets>
cnt=1
max=$1
sleepinterval=$2

# send get to www.example.com max times
# sleeping sleepinterval seconds between each
# the response is saved to index.html.<number> files, these
# are immediately removed each time
while [ $cnt -le $max ]
do
    echo $cnt
    wget www.example.com
    ((cnt++))
    echo "retrieved webpage, removing index.html files"
    rm index.html*
    sleep $sleepinterval
done
echo "done"