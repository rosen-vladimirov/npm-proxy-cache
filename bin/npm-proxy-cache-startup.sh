#! /bin/sh

PIDFILE=$1
/home/ubuntu/npm-proxy-cache/node_modules/npm-proxy-cache/bin/npm-proxy-cache -s /home/ubuntu/npm-proxy-cache/cached_data -p 8085 --ttl 3600 -e --internal-port 8086 &
PID=$!
echo $PID>$PIDFILE
