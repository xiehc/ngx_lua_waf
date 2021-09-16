#!/bin/bash

cat /opt/ourpalm/logs/waf/*|awk '{print $1}'|perl -ne 'if($_ =~ /(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)/ ) {print $_}'|sort  |uniq -c |sort -n|perl -ne 'if($_ =~ /\s+(\d+)\s+(.*)/ ) {if ($1>1) {print "$2\n"}}' > /etc/nginx/waf/ngx_lua_waf/wafconf/banip
