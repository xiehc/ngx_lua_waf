RulePath = "/etc/nginx/waf/ngx_lua_waf/wafconf/"
BanIpFile = "/etc/nginx/waf/ngx_lua_waf/wafconf/banip"
NotBanIplist={"127.0.0.1","192.168.0.1"}
attacklog = "on"
logdir = "/opt/logs/waf/"
UrlDeny="on"
Redirect="on"
CookieMatch="on"
postMatch="on" 
refererMatch="on"
whiteModule="on" 
black_fileExt={"php","jsp"}
bypassIPlist={"127.0.0.1"}
ipBlocklist={"1.0.0.1"}
CCDeny="off"
CCrate="10000/60"
html=[[
<html>
<head>
        <title>please go away</title>
</head>
<body>
     please go away
</body>
</html>
]]
