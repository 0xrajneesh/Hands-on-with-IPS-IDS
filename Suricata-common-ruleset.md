# Suricata ruleset(Common Use case)

## 1) Outbound curl/wget User-Agent
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"HTTP client using curl/wget user-agent";
  flow:established,to_server;
  http.user_agent; content:"curl/"; nocase; pcre:"/^(?:curl|Wget)/i";
  classtype:policy-violation; sid:1000001; rev:1;
)
```


Use to flag scripted exfil/tests using curl or wget.

## 2) HTTP request for phpMyAdmin
```
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"Attempt to access phpMyAdmin";
  flow:established,to_server;
  http.uri; content:"/phpmyadmin"; nocase;
  classtype:web-application-attack; sid:1000002; rev:1;
)
```


Catches probes hitting common admin panels.

## 3) Basic SQLi pattern in URI/body
```
alert http any any -> $HOME_NET any (
  msg:"Possible SQLi: ' OR 1=1";
  flow:established,to_server;
  http.request_line; pcre:"/'\s*OR\s*1=1/i";
  classtype:web-application-attack; sid:1000003; rev:1;
)
```
Detects a classic SQL injection test string.

## 4) Reflected XSS marker

```
alert http any any -> $HOME_NET any (
  msg:"Possible XSS attempt: <script in request";
  flow:established,to_server;
  http.uri; content:"<script"; nocase;
  classtype:web-application-attack; sid:1000004; rev:1;
)
```
Flags obvious cross-site scripting probes.

## 5) Directory traversal to /etc/passwd
```
alert http any any -> $HOME_NET any (
  msg:"LFI/Traversal attempt to /etc/passwd";
  flow:established,to_server;
  http.uri; content:"../"; http.uri; content:"/etc/passwd"; nocase;
  classtype:web-application-attack; sid:1000005; rev:1;
)
```

Catches Unix file read via traversal.

## 6) Remote File Inclusion probe
```alert http any any -> $HOME_NET any (
  msg:"RFI attempt with http:// in parameter";
  flow:established,to_server;
  http.uri; pcre:"/\?(?:[^=]+)=https?:\/\//Ui";
  classtype:web-application-attack; sid:1000006; rev:1;
)
```
Detects parameters that pull external URLs.

## 7) Command injection hints
```
alert http any any -> $HOME_NET any (
  msg:"Possible command injection tokens (;|&&|`)";
  flow:established,to_server;
  http.uri; pcre:"/[;&`]\s*(?:id|whoami|wget|curl)/Ui";
  classtype:web-application-attack; sid:1000007; rev:1;
)
```
Flags shell metacharacters plus common commands.

## 8) Access to .git/ directory
```
alert http any any -> $HOME_NET any (
  msg:"Exposed .git directory access";
  flow:established,to_server;
  http.uri; content:"/.git/"; nocase;
  classtype:web-application-attack; sid:1000008; rev:1;
)
```

Warns when VCS metadata is web-exposed.

## 9) WordPress brute-force (401 bursts)
```
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"Likely login brute-force: repeated 401s";
  flow:established,to_client;
  http.response_line; content:"401";
  detection_filter:track by_dst, count 10, seconds 60;
  classtype:attempted-user; sid:1000009; rev:1;
)
```

Triggers when a client gets many auth failures quickly.

## 10) Spike in 500 errors
```
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"Server instability: repeated 500 responses";
  flow:established,to_client;
  http.response_line; content:"500";
  detection_filter:track by_src, count 20, seconds 60;
  classtype:generic-activity; sid:1000010; rev:1;
)
```

Helps catch app crashes or active fuzzing.

## 11) TLS SNI contains .onion
```
alert tls $HOME_NET any -> $EXTERNAL_NET any (
  msg:"TLS SNI indicates Tor (.onion)";
  flow:established,to_server;
  tls.sni; content:".onion"; nocase;
  classtype:policy-violation; sid:1000011; rev:1;
)
```

Flags possible Tor hidden service access.

## 12) Deprecated SSLv3
```
alert tls $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Deprecated SSLv3 negotiated";
  flow:established;
  tls.version:SSLv3;
  classtype:protocol-command-decode; sid:1000012; rev:1;
)
```

Detects insecure legacy SSL usage.

## 13) Deprecated TLS 1.0
```
alert tls $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Deprecated TLS 1.0 negotiated";
  flow:established;
  tls.version:TLS1.0;
  classtype:protocol-command-decode; sid:1000013; rev:1;
)
```

Identifies TLS 1.0 sessions for remediation.

## 14) Long DNS label (exfil hint)
```
alert dns $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Very long DNS label in query";
  dns.query; pcre:"/(^|\.)[A-Za-z0-9\-]{50,}\./";
  classtype:potential-ly-dangerous; sid:1000014; rev:1;
)
```

Heuristics for DNS tunneling/exfil.

## 15) Suspicious TXT-like data in HTTP (Base64-ish)
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Long base64-like string in URI";
  flow:established,to_server;
  http.uri; pcre:"/[A-Za-z0-9+\/]{100,}={0,2}/";
  classtype:potential-ly-dangerous; sid:1000015; rev:1;
)
```

Catches encoded payloads in requests.

## 16) SSH protocol v1 banner
```
alert tcp $HOME_NET any -> $EXTERNAL_NET 22 (
  msg:"Legacy SSH-1 client usage";
  flow:to_server,established;
  content:"SSH-1."; depth:6;
  classtype:protocol-command-decode; sid:1000016; rev:1;
)
```

Flags obsolete SSHv1 connections.

## 17) Outbound SSH to Internet
```
alert tcp $HOME_NET any -> $EXTERNAL_NET 22 (
  msg:"Outbound SSH from internal host";
  flags:S,12; flow:stateless;
  classtype:policy-violation; sid:1000017; rev:1;
)
```

Notifies when internal users initiate SSH outside (policy).

## 18) RDP exposure to Internet
```
alert tcp $HOME_NET any -> $EXTERNAL_NET 3389 (
  msg:"Outbound RDP from internal host";
  flags:S,12; flow:stateless;
  classtype:policy-violation; sid:1000018; rev:1;
)
```

Detects RDP leaving your network.

## 19) SMB ADMIN$ access attempt
```
alert smb any any -> $HOME_NET any (
  msg:"SMB access to ADMIN$ share";
  flow:established,to_server;
  smb.path; content:"\\ADMIN$"; nocase;
  classtype:attempted-admin; sid:1000019; rev:1;
)
```

Flags administrative share usage.

## 20) Executable over SMB (MZ header)
```
alert smb any any -> $HOME_NET any (
  msg:"Executable file transfer over SMB";
  flow:established,to_client;
  file_data; content:"MZ"; depth:2;
  classtype:policy-violation; sid:1000020; rev:1;
)
```

Spot PE downloads via SMB shares.

## 21) FTP cleartext password seen
```
alert ftp $HOME_NET any -> $EXTERNAL_NET 21 (
  msg:"FTP cleartext AUTH (USER/PASS)";
  flow:established,to_server;
  ftp.command; pcre:"/^(USER|PASS)\s+/i";
  classtype:policy-violation; sid:1000021; rev:1;
)
```

Highlights insecure FTP authentication.

## 22) FTP anonymous login
```
alert ftp $HOME_NET any -> $EXTERNAL_NET 21 (
  msg:"FTP anonymous login attempt";
  flow:established,to_server;
  ftp.command; content:"USER "; nocase; pcre:"/USER\s+anonymous/i";
  classtype:attempted-recon; sid:1000022; rev:1;
)
```

Detects anonymous FTP access.

## 23) Telnet usage
```
alert tcp $HOME_NET any -> $EXTERNAL_NET 23 (
  msg:"Telnet usage detected";
  flags:S,12; flow:stateless;
  classtype:policy-violation; sid:1000023; rev:1;
)
```

Warns on legacy plaintext remote shell.

## 24) NTP monlist keyword
```
alert udp $EXTERNAL_NET any -> $HOME_NET 123 (
  msg:"NTP monlist probe (legacy amplification)";
  content:"monlist"; nocase;
  classtype:attempted-recon; sid:1000024; rev:1;
)
```

Catches old‐school NTP reflection checks.

## 25) SNMP community 'public'
```
alert udp $EXTERNAL_NET any -> $HOME_NET 161 (
  msg:"SNMP community 'public' access";
  content:"public"; nocase;
  classtype:attempted-recon; sid:1000025; rev:1;
)
```

Flags default/guessable SNMP communities.

## 26) ICMP oversized echo (exfil hint)
```
alert icmp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Large ICMP echo payload";
  itype:8; dsize:>1000;
  classtype:potential-ly-dangerous; sid:1000026; rev:1;
)
```

Detects unusually large pings that may carry data.

## 27) HTTP download of .exe
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"HTTP request for .exe";
  flow:established,to_server;
  http.uri; endswith:".exe"; nocase;
  classtype:policy-violation; sid:1000027; rev:1;
)
```

Flags executable pulls over HTTP.

## 28) Basic Auth header present
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"HTTP Authorization: Basic in request";
  flow:established,to_server;
  http.header; content:"Authorization: Basic"; nocase;
  classtype:policy-violation; sid:1000028; rev:1;
)
```

Highlights plaintext credential patterns.

## 29) Cloud metadata service access
```
alert http $HOME_NET any -> 169.254.169.254 any (
  msg:"Access to cloud instance metadata service";
  flow:established,to_server;
  classtype:policy-violation; sid:1000029; rev:1;
)
```

Detects potential SSRF/credential harvesting to IMDS.

## 30) Response contains /etc/passwd markers
```
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"Sensitive data leak: passwd contents in response";
  flow:established,to_client;
  file_data; content:"root:x:0:0:"; nocase;
  classtype:data-loss; sid:1000030; rev:1;
)
```

Catches classic Unix account file leakage.

## 31) Repeated 403s to same client
```
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"Multiple 403 Forbidden responses to client";
  flow:established,to_client;
  http.response_line; content:"403";
  detection_filter:track by_dst, count 10, seconds 60;
  classtype:attempted-recon; sid:1000031; rev:1;
)
```

Heuristic for path brute-forcing.

## 32) WebDAV method usage
```
alert http any any -> $HOME_NET any (
  msg:"WebDAV method used (PROPFIND/PUT)";
  flow:established,to_server;
  http.method; pcre:"/^(PROPFIND|PUT|MKCOL|MOVE|COPY|DELETE)$/";
  classtype:policy-violation; sid:1000032; rev:1;
)
```

Flags WebDAV operations often disabled by policy.

## 33) Path traversal pattern ..%2f
alert http any any -> $HOME_NET any (
  msg:"Encoded traversal ..%2f in URI";
  flow:established,to_server;
  http.uri; content:"..%2f"; nocase;
  classtype:web-application-attack; sid:1000033; rev:1;
)


Detects encoded traversal attempts.

34) PHP remote shell indicators
alert http any any -> $HOME_NET any (
  msg:"Potential PHP webshell indicator (cmd= whoami)";
  flow:established,to_server;
  http.uri; pcre:"/(?:^|[?&])cmd=(?:id|whoami|uname)/Ui";
  classtype:web-application-attack; sid:1000034; rev:1;
)


Catches simple webshell command parameters.

35) SSRF via file:// or gopher://
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Possible SSRF using file:// or gopher://";
  flow:established,to_server;
  http.uri; pcre:"/(file|gopher):\/\//i";
  classtype:web-application-attack; sid:1000035; rev:1;
)


Looks for dangerous URL schemes in requests.

36) Kubernetes API path exposure (unauth HTTP)
alert http $EXTERNAL_NET any -> $HOME_NET 8080 (
  msg:"K8s API path over plain HTTP";
  flow:established,to_server;
  http.uri; content:"/api/v1/namespaces"; nocase;
  classtype:policy-violation; sid:1000036; rev:1;
)


Flags kube-api served over non-TLS (legacy 8080).

37) Office macro-enabled doc download
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Downloading macro-enabled Office file (.docm/.xlsm)";
  flow:established,to_server;
  http.uri; pcre:"/\.(docm|xlsm|pptm)(?:\?|$)/i";
  classtype:policy-violation; sid:1000037; rev:1;
)


Warns on macro-enabled file pulls.

38) PE file in HTTP response (magic MZ)
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"PE binary in HTTP response (MZ header)";
  flow:established,to_client;
  file_data; content:"MZ"; depth:2;
  classtype:policy-violation; sid:1000038; rev:1;
)


Detects executable content delivered over HTTP.

39) Cryptocurrency miner User-Agent
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Mining software user-agent (xmrig)";
  flow:established,to_server;
  http.user_agent; content:"xmrig"; nocase;
  classtype:policy-violation; sid:1000039; rev:1;
)


Spots popular CPU miner traffic.

40) DNS query for RFC1918 names (odd internal leak)
alert dns $HOME_NET any -> $EXTERNAL_NET any (
  msg:"DNS query that looks like RFC1918 address";
  dns.query; pcre:"/^(?:10|127|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)(?:\.[0-9]{1,3}){2}\.?$/";
  classtype:bad-unknown; sid:1000040; rev:1;
)


Flags clients trying to resolve private IPs via public DNS.
