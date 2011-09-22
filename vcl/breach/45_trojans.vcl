sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "root\.exe"){
      set req.http.X-Sec-RuleInfo = "Backdoor access";
      set req.http.X-Sec-RuleName = "MALICIOUS_SOFTWARE/TROJAN";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-01";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A7";
      set req.http.X-Sec-RuleName = "PCI/5.1.1";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950921";
      call sec_default_handler;
   }
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  (?:<title>[^<]*?(?:\b(?:(?:c(?:ehennemden|gi-telnet)|gamma web shell)\b|imhabirligi phpftp)|(?:r(?:emote explorer|57shell)|aventis klasvayv|zehir)\b|\.::(?:news remote php shell injection::\.| rhtools\b)|ph(?:p(?:(?: commander|-terminal)\b|remoteview)|vayv)|myshell)|\b(?:(?:(?:microsoft windows\b.{0,10}?\bversion\b.{0,20}?\(c\) copyright 1985-.{0,10}?\bmicrosoft corp|ntdaddy v1\.9 - obzerve \| fux0r inc)\.|(?:www\.sanalteror\.org - indexer and read|haxplor)er|php(?:konsole| shell)|c99shell)\b|aventgrup\.<br>|drwxr))
}

