sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## &REQUEST_HEADERS, :Host
   # AC Host 
   # skipped  & REQUEST_HEADERS eq Host 0
   ## REQUEST_HEADERS, :Host
   # AC Host 
   ## Rule: REQUEST_HEADERS rx :Host
   # AAA Host
   if(req.http.Host ~ "^$"){
      set req.http.X-Sec-RuleInfo = "Request Missing a Host Header";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/MISSING_HEADER_HOST";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-21";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A7";
      set req.http.X-Sec-RuleName = "PCI/6.5.10";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "960008";
      call sec_default_handler;
   }
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD rx :
   if(req.request ~ "^OPTIONS$"){
      set req.http.X-Sec-RuleInfo = "Request Missing an Accept Header";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/MISSING_HEADER_ACCEPT";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-21";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A7";
      set req.http.X-Sec-RuleName = "PCI/6.5.10";
      set req.http.X-Sec-RuleId = "960015";
      # chained rule
   }
   ## &REQUEST_HEADERS, :Accept
   # AC Accept 
   # skipped  & REQUEST_HEADERS eq Accept 0
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD rx :
   if(req.request ~ "^OPTIONS$"){
      set req.http.X-Sec-RuleInfo = "Request Has an Empty Accept Header";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/MISSING_HEADER_ACCEPT";
      set req.http.X-Sec-RuleId = "960021";
      # chained rule
   }
   ## REQUEST_HEADERS, :Accept
   # AC Accept 
   ## Rule: REQUEST_HEADERS rx :Accept
   # AAA Accept
   if(req.http.Accept ~ "^$"){
      call sec_default_handler;
   }
   ## &REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   # skipped  & REQUEST_HEADERS eq User-Agent 0
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "^$"){
      set req.http.X-Sec-RuleInfo = "Request Missing a User Agent Header";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/MISSING_HEADER_UA";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-21";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A7";
      set req.http.X-Sec-RuleName = "PCI/6.5.10";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "960009";
      call sec_default_handler;
   }
   ## &REQUEST_HEADERS, :Content-Type
   # AC Content-Type 
   # skipped  & REQUEST_HEADERS eq Content-Type 0
   ## REQUEST_HEADERS, :Content-Length
   # AC Content-Length 
   ## Rule: REQUEST_HEADERS rx :Content-Length
   # AAA Content-Length
   if(req.http.Content-Length ~ "^0$"){
      call sec_default_handler;
   }
   ## REQUEST_HEADERS, :Host
   # AC Host 
   ## Rule: REQUEST_HEADERS rx :Host
   # AAA Host
   if(req.http.Host ~ "^[\d.:]+$"){
      set req.http.X-Sec-RuleInfo = "Host header is a numeric IP address";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/IP_HOST";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-21";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A7";
      set req.http.X-Sec-RuleName = "PCI/6.5.10";
      set req.http.X-Sec-RuleName = "http://technet.microsoft.com/en-us/magazine/2005.01.hackerbasher.aspx";
      set req.http.X-Sec-RuleId = "960017";
      call sec_default_handler;
   }
}

