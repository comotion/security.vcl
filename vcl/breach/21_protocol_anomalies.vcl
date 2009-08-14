sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE rx  ^GET /$
   ## REMOTE_ADDR, 
   # skipped   REMOTE_ADDR rx  ^127\.0\.0\.1$
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE rx  ^GET / HTTP/1.0$
   ## REMOTE_ADDR, 
   # skipped   REMOTE_ADDR rx  ^127\.0\.0\.1$
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "^Apache.*\(internal dummy connection\)$"){
      call sec_sev1;
   }
   ## REQUEST_PROTOCOL, 
   ## Rule: REQUEST_PROTOCOL rx :
   if(req.proto ~ "^"){
      set req.http.X-Sec-RuleInfo = "HTTP/0.9 Request Detected";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleId = "960019";
      call sec_sev1;
   }
   ## &REQUEST_HEADERS, :Host
   # AC Host 
   # skipped  & REQUEST_HEADERS eq Host 0
   ## REQUEST_HEADERS, :Host
   # AC Host 
   ## Rule: REQUEST_HEADERS rx :Host
   # AAA Host
   if(req.http.Host ~ "^$"){
      set req.http.X-Sec-RuleInfo = "Request Missing a Host Header";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/MISSING_HEADER";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleId = "960008";
      call sec_sev1;
   }
   ## &REQUEST_HEADERS, :Accept
   # AC Accept 
   # skipped  & REQUEST_HEADERS eq Accept 0
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD rx :
   if(req.request ~ "^OPTIONS$"){
      call sec_sev1;
   }
   ## REQUEST_HEADERS, :Accept
   # AC Accept 
   ## Rule: REQUEST_HEADERS rx :Accept
   # AAA Accept
   if(req.http.Accept ~ "^$"){
      set req.http.X-Sec-RuleInfo = "Request Missing an Accept Header";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/MISSING_HEADER";
      set req.http.X-Sec-RuleId = "960015";
      # chained rule
   }
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD rx :
   if(req.request ~ "^OPTIONS$"){
      call sec_sev1;
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
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/MISSING_HEADER";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleId = "960009";
      call sec_sev1;
   }
   ## &REQUEST_HEADERS, :Content-Type
   # AC Content-Type 
   # skipped  & REQUEST_HEADERS eq Content-Type 0
   ## REQUEST_HEADERS, :Content-Length
   # AC Content-Length 
   ## Rule: REQUEST_HEADERS rx :Content-Length
   # AAA Content-Length
   if(req.http.Content-Length ~ "^0$"){
      call sec_sev1;
   }
   ## REQUEST_HEADERS, :Host
   # AC Host 
   ## Rule: REQUEST_HEADERS rx :Host
   # AAA Host
   if(req.http.Host ~ "^[\d\.]+$"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "Host header is a numeric IP address";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/IP_HOST";
      set req.http.X-Sec-RuleId = "960017";
      call sec_sev1;
   }
   ## RESPONSE_STATUS, 
   # skipped   RESPONSE_STATUS rx  ^
   ## WEBSERVER_ERROR_LOG, 
   # skipped   WEBSERVER_ERROR_LOG rx  !
}

