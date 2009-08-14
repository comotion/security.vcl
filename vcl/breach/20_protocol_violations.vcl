sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE rx  ^(([a-z]{3,10}\s+(\w{3,7}?://[\w\-\./]*(:\d+)?)?/[^?#]*(\?[^#\s]*)?(#[\S]*)?|connect (\d{1,3}\.){3}\d{1,3}\.?(:\d+)?|options \*)\s+[\w\./]+|get /[^?#]*(\?[^#\s]*)?(#[\S]*)?)$
   ## REQUEST_HEADERS, :'/(Content-Length|Transfer-Encoding)/'
   # AA 
   ## Rule: REQUEST_HEADERS rx :Content-Length|Transfer-Encoding
   # AAA Content-Length|Transfer-Encoding
   if(req.http.Content-Length ~ ","){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "HTTP Request Smuggling Attack.";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/REQUEST_SMUGGLING";
      set req.http.X-Sec-Severity = "1";
      set req.http.X-Sec-RuleId = "950012";
      call sec_sev1;
   }
   if(req.http.Transfer-Encoding ~ ","){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "HTTP Request Smuggling Attack.";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/REQUEST_SMUGGLING";
      set req.http.X-Sec-Severity = "1";
      set req.http.X-Sec-RuleId = "950012";
      call sec_sev1;
   }
   ## REQBODY_PROCESSOR_ERROR, 
   # skipped   REQBODY_PROCESSOR_ERROR eq  0
   ## REQUEST_HEADERS, :Content-Length
   # AC Content-Length 
   ## Rule: REQUEST_HEADERS rx :Content-Length
   # AAA Content-Length
   if(req.http.Content-Length ~ "^\d+$"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "Content-Length HTTP header is not numeric";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/INVALID_HREQ";
      set req.http.X-Sec-RuleId = "960016";
      call sec_sev1;
   }
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD rx :
   if(req.request ~ "^(GET|HEAD)$"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "GET or HEAD requests with bodies";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/EVASION";
      set req.http.X-Sec-RuleId = "960011";
      # chained rule
   }
   ## REQUEST_HEADERS, :Content-Length
   # AC Content-Length 
   ## Rule: REQUEST_HEADERS rx :Content-Length
   # AAA Content-Length
   if(req.http.Content-Length ~ "^0?$"){
      call sec_sev1;
   }
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD rx :
   if(req.request ~ "^POST$"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "POST request must have a Content-Length header";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/EVASION";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleId = "960012";
      # chained rule
   }
   ## &REQUEST_HEADERS, :Content-Length
   # AC Content-Length 
   # skipped  & REQUEST_HEADERS eq Content-Length 0
   ## REQUEST_HEADERS, :Transfer-Encoding
   # AC Transfer-Encoding 
   ## Rule: REQUEST_HEADERS rx :Transfer-Encoding
   # AAA Transfer-Encoding
   if(req.http.Transfer-Encoding ~ "^$"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "ModSecurity does not support transfer encodings";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/EVASION";
      set req.http.X-Sec-Severity = "3";
      set req.http.X-Sec-RuleId = "960013";
      call sec_sev1;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "%25u[fF]{2}[0-9a-fA-F]{2}"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "Unicode Full/Half Width Abuse Attack Attempt";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleId = "950116";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "%25u[fF]{2}[0-9a-fA-F]{2}"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "Unicode Full/Half Width Abuse Attack Attempt";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleId = "950116";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "%25u[fF]{2}[0-9a-fA-F]{2}"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "Unicode Full/Half Width Abuse Attack Attempt";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleId = "950116";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  %25u[fF]{2}[0-9a-fA-F]{2}
   ## XML, :/*|
   # AC /*| 
   # skipped   XML rx /*| %25u[fF]{2}[0-9a-fA-F]{2}
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "%25u[fF]{2}[0-9a-fA-F]{2}"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "Unicode Full/Half Width Abuse Attack Attempt";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleId = "950116";
      call sec_sev1;
   }
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "^"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "Proxy access attempt";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/PROXY_ACCESS";
      set req.http.X-Sec-RuleId = "960014";
      call sec_sev1;
   }
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME validateByteRange  1-255
   ## REQUEST_HEADERS_NAMES, 
   # skipped   REQUEST_HEADERS_NAMES validateByteRange  1-255
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS validateByteRange  1-255
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   # skipped !  REQUEST_HEADERS validateByteRange Referer 1-255
   ## ARGS, 
   # skipped   ARGS validateByteRange  1-255
   ## ARGS_NAMES, 
   # skipped   ARGS_NAMES validateByteRange  1-255
   ## REQUEST_HEADERS, :Referer
   # AC Referer 
   # skipped   REQUEST_HEADERS validateByteRange Referer 1-255
}

