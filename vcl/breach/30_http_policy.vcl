sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD rx :
   if(req.request ~ "^(((POS|GE)T|OPTIONS|HEAD))$"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Method is not allowed by policy";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "POLICY/METHOD_NOT_ALLOWED";
      set req.http.X-Sec-RuleId = "960032";
      call sec_sev1;
   }
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD rx :
   if(req.request ~ "^(get|head|propfind|options)$"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Request content type is not allowed by policy";
      set req.http.X-Sec-RuleName = "POLICY/ENCODING_NOT_ALLOWED";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleId = "960010";
      # chained rule
   }
   ## REQUEST_HEADERS, :Content-Type
   # AC Content-Type 
   ## Rule: REQUEST_HEADERS rx :Content-Type
   # AAA Content-Type
   if(req.http.Content-Type ~ "(^(application\/x-www-form-urlencoded(;(\s?charset\s?=\s?[\w\d\-]{1,18})?)??$|multipart/form-data;)|text/xml)"){
      call sec_sev1;
   }
   ## REQUEST_PROTOCOL, 
   ## Rule: REQUEST_PROTOCOL rx :
   if(req.proto ~ "^HTTP/(0\.9|1\.[01])$"){
      set req.http.X-Sec-Return = "505";
      set req.http.X-Sec-RuleInfo = "HTTP protocol version is not allowed by policy";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "POLICY/PROTOCOL_NOT_ALLOWED";
      set req.http.X-Sec-RuleId = "960034";
      call sec_sev1;
   }
   ## REQUEST_BASENAME, 
   ## Rule: REQUEST_BASENAME rx :
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, :Content-Encoding
   # AC Content-Encoding 
   ## Rule: REQUEST_HEADERS rx :Content-Encoding
   # AAA Content-Encoding
   if(req.http.Content-Encoding ~ "^Identity$"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "ModSecurity does not support content encodings";
      set req.http.X-Sec-Severity = "3";
      set req.http.X-Sec-RuleId = "960902";
      call sec_sev1;
   }
   ## RESPONSE_HEADERS, :Content-Encoding
   # AC Content-Encoding 
   # skipped   RESPONSE_HEADERS rx Content-Encoding ^Identity$
   ## &GLOBAL, :alerted_960903_compression
   # AC alerted_960903_compression 
   # skipped  & GLOBAL eq alerted_960903_compression 0
}

