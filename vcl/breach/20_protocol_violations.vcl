sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE rx  ^(?:(?:[a-z]{3,10}\s+(?:\w{3,7}?://[\w\-\./]*(?::\d+)?)?/[^?#]*(?:\?[^#\s]*)?(?:#[\S]*)?|connect (?:\d{1,3}\.){3}\d{1,3}\.?(?::\d+)?|options \*)\s+[\w\./]+|get /[^?#]*(?:\?[^#\s]*)?(?:#[\S]*)?)$
   ## WEBSERVER_ERROR_LOG, 
   # skipped   WEBSERVER_ERROR_LOG contains  Invalid URI in request
   ## FILES_NAMES, 
   ## Rule: FILES_NAMES rx :
   ## FILES, 
   ## Rule: FILES rx :
   ## REQBODY_ERROR, 
   # skipped   REQBODY_ERROR eq  0
   ## MULTIPART_STRICT_ERROR, 
   # skipped   MULTIPART_STRICT_ERROR eq  0
   ## MULTIPART_UNMATCHED_BOUNDARY, 
   # skipped   MULTIPART_UNMATCHED_BOUNDARY eq  0
   ## REQUEST_HEADERS, :Content-Length
   # AC Content-Length 
   ## Rule: REQUEST_HEADERS rx :Content-Length
   # AAA Content-Length
   if(req.http.Content-Length ~ "^\d+$"){
      set req.http.X-Sec-RuleInfo = "Content-Length HTTP header is not numeric";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/INVALID_HREQ";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-26";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.13";
      set req.http.X-Sec-RuleName = "RULE_MATURITY/9";
      set req.http.X-Sec-RuleName = "RULE_ACCURACY/9";
      set req.http.X-Sec-RuleName = "https://www.owasp.org/index.php/ModSecurity_CRS_RuleID-%{tx.id}";
      set req.http.X-Sec-RuleId = "960016";
      call sec_default_handler;
   }
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD rx :
   if(req.request ~ "^(?:GET|HEAD)$"){
      set req.http.X-Sec-RuleInfo = "GET or HEAD requests with bodies";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/EVASION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-21";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A7";
      set req.http.X-Sec-RuleName = "PCI/6.5.10";
      set req.http.X-Sec-RuleName = "RULE_MATURITY/9";
      set req.http.X-Sec-RuleName = "RULE_ACCURACY/9";
      set req.http.X-Sec-RuleName = "https://www.owasp.org/index.php/ModSecurity_CRS_RuleID-%{tx.id}";
      set req.http.X-Sec-RuleName = "http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.3";
      set req.http.X-Sec-RuleId = "960011";
      # chained rule
   }
   ## REQUEST_HEADERS, :Content-Length
   # AC Content-Length 
   ## Rule: REQUEST_HEADERS rx :Content-Length
   # AAA Content-Length
   if(req.http.Content-Length ~ "^0?$"){
      call sec_default_handler;
   }
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD rx :
   if(req.request ~ "^POST$"){
      set req.http.X-Sec-RuleInfo = "POST request must have a Content-Length header";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/EVASION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-21";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A7";
      set req.http.X-Sec-RuleName = "PCI/6.5.10";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleName = "RULE_MATURITY/9";
      set req.http.X-Sec-RuleName = "RULE_ACCURACY/9";
      set req.http.X-Sec-RuleName = "https://www.owasp.org/index.php/ModSecurity_CRS_RuleID-%{tx.id}";
      set req.http.X-Sec-RuleName = "http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9.5";
      set req.http.X-Sec-RuleId = "960012";
      # chained rule
   }
   ## &REQUEST_HEADERS, :Content-Length
   # AC Content-Length 
   # skipped  & REQUEST_HEADERS eq Content-Length 0
   ## REQUEST_HEADERS, :Content-Encoding
   # AC Content-Encoding 
   ## Rule: REQUEST_HEADERS rx :Content-Encoding
   # AAA Content-Encoding
   if(req.http.Content-Encoding ~ "^Identity$"){
      set req.http.X-Sec-RuleInfo = "ModSecurity does not support content encodings";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleName = "RULE_MATURITY/9";
      set req.http.X-Sec-RuleName = "RULE_ACCURACY/9";
      set req.http.X-Sec-RuleName = "https://www.owasp.org/index.php/ModSecurity_CRS_RuleID-%{tx.id}";
      set req.http.X-Sec-RuleName = "http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.5";
      set req.http.X-Sec-RuleId = "960902";
      call sec_default_handler;
   }
   ## REQUEST_HEADERS, :Expect
   # AC Expect 
   ## Rule: REQUEST_HEADERS rx :Expect
   # AAA Expect
   if(req.http.Expect ~ "100-continue"){
      set req.http.X-Sec-RuleInfo = "Expect Header Not Allowed for HTTP 1.0.";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleName = "RULE_MATURITY/4";
      set req.http.X-Sec-RuleName = "RULE_ACCURACY/8";
      set req.http.X-Sec-RuleName = "https://www.owasp.org/index.php/ModSecurity_CRS_RuleID-%{tx.id}";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/INVALID_HREQ";
      set req.http.X-Sec-RuleName = "http://www.bad-behavior.ioerror.us/documentation/how-it-works/";
      set req.http.X-Sec-RuleId = "960022";
      # chained rule
   }
   ## REQUEST_PROTOCOL, 
   # skipped   REQUEST_PROTOCOL streq  HTTP/1.0
   ## &REQUEST_HEADERS, :Pragma
   # AC Pragma 
   # skipped  & REQUEST_HEADERS eq Pragma 1
   ## &REQUEST_HEADERS, :Cache-Control
   # AC Cache-Control 
   # skipped  & REQUEST_HEADERS eq Cache-Control 0
   ## REQUEST_PROTOCOL, 
   # skipped   REQUEST_PROTOCOL streq  HTTP/1.1
   ## REQUEST_HEADERS, :Range
   # AC Range 
   ## Rule: REQUEST_HEADERS beginsWith :Range
   # AAA Range
   if(req.http.Range ~ "^bytes=0-"){
      set req.http.X-Sec-RuleInfo = "Range: field exists and begins with 0.";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleName = "RULE_MATURITY/5";
      set req.http.X-Sec-RuleName = "RULE_ACCURACY/7";
      set req.http.X-Sec-RuleName = "https://www.owasp.org/index.php/ModSecurity_CRS_RuleID-%{tx.id}";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/INVALID_HREQ";
      set req.http.X-Sec-RuleName = "http://www.bad-behavior.ioerror.us/documentation/how-it-works/";
      set req.http.X-Sec-RuleId = "958291";
      call sec_default_handler;
   }
   ## REQUEST_HEADERS, :Range
   # AC Range 
   ## Rule: REQUEST_HEADERS rx :Range
   # AAA Range
   if(req.http.Range ~ "(\d+)\-(\d+)\,"){
      set req.http.X-Sec-RuleInfo = "Range: Invalid Last Byte Value.";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleName = "RULE_MATURITY/5";
      set req.http.X-Sec-RuleName = "RULE_ACCURACY/7";
      set req.http.X-Sec-RuleName = "https://www.owasp.org/index.php/ModSecurity_CRS_RuleID-%{tx.id}";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/INVALID_HREQ";
      set req.http.X-Sec-RuleName = "http://www.bad-behavior.ioerror.us/documentation/how-it-works/";
      set req.http.X-Sec-RuleId = "958230";
      # chained rule
   }
   ## REQUEST_HEADERS, :Request-Range
   # AC Request-Range 
   ## Rule: REQUEST_HEADERS rx :Request-Range
   # AAA Request-Range
   if(req.http.Request-Range ~ "(\d+)\-(\d+)\,"){
      set req.http.X-Sec-RuleInfo = "Range: Invalid Last Byte Value.";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleName = "RULE_MATURITY/5";
      set req.http.X-Sec-RuleName = "RULE_ACCURACY/7";
      set req.http.X-Sec-RuleName = "https://www.owasp.org/index.php/ModSecurity_CRS_RuleID-%{tx.id}";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/INVALID_HREQ";
      set req.http.X-Sec-RuleName = "http://www.bad-behavior.ioerror.us/documentation/how-it-works/";
      set req.http.X-Sec-RuleId = "958230";
      # chained rule
   }
   ## TX, :2
   # AC 2 
   # skipped   TX ge 2 %{tx.1}
   ## REQUEST_HEADERS, :Range
   # AC Range 
   ## Rule: REQUEST_HEADERS rx :Range
   # AAA Range
   if(req.http.Range ~ "^bytes=(\d+)?\-(\d+)?\,\s?(\d+)?\-(\d+)?\,\s?(\d+)?\-(\d+)?\,\s?(\d+)?\-(\d+)?\,\s?(\d+)?\-(\d+)?\,"){
      set req.http.X-Sec-RuleInfo = "Range: Too many fields";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleName = "RULE_MATURITY/5";
      set req.http.X-Sec-RuleName = "RULE_ACCURACY/7";
      set req.http.X-Sec-RuleName = "https://www.owasp.org/index.php/ModSecurity_CRS_RuleID-%{tx.id}";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/INVALID_HREQ";
      set req.http.X-Sec-RuleName = "http://www.bad-behavior.ioerror.us/documentation/how-it-works/";
      set req.http.X-Sec-RuleId = "958231";
      call sec_default_handler;
   }
   ## REQUEST_HEADERS, :Request-Range
   # AC Request-Range 
   ## Rule: REQUEST_HEADERS rx :Request-Range
   # AAA Request-Range
   if(req.http.Request-Range ~ "^bytes=(\d+)?\-(\d+)?\,\s?(\d+)?\-(\d+)?\,\s?(\d+)?\-(\d+)?\,\s?(\d+)?\-(\d+)?\,\s?(\d+)?\-(\d+)?\,"){
      set req.http.X-Sec-RuleInfo = "Range: Too many fields";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleName = "RULE_MATURITY/5";
      set req.http.X-Sec-RuleName = "RULE_ACCURACY/7";
      set req.http.X-Sec-RuleName = "https://www.owasp.org/index.php/ModSecurity_CRS_RuleID-%{tx.id}";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/INVALID_HREQ";
      set req.http.X-Sec-RuleName = "http://www.bad-behavior.ioerror.us/documentation/how-it-works/";
      set req.http.X-Sec-RuleId = "958231";
      call sec_default_handler;
   }
   ## REQUEST_HEADERS, :Connection
   # AC Connection 
   ## Rule: REQUEST_HEADERS rx :Connection
   # AAA Connection
   if(req.http.Connection ~ "\b(keep-alive|close),\s?(keep-alive|close)\b"){
      set req.http.X-Sec-RuleInfo = "Multiple/Conflicting Connection Header Data Found.";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/INVALID_HREQ";
      set req.http.X-Sec-RuleName = "RULE_MATURITY/5";
      set req.http.X-Sec-RuleName = "RULE_ACCURACY/8";
      set req.http.X-Sec-RuleName = "https://www.owasp.org/index.php/ModSecurity_CRS_RuleID-%{tx.id}";
      set req.http.X-Sec-RuleName = "http://www.bad-behavior.ioerror.us/documentation/how-it-works/";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "958295";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\%((?!$|\W)|[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})"){
      set req.http.X-Sec-RuleInfo = "URL Encoding Abuse Attack Attempt";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/EVASION";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "950107";
      # chained rule
   }
   ## REQUEST_URI, 
   # skipped   REQUEST_URI validateUrlEncoding  
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\%((?!$|\W)|[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})"){
      set req.http.X-Sec-RuleInfo = "Multiple URL Encoding Detected";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/EVASION";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "950109";
      call sec_default_handler;
   }
   ## REQUEST_HEADERS, :Content-Type
   # AC Content-Type 
   ## Rule: REQUEST_HEADERS rx :Content-Type
   # AAA Content-Type
   if(req.http.Content-Type ~ "^(application\/x-www-form-urlencoded|text\/xml)(?:;(?:\s?charset\s?=\s?[\w\d\-]{1,18})?)??$"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "URL Encoding Abuse Attack Attempt";
      set req.http.X-Sec-RuleName = "PROTOCOL_VIOLATION/EVASION";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "950108";
      # chained rule
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \%((?!$|\W)|[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \%((?!$|\W)|[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY validateUrlEncoding  
   ## XML, :/*
   # AC /* 
   # skipped   XML validateUrlEncoding /* 
   ## TX, :CRS_VALIDATE_UTF8_ENCODING
   # AC CRS_VALIDATE_UTF8_ENCODING 
   # skipped   TX eq CRS_VALIDATE_UTF8_ENCODING 1
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME validateUtf8Encoding :
   if(req.url validateUtf8Encoding ""){
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS validateUtf8Encoding :
   if(req.url validateUtf8Encoding ""){
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES validateUtf8Encoding :
   if(req.url validateUtf8Encoding ""){
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\%u[fF]{2}[0-9a-fA-F]{2}"){
      set req.http.X-Sec-RuleInfo = "Unicode Full/Half Width Abuse Attack Attempt";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleName = "http://www.kb.cert.org/vuls/id/739224";
      set req.http.X-Sec-RuleId = "950116";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \%u[fF]{2}[0-9a-fA-F]{2}
   ## ARGS, 
   # skipped   ARGS validateByteRange  1-255
   ## ARGS_NAMES, 
   # skipped   ARGS_NAMES validateByteRange  1-255
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS validateByteRange  1-255
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   # skipped !  REQUEST_HEADERS validateByteRange Referer 1-255
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## REQUEST_URI, 
   # skipped   REQUEST_URI validateByteRange  32-126
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY validateByteRange  32-126
   ## REQUEST_HEADERS_NAMES, 
   # skipped   REQUEST_HEADERS_NAMES validateByteRange  32-126
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS validateByteRange  32-126
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   # skipped !  REQUEST_HEADERS validateByteRange Referer 32-126
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   # skipped   TX validateByteRange HPP_DATA 32-126
}

