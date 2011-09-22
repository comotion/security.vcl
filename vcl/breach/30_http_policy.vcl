sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD within :
   if((%{tx.allowed_methods}) ~ "req.request"){
      set req.http.X-Sec-RuleInfo = "Method is not allowed by policy";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "POLICY/METHOD_NOT_ALLOWED";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/RE1";
      set req.http.X-Sec-RuleName = "PCI/12.1";
      set req.http.X-Sec-RuleId = "960032";
      call sec_default_handler;
   }
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD rx :
   if(req.request ~ "^(?:GET|HEAD|PROPFIND|OPTIONS)$"){
      set req.http.X-Sec-RuleInfo = "Request content type is not allowed by policy";
      set req.http.X-Sec-RuleName = "POLICY/ENCODING_NOT_ALLOWED";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-20";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/EE2";
      set req.http.X-Sec-RuleName = "PCI/12.1";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleId = "960010";
      # chained rule
   }
   ## REQUEST_HEADERS, :Content-Type
   # AC Content-Type 
   ## Rule: REQUEST_HEADERS rx :Content-Type
   # AAA Content-Type
   if(req.http.Content-Type ~ "^([^;\s]+)"){
      # chained rule
   }
   ## TX, :0
   # AC 0 
   ## Rule: TX within :0
   ## REQUEST_PROTOCOL, 
   ## Rule: REQUEST_PROTOCOL within :
   if((%{tx.allowed_http_versions}) ~ "req.proto"){
      set req.http.X-Sec-RuleInfo = "HTTP protocol version is not allowed by policy";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "POLICY/PROTOCOL_NOT_ALLOWED";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-21";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.10";
      set req.http.X-Sec-RuleId = "960034";
      call sec_default_handler;
   }
   ## REQUEST_BASENAME, 
   ## Rule: REQUEST_BASENAME rx :
   ## TX, :EXTENSION
   # AC EXTENSION 
   ## Rule: TX within :EXTENSION
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## TX, :HEADER_NAME
   # AC HEADER_NAME 
   ## Rule: TX within :HEADER_NAME
}

