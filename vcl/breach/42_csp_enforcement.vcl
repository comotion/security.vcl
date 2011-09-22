sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME streq  %{tx.csp_report_uri}
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  ({\"csp-report\":.*blocked-uri\":\"(.*?)\".*violated-directive\":\"(.*)\")
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "(?i:mozilla.*firefox)"){
      set req.http.X-Sec-RuleId = "960002";
      # chained rule
   }
   ## TX, :CSP_REPORT_ONLY
   # AC CSP_REPORT_ONLY 
   # skipped   TX eq CSP_REPORT_ONLY 1
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "(?i:mozilla.*firefox)"){
      set req.http.X-Sec-RuleId = "960003";
      # chained rule
   }
   ## TX, :CSP_REPORT_ONLY
   # AC CSP_REPORT_ONLY 
   # skipped   TX eq CSP_REPORT_ONLY 0
}

