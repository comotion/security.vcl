
# For now
sub sec_request_sev1 {
   set req.http.X-SEC-Severity = "1";
   call sec_handler;
}

# Checks if someone tries use a blacklisted request method
sub vcl_recv {
   set req.http.X-SEC-Module =  "request";


   if ( req.request == "PUT"
#     || req.request == "POST"
      || req.request == "TRACE"
      || req.request == "OPTIONS"
      || req.request == "CONNECT"
      || req.request == "DELETE") {
                set req.http.X-SEC-RuleName = "Blocked request methods";
                set req.http.X-SEC-RuleId   = "1";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries use a blacklisted request method";
                call sec_request_sev1;
   }

   # request whitelist - this is strict and will break any non-conformant app
   if (req.request != "GET"
      && req.request != "POST"
      && req.request != "HEAD"){
                set req.http.X-SEC-RuleName = "Not in method whitelist";
                set req.http.X-SEC-RuleId   = "2";
      call sec_request_sev1;
   }
   if (req.proto ~ "^HTTP/1.1$" && !req.http.host) {
      set req.http.X-SEC-RuleName = "HTTP/1.1 no host header";
      set req.http.X-SEC-RuleId = "3";
   }
   #if (req.proto ~ "^HTTP/1.0$" && req.http.) {A
   # awaiting vmod to iterate over headers...
}
