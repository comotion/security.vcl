
# For now
sub sec_request_sev1 {
        set req.http.X-SEC-Severity = "1";
        call sec_handler;
}

sub vcl_recv {
        set req.http.X-SEC-Module =  "request";

#sub vcl_recv {
    # Checks if someone tries use a blacklisted request method
    if ( req.request == "PUT"
#     || req.request == "POST"
      || req.request == "TRACE"
      || req.request == "OPTIONS"
      || req.request == "CONNECT"
      || req.request == "DELETE") {
                set req.http.X-SEC-RuleName = "Blocked Requestmethods";
                set req.http.X-SEC-RuleId   = "1";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries use a blacklisted request method";
                call sec_request_sev1;
    }
}
