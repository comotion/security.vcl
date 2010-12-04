
# For now
sub sec_contentencoding_sev1 {
        set req.http.X-SEC-Severity = "1";
        call sec_handler;
}

sub vcl_recv {
        set req.http.X-SEC-Module =  "contentencoding";

        # Security.vcl does not support content encodings
        if(req.http.Content-Encoding ~ "!^Identity$"){
                set req.http.X-SEC-RuleName = "Inbound compressed content";
                set req.http.X-SEC-RuleId   = "1";
                set req.http.X-SEC-RuleInfo = "Blocks inbound compressed content";
                call sec_contentencoding_sev1;
        }
}
