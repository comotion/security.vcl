
# For now
sub sec_xss_sev1 {
        set req.http.X-SEC-Severity = "1";
        call sec_handler;
}

sub vcl_recv {
        set req.http.X-SEC-Module =  "xss";

#        # Checks if someone tries to inject java/vb script for XSS in URL
#        if (req.url ~ "<?(java|vb)?script>?.*<.+\/script>?") {
#                set req.http.X-SEC-RuleName = "Cross Site Scripting Attempt";
#                set req.http.X-SEC-RuleId   = "1";
#                set req.http.X-SEC-RuleInfo = "Checks if someone tries to inject java/vb script for XSS in URL";
#                call sec_xss_sev1;
#        }

        # Checks if someone tries to inject java/vb script for XSS in URL
        if (req.url ~ "(<|\%3C)?(java|vb)?script(>|\%3E).*(<|\%3C).*\/script(>|\%3E)?") {
                set req.http.X-SEC-RuleName = "Cross Site Scripting Attempt";
                set req.http.X-SEC-RuleId   = "1";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to inject java/vb script for XSS in URL";
                call sec_xss_sev1;
        }

        # Checks if someone tries to inject java/vb script for XSS in URL
        if (req.url ~ "(java|vb)?script:") {
                set req.http.X-SEC-RuleName = "Cross Site Scripting Attempt: (java|vb)script:";
                set req.http.X-SEC-RuleId   = "2";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to inject java/vb script for XSS in URL";
                call sec_xss_sev1;
        }

        # Checks if someone tries to inject java/vb script for XSS in URL
        if (req.url ~ "\(.*javascript.*\)") {
                set req.http.X-SEC-RuleName = "Cross Site Scripting Attempt: (javascript)";
                set req.http.X-SEC-RuleId   = "3";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to inject java/vb script for XSS in URL";
                call sec_xss_sev1;
        }

        # Checks if someone tries to inject java/vb script for XSS in URL
        if (req.url ~ "\(.*vbscript.*\)") {
                set req.http.X-SEC-RuleName = "Cross Site Scripting Attempt: (vbscript)";
                set req.http.X-SEC-RuleId   = "4";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to inject java/vb script for XSS in URL";
                call sec_xss_sev1;
        }

        # Checks if someone tries to inject java/vb script for XSS in URL
        if (req.url ~ ":?.*url\(") {
                set req.http.X-SEC-RuleName = "Cross Site Scripting Attempt: :url(";
                set req.http.X-SEC-RuleId   = "5";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to inject java/vb script for XSS in URL";
                call sec_xss_sev1;
        }
}
