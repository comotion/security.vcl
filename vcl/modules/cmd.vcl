
# For now
sub sec_cmd_sev1 {
        set req.http.X-SEC-Severity = "1";
        call sec_handler;
}


sub vcl_recv {
        set req.http.X-SEC-Module =  "cmd";

# Should it be "wget%20", "wget " or "wget\s+"  ?
# "=cmd\W+" or "=cmd.+" is the best I can think of at the moment
# What about "=cmd(\%20| )" or... ?

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&|%7C%7C)wget.+") {
                set req.http.X-SEC-RuleName = "Common command in URL: wget";
                set req.http.X-SEC-RuleId   = "1";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to inject a common command name in URL: wget";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&|%7C%7C)curl.+") {
                set req.http.X-SEC-RuleName = "Common command in URL: curl";
                set req.http.X-SEC-RuleId   = "2";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to inject a common command name in URL: curl";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&|%7C%7C)echo.+") {
                set req.http.X-SEC-RuleName = "Common command in URL: curl";
                set req.http.X-SEC-RuleId   = "3";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to inject a common command name in URL: curl";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&|%7C%7C)cat.+") {
                set req.http.X-SEC-RuleName = "Common command in URL: curl";
                set req.http.X-SEC-RuleId   = "4";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to inject a common command name in URL: curl";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&|%7C%7C)cmd.exe.+") {
                set req.http.X-SEC-RuleName = "Common command in URL: cmd.exe";
                set req.http.X-SEC-RuleId   = "5";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to inject a common command name in URL: cmd.exe";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&)nc(.exe)?.+(\-(l|p)?)?") {
                set req.http.X-SEC-RuleName = "Common command in URL: netcat";
                set req.http.X-SEC-RuleId   = "6";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to inject a common command name in URL: netcat";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&)(whoami|who|uptime|last|df).*") {
                set req.http.X-SEC-RuleName = "Unix command in url";
                set req.http.X-SEC-RuleId   = "7";
                set req.http.X-SEC-RuleInfo = "Triggers on unix command in URL: whoami/who/uptime/last/df";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to redirect output to /dev/null
        if (req.url ~ "(>|%3E|-o)+" && req.url ~ "/dev/null") {
                set req.http.X-SEC-RuleName = "Common redirect of command ouput in URL: /dev/null";
                set req.http.X-SEC-RuleId   = "100";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to redirect command output in URL: /dev/null";
                call sec_cmd_sev1;
        }
}
