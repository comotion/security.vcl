
# For now
sub sec_sql_sev1 {
        set req.http.X-SEC-Severity = "1";
        call sec_handler;
}


sub vcl_recv {
        set req.http.X-SEC-Module =  "sql";

        # Checks if someone tries to use SQL statement in URL: SELECT FROM
        if (req.url ~ ".+SELECT.+FROM") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: SELECT FROM";
                set req.http.X-SEC-RuleId   = "1";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: SELECT FROM";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: UNION SELECT
        if (req.url ~ ".+UNION\s+SELECT") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: UNION SELECT";
                set req.http.X-SEC-RuleId   = "2";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: UNION SELECT";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: UPDATE SET
        if (req.url ~ ".+UPDATE.+SET") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: UPDATE SET";
                set req.http.X-SEC-RuleId   = "3";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: UPDATE SET";
                call sec_sql_sev1;
        }
   
        # Checks if someone tries to use SQL statement in URL: INSERT INTO
        if (req.url ~ ".+INSERT.+INTO") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: INSERT INTO";
                set req.http.X-SEC-RuleId   = "4";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: INSERT INTO";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: DELETE FROM
        if (req.url ~ ".+DELETE.+FROM") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: DELETE FROM";
                set req.http.X-SEC-RuleId   = "5";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: DELETE FROM";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: ASCII SELECT
        if (req.url ~ ".+ASCII\(.+SELECT") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: ASCII SELECT";
                set req.http.X-SEC-RuleId   = "6";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: ASCII SELECT";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: DROP TABLE
        if (req.url ~ ".+DROP.+TABLE") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: DROP TABLE";
                set req.http.X-SEC-RuleId   = "7";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: DROP TABLE";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: DROP DATABASE
        if (req.url ~ ".+DROP.+DATABASE") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: DROP DATABASE";
                set req.http.X-SEC-RuleId   = "8";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: DROP DATABASE";
                call sec_sql_sev1;
        }

}
