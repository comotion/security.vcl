
# For now
sub sec_sql_sev1 {
        set req.http.X-SEC-Severity = "1";
        call sec_handler;
}


sub vcl_recv {
        set req.http.X-SEC-Module =  "sql";

        # Checks if someone tries to use SQL statement in URL: SELECT FROM
        if (req.url ~ "(?i).+SELECT.+FROM") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: SELECT FROM";
                set req.http.X-SEC-RuleId   = "1";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: SELECT FROM";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: UNION SELECT
        if (req.url ~ "(?i).+UNION\s+SELECT") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: UNION SELECT";
                set req.http.X-SEC-RuleId   = "2";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: UNION SELECT";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: UPDATE SET
        if (req.url ~ "(?i).+UPDATE.+SET") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: UPDATE SET";
                set req.http.X-SEC-RuleId   = "3";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: UPDATE SET";
                call sec_sql_sev1;
        }
   
        # Checks if someone tries to use SQL statement in URL: INSERT INTO
        if (req.url ~ "(?i).+INSERT.+INTO") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: INSERT INTO";
                set req.http.X-SEC-RuleId   = "4";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: INSERT INTO";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: DELETE FROM
        if (req.url ~ "(?i).+DELETE.+FROM") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: DELETE FROM";
                set req.http.X-SEC-RuleId   = "5";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: DELETE FROM";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: ASCII SELECT
        if (req.url ~ "(?i).+ASCII\(.+SELECT") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: ASCII SELECT";
                set req.http.X-SEC-RuleId   = "6";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: ASCII SELECT";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: DROP TABLE
        if (req.url ~ "(?i).+DROP.+TABLE") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: DROP TABLE";
                set req.http.X-SEC-RuleId   = "7";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: DROP TABLE";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: DROP DATABASE
        if (req.url ~ "(?i).+DROP.+DATABASE") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: DROP DATABASE";
                set req.http.X-SEC-RuleId   = "8";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: DROP DATABASE";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: SELECT VERSION
        if (req.url ~ "(?i).+SELECT.+VERSION") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: SELECT VERSION";
                set req.http.X-SEC-RuleId   = "9";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: SELECT VERSION";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: SHOW CURDATE/CURTIME
        if (req.url ~ "(?i).+SHOW.+CUR(DATE|TIME)") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: SHOW CURDATE/CURTIME";
                set req.http.X-SEC-RuleId   = "10";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: SHOW CURDATE/CURTIME";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: SELECT SUBSTR
        if (req.url ~ "(?i).+SELECT.+SUBSTR") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: SELECT SUBSTR";
                set req.http.X-SEC-RuleId   = "11";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: SELECT SUBSTR";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: SELECT INSTR
        if (req.url ~ "(?i).+SELECT.+INSTR") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: SELECT INSTR";
                set req.http.X-SEC-RuleId   = "12";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: SELECT INSTR";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: SHOW CHARACTER SET
        if (req.url ~ "(?i).+SHOW.+CHARACTER.+SET") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: SHOW CHARACTER SET";
                set req.http.X-SEC-RuleId   = "13";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: SHOW CHARACTER SET";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: BULK INSERT
        if (req.url ~ "(?i).+BULK.+INSERT") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: BULK INSERT";
                set req.http.X-SEC-RuleId   = "14";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: BULK INSERT";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: INSERT VALUES
        if (req.url ~ "(?i).+INSERT.+VALUES") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: INSERT VALUES";
                set req.http.X-SEC-RuleId   = "15";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: INSERT VALUES";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: MySQL Comments /* */
        if (req.url ~ "(?i).+\%2F\%2A.+\%2A\%2F") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: Comments";
                set req.http.X-SEC-RuleId   = "16";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: Comments";
                call sec_sql_sev1;
        }

        # Checks if someone tries to use SQL statement in URL: SELEC CONCAT
        if (req.url ~ "(?i).+SELECT.+CONCAT") {
                set req.http.X-SEC-RuleName = "SQL Injection Attempt: SELECT CONCAT";
                set req.http.X-SEC-RuleId   = "17";
                set req.http.X-SEC-RuleInfo = "Checks if someone tries to use SQL statement in URL: SELECT CONCAT";
                call sec_sql_sev1;
        }

}
