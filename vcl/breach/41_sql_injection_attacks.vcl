sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:\A|[^\d])0x[a-f\d]{3,}[a-f\d]*)+"){
      set req.http.X-Sec-RuleInfo = "SQL Hex Encoding Identified";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981260-2";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:\A|[^\d])0x[a-f\d]{3,}[a-f\d]*)+"){
      set req.http.X-Sec-RuleInfo = "SQL Hex Encoding Identified";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981260-2";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:\A|[^\d])0x[a-f\d]{3,}[a-f\d]*)+"){
      set req.http.X-Sec-RuleInfo = "SQL Hex Encoding Identified";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981260-2";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:\A|[^\d])0x[a-f\d]{3,}[a-f\d]*)+"){
      set req.http.X-Sec-RuleInfo = "SQL Hex Encoding Identified";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981260-2";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:\A|[^\d])0x[a-f\d]{3,}[a-f\d]*)+"){
      set req.http.X-Sec-RuleInfo = "SQL Hex Encoding Identified";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981260-2";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:\A|[^\d])0x[a-f\d]{3,}[a-f\d]*)+
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(\/\*\!?|\*\/|\-\-[\s\r\n\v\f]|(?:--[^-]*-)|([^\-&])#.*[\s\r\n\v\f]|;?\\x00)"){
      set req.http.X-Sec-RuleInfo = "SQL Comment Sequence Detected.";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981231";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(\/\*\!?|\*\/|\-\-[\s\r\n\v\f]|(?:--[^-]*-)|([^\-&])#.*[\s\r\n\v\f]|;?\\x00)"){
      set req.http.X-Sec-RuleInfo = "SQL Comment Sequence Detected.";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981231";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(\/\*\!?|\*\/|\-\-[\s\r\n\v\f]|(?:--[^-]*-)|([^\-&])#.*[\s\r\n\v\f]|;?\\x00)"){
      set req.http.X-Sec-RuleInfo = "SQL Comment Sequence Detected.";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981231";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(\/\*\!?|\*\/|\-\-[\s\r\n\v\f]|(?:--[^-]*-)|([^\-&])#.*[\s\r\n\v\f]|;?\\x00)"){
      set req.http.X-Sec-RuleInfo = "SQL Comment Sequence Detected.";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981231";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(\/\*\!?|\*\/|\-\-[\s\r\n\v\f]|(?:--[^-]*-)|([^\-&])#.*[\s\r\n\v\f]|;?\\x00)"){
      set req.http.X-Sec-RuleInfo = "SQL Comment Sequence Detected.";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981231";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (\/\*\!?|\*\/|\-\-[\s\r\n\v\f]|(?:--[^-]*-)|([^\-&])#.*[\s\r\n\v\f]|;?\\x00)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(^[\"'`´’‘;]+|[\"'`´’‘;]+$)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: Common Injection Testing Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981318";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(^[\"'`´’‘;]+|[\"'`´’‘;]+$)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: Common Injection Testing Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981318";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(^[\"'`´’‘;]+|[\"'`´’‘;]+$)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: Common Injection Testing Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981318";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(^[\"'`´’‘;]+|[\"'`´’‘;]+$)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: Common Injection Testing Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981318";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(^[\"'`´’‘;]+|[\"'`´’‘;]+$)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: Common Injection Testing Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981318";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (^[\"'`´’‘;]+|[\"'`´’‘;]+$)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(\!\=|\&\&|\|\||>>|<<|>=|<=|<>|<=>|xor|rlike|regexp|isnull)|(?:not\s+between\s+0\s+and)|(?:is\s+null)|(like\s+null)|(?:(?:^|\W)in[+\s]*\([\s\d\"]+[^()]*\))|(?:xor|<>|rlike(?:\s+binary)?)|(?:regexp\s+binary))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: SQL Operator Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981319";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(\!\=|\&\&|\|\||>>|<<|>=|<=|<>|<=>|xor|rlike|regexp|isnull)|(?:not\s+between\s+0\s+and)|(?:is\s+null)|(like\s+null)|(?:(?:^|\W)in[+\s]*\([\s\d\"]+[^()]*\))|(?:xor|<>|rlike(?:\s+binary)?)|(?:regexp\s+binary))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: SQL Operator Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981319";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(\!\=|\&\&|\|\||>>|<<|>=|<=|<>|<=>|xor|rlike|regexp|isnull)|(?:not\s+between\s+0\s+and)|(?:is\s+null)|(like\s+null)|(?:(?:^|\W)in[+\s]*\([\s\d\"]+[^()]*\))|(?:xor|<>|rlike(?:\s+binary)?)|(?:regexp\s+binary))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: SQL Operator Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981319";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(\!\=|\&\&|\|\||>>|<<|>=|<=|<>|<=>|xor|rlike|regexp|isnull)|(?:not\s+between\s+0\s+and)|(?:is\s+null)|(like\s+null)|(?:(?:^|\W)in[+\s]*\([\s\d\"]+[^()]*\))|(?:xor|<>|rlike(?:\s+binary)?)|(?:regexp\s+binary))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: SQL Operator Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981319";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(\!\=|\&\&|\|\||>>|<<|>=|<=|<>|<=>|xor|rlike|regexp|isnull)|(?:not\s+between\s+0\s+and)|(?:is\s+null)|(like\s+null)|(?:(?:^|\W)in[+\s]*\([\s\d\"]+[^()]*\))|(?:xor|<>|rlike(?:\s+binary)?)|(?:regexp\s+binary))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: SQL Operator Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981319";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(\!\=|\&\&|\|\||>>|<<|>=|<=|<>|<=>|xor|rlike|regexp|isnull)|(?:not\s+between\s+0\s+and)|(?:is\s+null)|(like\s+null)|(?:(?:^|\W)in[+\s]*\([\s\d\"]+[^()]*\))|(?:xor|<>|rlike(?:\s+binary)?)|(?:regexp\s+binary))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:=|<=>|r?like|sounds\s+like|regexp)([\s'\"`´’‘\(\)]*)?\2|([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'\"`´’‘\(\)]*)?(?!\6)([\d\w]+))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "950901";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:=|<=>|r?like|sounds\s+like|regexp)([\s'\"`´’‘\(\)]*)?\2|([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'\"`´’‘\(\)]*)?(?!\6)([\d\w]+))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "950901";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:=|<=>|r?like|sounds\s+like|regexp)([\s'\"`´’‘\(\)]*)?\2|([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'\"`´’‘\(\)]*)?(?!\6)([\d\w]+))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "950901";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:=|<=>|r?like|sounds\s+like|regexp)([\s'\"`´’‘\(\)]*)?\2|([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'\"`´’‘\(\)]*)?(?!\6)([\d\w]+))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "950901";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:=|<=>|r?like|sounds\s+like|regexp)([\s'\"`´’‘\(\)]*)?\2|([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'\"`´’‘\(\)]*)?(?!\6)([\d\w]+))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "950901";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:=|<=>|r?like|sounds\s+like|regexp)([\s'\"`´’‘\(\)]*)?\2|([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'\"`´’‘\(\)]*)?(?!\6)([\d\w]+))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:m(?:s(?:ysaccessobjects|msysaces|msysobjects|msysqueries|msysrelationships|msysaccessstorage|msysaccessxml|msysmodules|msysmodules2|db)|aster\.\.sysdatabases|ysql\.db)|s(?:ys(?:\.database_name|aux)|chema(?:\W*\(|_name)|qlite(_temp)?_master)|d(?:atabas|b_nam)e\W*\(|information_schema|pg_(catalog|toast)|northwind|tempdb))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: Common DB Names Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981320";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:m(?:s(?:ysaccessobjects|msysaces|msysobjects|msysqueries|msysrelationships|msysaccessstorage|msysaccessxml|msysmodules|msysmodules2|db)|aster\.\.sysdatabases|ysql\.db)|s(?:ys(?:\.database_name|aux)|chema(?:\W*\(|_name)|qlite(_temp)?_master)|d(?:atabas|b_nam)e\W*\(|information_schema|pg_(catalog|toast)|northwind|tempdb))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: Common DB Names Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981320";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:m(?:s(?:ysaccessobjects|msysaces|msysobjects|msysqueries|msysrelationships|msysaccessstorage|msysaccessxml|msysmodules|msysmodules2|db)|aster\.\.sysdatabases|ysql\.db)|s(?:ys(?:\.database_name|aux)|chema(?:\W*\(|_name)|qlite(_temp)?_master)|d(?:atabas|b_nam)e\W*\(|information_schema|pg_(catalog|toast)|northwind|tempdb))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: Common DB Names Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981320";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:m(?:s(?:ysaccessobjects|msysaces|msysobjects|msysqueries|msysrelationships|msysaccessstorage|msysaccessxml|msysmodules|msysmodules2|db)|aster\.\.sysdatabases|ysql\.db)|s(?:ys(?:\.database_name|aux)|chema(?:\W*\(|_name)|qlite(_temp)?_master)|d(?:atabas|b_nam)e\W*\(|information_schema|pg_(catalog|toast)|northwind|tempdb))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: Common DB Names Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981320";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:m(?:s(?:ysaccessobjects|msysaces|msysobjects|msysqueries|msysrelationships|msysaccessstorage|msysaccessxml|msysmodules|msysmodules2|db)|aster\.\.sysdatabases|ysql\.db)|s(?:ys(?:\.database_name|aux)|chema(?:\W*\(|_name)|qlite(_temp)?_master)|d(?:atabas|b_nam)e\W*\(|information_schema|pg_(catalog|toast)|northwind|tempdb))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack: Common DB Names Detected";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleId = "981320";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:m(?:s(?:ysaccessobjects|msysaces|msysobjects|msysqueries|msysrelationships|msysaccessstorage|msysaccessxml|msysmodules|msysmodules2|db)|aster\.\.sysdatabases|ysql\.db)|s(?:ys(?:\.database_name|aux)|chema(?:\W*\(|_name)|qlite(_temp)?_master)|d(?:atabas|b_nam)e\W*\(|information_schema|pg_(catalog|toast)|northwind|tempdb))
   ## REQUEST_COOKIES, 
   # skipped   REQUEST_COOKIES pm  select show top distinct from dual where group by order having limit offset union rownum as (case
   ## REQUEST_COOKIES_NAMES, 
   # skipped   REQUEST_COOKIES_NAMES pm  select show top distinct from dual where group by order having limit offset union rownum as (case
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pm  select show top distinct from dual where group by order having limit offset union rownum as (case
   ## ARGS_NAMES, 
   # skipped   ARGS_NAMES pm  select show top distinct from dual where group by order having limit offset union rownum as (case
   ## ARGS, 
   # skipped   ARGS pm  select show top distinct from dual where group by order having limit offset union rownum as (case
   ## XML, :/*
   # AC /* 
   # skipped   XML pm /* select show top distinct from dual where group by order having limit offset union rownum as (case
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT
   # AC SQLI_SELECT_STATEMENT 
   ## Rule: TX contains :SQLI_SELECT_STATEMENT
   ## TX, :SQLI_SELECT_STATEMENT_COUNT
   # AC SQLI_SELECT_STATEMENT_COUNT 
   # skipped   TX ge SQLI_SELECT_STATEMENT_COUNT 3
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_catalog\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959517";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_catalog\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959517";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsys\.user_catalog\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959517";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsys\.user_catalog\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959517";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsys\.user_catalog\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959517";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsys\.user_catalog\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bconstraint_type\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959503";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bconstraint_type\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959503";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bconstraint_type\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959503";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bconstraint_type\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959503";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bconstraint_type\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959503";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bconstraint_type\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959521";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959521";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsys\.user_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959521";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsys\.user_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959521";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsys\.user_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959521";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsys\.user_tables\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bmsysqueries\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959509";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bmsysqueries\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959509";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bmsysqueries\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959509";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bmsysqueries\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959509";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bmsysqueries\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959509";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bmsysqueries\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bmsysaces\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959506";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bmsysaces\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959506";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bmsysaces\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959506";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bmsysaces\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959506";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bmsysaces\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959506";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bmsysaces\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\@\@spid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959500";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\@\@spid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959500";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\@\@spid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959500";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\@\@spid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959500";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\@\@spid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959500";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\@\@spid\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bcharindex\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959502";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bcharindex\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959502";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bcharindex\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959502";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bcharindex\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959502";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bcharindex\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959502";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bcharindex\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.all_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959515";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.all_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959515";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsys\.all_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959515";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsys\.all_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959515";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsys\.all_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959515";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsys\.all_tables\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_constraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959518";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_constraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959518";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsys\.user_constraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959518";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsys\.user_constraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959518";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsys\.user_constraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959518";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsys\.user_constraints\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{0,40}\busers?\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959514";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{0,40}\busers?\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959514";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bselect\b.{0,40}\busers?\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959514";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bselect\b.{0,40}\busers?\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959514";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bselect\b.{0,40}\busers?\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959514";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bselect\b.{0,40}\busers?\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bwaitfor\b\W*?\bdelay\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959538";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bwaitfor\b\W*?\bdelay\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959538";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bwaitfor\b\W*?\bdelay\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959538";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bwaitfor\b\W*?\bdelay\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959538";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bwaitfor\b\W*?\bdelay\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959538";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bwaitfor\b\W*?\bdelay\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bmsyscolumns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959507";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bmsyscolumns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959507";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bmsyscolumns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959507";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bmsyscolumns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959507";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bmsyscolumns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959507";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bmsyscolumns\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{0,40}\bsubstring\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959513";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{0,40}\bsubstring\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959513";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bselect\b.{0,40}\bsubstring\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959513";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bselect\b.{0,40}\bsubstring\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959513";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bselect\b.{0,40}\bsubstring\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959513";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bselect\b.{0,40}\bsubstring\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_triggers\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959522";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_triggers\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959522";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsys\.user_triggers\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959522";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsys\.user_triggers\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959522";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsys\.user_triggers\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959522";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsys\.user_triggers\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\blocate\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959505";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\blocate\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959505";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\blocate\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959505";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\blocate\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959505";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\blocate\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959505";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\blocate\W+\()
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bmsysrelationships\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959510";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bmsysrelationships\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959510";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bmsysrelationships\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959510";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bmsysrelationships\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959510";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bmsysrelationships\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959510";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bmsysrelationships\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_tab_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959520";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_tab_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959520";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsys\.user_tab_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959520";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsys\.user_tab_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959520";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsys\.user_tab_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959520";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsys\.user_tab_columns\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\battnotnull\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959501";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\battnotnull\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959501";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\battnotnull\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959501";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\battnotnull\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959501";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\battnotnull\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959501";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\battnotnull\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bmsysobjects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959508";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bmsysobjects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959508";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bmsysobjects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959508";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bmsysobjects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959508";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bmsysobjects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959508";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bmsysobjects\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.tab\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959516";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.tab\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959516";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsys\.tab\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959516";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsys\.tab\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959516";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsys\.tab\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959516";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsys\.tab\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{0,40}\bascii\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959512";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{0,40}\bascii\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959512";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bselect\b.{0,40}\bascii\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959512";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bselect\b.{0,40}\bascii\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959512";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bselect\b.{0,40}\bascii\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959512";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bselect\b.{0,40}\bascii\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_views\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959523";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_views\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959523";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsys\.user_views\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959523";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsys\.user_views\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959523";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsys\.user_views\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959523";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsys\.user_views\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\binstr\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959504";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\binstr\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959504";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\binstr\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959504";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\binstr\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959504";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\binstr\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959504";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\binstr\W+\()
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959519";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsys\.user_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959519";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsys\.user_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959519";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsys\.user_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959519";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsys\.user_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959519";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsys\.user_objects\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bmysql\.(db|user)\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959511";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bmysql\.(db|user)\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959511";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bmysql\.(db|user)\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959511";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bmysql\.(db|user)\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959511";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bmysql\.(db|user)\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959511";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bmysql\.(db|user)\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\buser_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959918";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\buser_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959918";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\buser_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959918";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\buser_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959918";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\buser_tables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959918";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\buser_tables\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\buser_tab_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959536";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\buser_tab_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959536";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\buser_tab_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959536";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\buser_tab_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959536";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\buser_tab_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959536";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\buser_tab_columns\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\ball_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959900";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\ball_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959900";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\ball_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959900";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\ball_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959900";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\ball_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959900";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\ball_objects\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bpg_class\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959910";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bpg_class\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959910";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bpg_class\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959910";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bpg_class\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959910";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bpg_class\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959910";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bpg_class\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsyscat\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959524";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsyscat\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959524";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsyscat\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959524";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsyscat\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959524";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsyscat\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959524";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsyscat\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsubstr\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959912";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsubstr\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959912";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsubstr\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959912";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsubstr\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959912";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsubstr\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959912";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsubstr\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsysdba\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959527";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsysdba\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959527";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsysdba\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959527";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsysdba\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959527";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsysdba\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959527";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsysdba\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\btextpos\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959533";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\btextpos\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959533";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\btextpos\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959533";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\btextpos\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959533";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\btextpos\W+\()"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959533";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\btextpos\W+\()
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\battrelid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959901";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\battrelid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959901";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\battrelid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959901";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\battrelid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959901";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\battrelid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959901";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\battrelid\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bpg_attribute\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959909";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bpg_attribute\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959909";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bpg_attribute\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959909";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bpg_attribute\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959909";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bpg_attribute\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959909";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bpg_attribute\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\buser_password\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959917";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\buser_password\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959917";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\buser_password\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959917";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\buser_password\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959917";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\buser_password\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959917";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\buser_password\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\buser_users\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959919";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\buser_users\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959919";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\buser_users\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959919";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\buser_users\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959919";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\buser_users\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959919";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\buser_users\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\buser_constraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959534";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\buser_constraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959534";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\buser_constraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959534";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\buser_constraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959534";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\buser_constraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959534";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\buser_constraints\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxtype\W+\bchar\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959537";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxtype\W+\bchar\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959537";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxtype\W+\bchar\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959537";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxtype\W+\bchar\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959537";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxtype\W+\bchar\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959537";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxtype\W+\bchar\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\buser_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959916";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\buser_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959916";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\buser_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959916";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\buser_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959916";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\buser_objects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959916";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\buser_objects\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bcolumn_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959904";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bcolumn_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959904";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bcolumn_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959904";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bcolumn_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959904";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bcolumn_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959904";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bcolumn_name\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsysfilegroups\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959528";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsysfilegroups\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959528";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsysfilegroups\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959528";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsysfilegroups\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959528";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsysfilegroups\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959528";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsysfilegroups\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsyscolumns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959525";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsyscolumns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959525";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsyscolumns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959525";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsyscolumns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959525";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsyscolumns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959525";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsyscolumns\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsubstring\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959913";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsubstring\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959913";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsubstring\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959913";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsubstring\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959913";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsubstring\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959913";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsubstring\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsysobjects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959530";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsysobjects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959530";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsysobjects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959530";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsysobjects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959530";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsysobjects\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959530";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsysobjects\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bobject_type\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959908";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bobject_type\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959908";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bobject_type\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959908";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bobject_type\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959908";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bobject_type\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959908";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bobject_type\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bobject_id\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959906";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bobject_id\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959906";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bobject_id\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959906";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bobject_id\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959906";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bobject_id\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959906";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bobject_id\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsysibm\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959529";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsysibm\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959529";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsysibm\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959529";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsysibm\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959529";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsysibm\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959529";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsysibm\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\buser_ind_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959535";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\buser_ind_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959535";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\buser_ind_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959535";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\buser_ind_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959535";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\buser_ind_columns\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959535";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\buser_ind_columns\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bcolumn_id\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959903";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bcolumn_id\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959903";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bcolumn_id\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959903";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bcolumn_id\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959903";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bcolumn_id\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959903";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bcolumn_id\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsysprocesses\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959531";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsysprocesses\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959531";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsysprocesses\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959531";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsysprocesses\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959531";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsysprocesses\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959531";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsysprocesses\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bmb_users\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959905";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bmb_users\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959905";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bmb_users\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959905";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bmb_users\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959905";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bmb_users\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959905";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bmb_users\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\btable_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959914";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\btable_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959914";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\btable_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959914";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\btable_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959914";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\btable_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959914";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\btable_name\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsystables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959532";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsystables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959532";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsystables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959532";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsystables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959532";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsystables\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959532";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsystables\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bobject_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959907";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bobject_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959907";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bobject_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959907";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bobject_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959907";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bobject_name\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959907";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bobject_name\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\brownum\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959911";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\brownum\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959911";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\brownum\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959911";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\brownum\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959911";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\brownum\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959911";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\brownum\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsysconstraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959526";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsysconstraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959526";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsysconstraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959526";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsysconstraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959526";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsysconstraints\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959526";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsysconstraints\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\batttypid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959902";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\batttypid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959902";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\batttypid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959902";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\batttypid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959902";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\batttypid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959902";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\batttypid\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\buser_group\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959915";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\buser_group\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959915";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\buser_group\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959915";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\buser_group\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959915";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\buser_group\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959915";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\buser_group\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\'msdasql\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959020";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\'msdasql\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959020";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\'msdasql\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959020";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\'msdasql\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959020";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\'msdasql\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959020";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\'msdasql\')
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bdelete\b\W*?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959069";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bdelete\b\W*?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959069";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bdelete\b\W*?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959069";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bdelete\b\W*?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959069";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bdelete\b\W*?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959069";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bdelete\b\W*?\bfrom\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_makecab\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959058";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_makecab\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959058";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_makecab\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959058";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_makecab\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959058";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_makecab\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959058";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_makecab\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\butl_http\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959049";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\butl_http\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959049";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\butl_http\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959049";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\butl_http\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959049";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\butl_http\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959049";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\butl_http\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.*?\bto_number\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959035";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.*?\bto_number\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959035";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bselect\b.*?\bto_number\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959035";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bselect\b.*?\bto_number\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959035";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bselect\b.*?\bto_number\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959035";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bselect\b.*?\bto_number\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\btbcreator\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959046";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\btbcreator\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959046";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\btbcreator\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959046";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\btbcreator\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959046";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\btbcreator\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959046";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\btbcreator\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsp_execute\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959038";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsp_execute\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959038";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsp_execute\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959038";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsp_execute\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959038";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsp_execute\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959038";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsp_execute\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bgroup\b.*\bby\b.{1,100}?\bhaving\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959011";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bgroup\b.*\bby\b.{1,100}?\bhaving\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959011";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bgroup\b.*\bby\b.{1,100}?\bhaving\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959011";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bgroup\b.*\bby\b.{1,100}?\bhaving\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959011";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bgroup\b.*\bby\b.{1,100}?\bhaving\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959011";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bgroup\b.*\bby\b.{1,100}?\bhaving\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.*?\bdata_type\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959027";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.*?\bdata_type\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959027";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bselect\b.*?\bdata_type\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959027";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bselect\b.*?\bdata_type\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959027";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bselect\b.*?\bdata_type\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959027";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bselect\b.*?\bdata_type\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_cmdshell\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959052";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_cmdshell\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959052";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_cmdshell\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959052";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_cmdshell\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959052";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_cmdshell\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959052";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_cmdshell\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bisnull\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959018";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bisnull\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959018";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bisnull\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959018";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bisnull\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959018";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bisnull\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959018";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bisnull\b\W*?\()
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bopenrowset|owa_util\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959023";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bopenrowset|owa_util\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959023";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bopenrowset|owa_util\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959023";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bopenrowset|owa_util\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959023";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bopenrowset|owa_util\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959023";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bopenrowset|owa_util\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bunion\b.{1,100}?\bselect\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959047";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bunion\b.{1,100}?\bselect\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959047";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bunion\b.{1,100}?\bselect\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959047";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bunion\b.{1,100}?\bselect\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959047";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bunion\b.{1,100}?\bselect\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959047";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bunion\b.{1,100}?\bselect\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\binsert\b\W*?\binto\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959015";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\binsert\b\W*?\binto\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959015";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\binsert\b\W*?\binto\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959015";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\binsert\b\W*?\binto\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959015";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\binsert\b\W*?\binto\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959015";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\binsert\b\W*?\binto\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{1,100}?\bcount\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959032";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{1,100}?\bcount\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959032";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bselect\b.{1,100}?\bcount\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959032";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bselect\b.{1,100}?\bcount\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959032";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bselect\b.{1,100}?\bcount\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959032";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bselect\b.{1,100}?\bcount\b.{1,100}?\bfrom\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\;\W*?\bdrop\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959001";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\;\W*?\bdrop\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959001";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\;\W*?\bdrop\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959001";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\;\W*?\bdrop\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959001";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\;\W*?\bdrop\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959001";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\;\W*?\bdrop\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_execresultset\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959055";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_execresultset\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959055";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_execresultset\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959055";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_execresultset\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959055";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_execresultset\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959055";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_execresultset\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regaddmultistring\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959060";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regaddmultistring\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959060";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_regaddmultistring\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959060";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_regaddmultistring\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959060";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_regaddmultistring\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959060";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_regaddmultistring\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\@\@version\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959004";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\@\@version\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959004";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\@\@version\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959004";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\@\@version\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959004";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\@\@version\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959004";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\@\@version\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regread\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959065";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regread\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959065";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_regread\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959065";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_regread\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959065";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_regread\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959065";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_regread\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bload\b\W*?\bdata\b.*\binfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959019";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bload\b\W*?\bdata\b.*\binfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959019";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bload\b\W*?\bdata\b.*\binfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959019";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bload\b\W*?\bdata\b.*\binfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959019";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bload\b\W*?\bdata\b.*\binfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959019";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bload\b\W*?\bdata\b.*\binfile\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.*?\bto_char\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959034";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.*?\bto_char\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959034";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bselect\b.*?\bto_char\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959034";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bselect\b.*?\bto_char\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959034";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bselect\b.*?\bto_char\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959034";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bselect\b.*?\bto_char\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bdbms_java\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959009";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bdbms_java\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959009";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bdbms_java\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959009";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bdbms_java\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959009";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bdbms_java\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959009";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bdbms_java\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_enumdsn\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959054";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_enumdsn\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959054";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_enumdsn\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959054";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_enumdsn\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959054";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_enumdsn\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959054";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_enumdsn\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_availablemedia\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959051";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_availablemedia\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959051";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_availablemedia\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959051";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_availablemedia\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959051";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_availablemedia\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959051";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_availablemedia\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsp_prepare|sp_password\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959042";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsp_prepare|sp_password\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959042";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsp_prepare|sp_password\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959042";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsp_prepare|sp_password\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959042";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsp_prepare|sp_password\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959042";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsp_prepare|sp_password\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bnvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959021";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bnvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959021";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bnvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959021";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bnvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959021";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bnvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959021";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bnvarchar\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\butl_file\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959048";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\butl_file\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959048";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\butl_file\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959048";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\butl_file\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959048";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\butl_file\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959048";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\butl_file\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\binner\b\W*?\bjoin\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959014";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\binner\b\W*?\bjoin\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959014";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\binner\b\W*?\bjoin\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959014";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\binner\b\W*?\bjoin\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959014";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\binner\b\W*?\bjoin\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959014";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\binner\b\W*?\bjoin\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regdeletekey\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959061";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regdeletekey\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959061";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_regdeletekey\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959061";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_regdeletekey\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959061";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_regdeletekey\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959061";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_regdeletekey\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_loginconfig\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959057";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_loginconfig\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959057";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_loginconfig\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959057";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_loginconfig\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959057";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_loginconfig\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959057";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_loginconfig\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsp_sqlexec|sp_replwritetovarbin|sp_help\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959043";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsp_sqlexec|sp_replwritetovarbin|sp_help\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959043";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsp_sqlexec|sp_replwritetovarbin|sp_help\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959043";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsp_sqlexec|sp_replwritetovarbin|sp_help\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959043";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsp_sqlexec|sp_replwritetovarbin|sp_help\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959043";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsp_sqlexec|sp_replwritetovarbin|sp_help\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bprint\b\W*?\@\@)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959024";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bprint\b\W*?\@\@)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959024";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bprint\b\W*?\@\@)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959024";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bprint\b\W*?\@\@)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959024";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bprint\b\W*?\@\@)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959024";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bprint\b\W*?\@\@)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{1,100}?\bfrom\b.{1,100}?\bwhere\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959031";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{1,100}?\bfrom\b.{1,100}?\bwhere\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959031";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bselect\b.{1,100}?\bfrom\b.{1,100}?\bwhere\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959031";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bselect\b.{1,100}?\bfrom\b.{1,100}?\bwhere\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959031";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bselect\b.{1,100}?\bfrom\b.{1,100}?\bwhere\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959031";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bselect\b.{1,100}?\bfrom\b.{1,100}?\bwhere\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regremovemultistring\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959066";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regremovemultistring\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959066";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_regremovemultistring\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959066";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_regremovemultistring\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959066";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_regremovemultistring\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959066";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_regremovemultistring\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regwrite\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959067";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regwrite\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959067";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_regwrite\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959067";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_regwrite\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959067";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_regwrite\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959067";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_regwrite\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959050";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959050";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959050";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959050";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959050";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bvarchar\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\binto\b\W*?\bdumpfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959016";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\binto\b\W*?\bdumpfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959016";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\binto\b\W*?\bdumpfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959016";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\binto\b\W*?\bdumpfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959016";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\binto\b\W*?\bdumpfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959016";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\binto\b\W*?\bdumpfile\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bif\b\W*?\(\W*?\bbenchmark\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959012";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bif\b\W*?\(\W*?\bbenchmark\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959012";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bif\b\W*?\(\W*?\bbenchmark\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959012";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bif\b\W*?\(\W*?\bbenchmark\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959012";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bif\b\W*?\(\W*?\bbenchmark\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959012";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bif\b\W*?\(\W*?\bbenchmark\W*?\()
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bopenquery\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959022";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bopenquery\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959022";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bopenquery\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959022";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bopenquery\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959022";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bopenquery\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959022";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bopenquery\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{1,100}?\blength\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959033";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{1,100}?\blength\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959033";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bselect\b.{1,100}?\blength\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959033";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bselect\b.{1,100}?\blength\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959033";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bselect\b.{1,100}?\blength\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959033";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bselect\b.{1,100}?\blength\b.{1,100}?\bfrom\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bcast\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959006";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bcast\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959006";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bcast\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959006";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bcast\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959006";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bcast\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959006";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bcast\b\W*?\()
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regdeletevalue\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959062";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regdeletevalue\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959062";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_regdeletevalue\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959062";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_regdeletevalue\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959062";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_regdeletevalue\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959062";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_regdeletevalue\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\'sqloledb\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959003";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\'sqloledb\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959003";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\'sqloledb\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959003";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\'sqloledb\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959003";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\'sqloledb\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959003";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\'sqloledb\')
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsp_addextendedproc|is_srvrolemember\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959037";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsp_addextendedproc|is_srvrolemember\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959037";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsp_addextendedproc|is_srvrolemember\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959037";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsp_addextendedproc|is_srvrolemember\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959037";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsp_addextendedproc|is_srvrolemember\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959037";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsp_addextendedproc|is_srvrolemember\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsql_longvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959044";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsql_longvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959044";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsql_longvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959044";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsql_longvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959044";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsql_longvarchar\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959044";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsql_longvarchar\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_dirtree\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959053";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_dirtree\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959053";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_dirtree\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959053";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_dirtree\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959053";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_dirtree\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959053";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_dirtree\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regenumkeys\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959063";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regenumkeys\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959063";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_regenumkeys\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959063";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_regenumkeys\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959063";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_regenumkeys\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959063";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_regenumkeys\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.*?\bdump\b.*\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959028";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.*?\bdump\b.*\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959028";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bselect\b.*?\bdump\b.*\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959028";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bselect\b.*?\bdump\b.*\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959028";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bselect\b.*?\bdump\b.*\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959028";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bselect\b.*?\bdump\b.*\bfrom\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_filelist\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959056";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_filelist\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959056";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_filelist\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959056";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_filelist\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959056";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_filelist\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959056";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_filelist\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\'sa\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959026";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\'sa\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959026";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\'sa\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959026";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\'sa\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959026";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\'sa\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959026";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\'sa\')
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959068";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959068";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959068";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959068";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959068";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsp_executesql\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959039";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsp_executesql\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959039";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsp_executesql\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959039";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsp_executesql\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959039";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsp_executesql\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959039";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsp_executesql\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bifnull\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959013";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bifnull\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959013";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bifnull\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959013";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bifnull\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959013";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bifnull\b\W*?\()"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959013";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bifnull\b\W*?\()
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\binto\b\W*?\boutfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959017";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\binto\b\W*?\boutfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959017";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\binto\b\W*?\boutfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959017";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\binto\b\W*?\boutfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959017";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\binto\b\W*?\boutfile\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959017";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\binto\b\W*?\boutfile\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsp_makewebtask\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959040";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsp_makewebtask\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959040";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsp_makewebtask\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959040";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsp_makewebtask\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959040";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsp_makewebtask\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959040";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsp_makewebtask\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\'dbo\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959010";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\'dbo\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959010";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\'dbo\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959010";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\'dbo\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959010";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\'dbo\')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959010";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\'dbo\')
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsql_variant\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959045";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsql_variant\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959045";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsql_variant\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959045";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsql_variant\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959045";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsql_variant\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959045";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsql_variant\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_ntsec\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959059";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_ntsec\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959059";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_ntsec\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959059";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_ntsec\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959059";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_ntsec\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959059";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_ntsec\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\;\W*?\bshutdown\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959002";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\;\W*?\bshutdown\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959002";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\;\W*?\bshutdown\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959002";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\;\W*?\bshutdown\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959002";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\;\W*?\bshutdown\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959002";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\;\W*?\bshutdown\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.*?\binstr\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959029";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.*?\binstr\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959029";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bselect\b.*?\binstr\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959029";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bselect\b.*?\binstr\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959029";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bselect\b.*?\binstr\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959029";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bselect\b.*?\binstr\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bautonomous_transaction\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959005";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bautonomous_transaction\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959005";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bautonomous_transaction\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959005";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bautonomous_transaction\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959005";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bautonomous_transaction\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959005";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bautonomous_transaction\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bdba_users\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959007";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bdba_users\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959007";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bdba_users\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959007";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bdba_users\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959007";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bdba_users\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959007";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bdba_users\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bsp_oacreate\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959041";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bsp_oacreate\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959041";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bsp_oacreate\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959041";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bsp_oacreate\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959041";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bsp_oacreate\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959041";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bsp_oacreate\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{1,100}?\btop\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959036";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bselect\b.{1,100}?\btop\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959036";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bselect\b.{1,100}?\btop\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959036";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bselect\b.{1,100}?\btop\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959036";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bselect\b.{1,100}?\btop\b.{1,100}?\bfrom\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959036";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bselect\b.{1,100}?\btop\b.{1,100}?\bfrom\b)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regenumvalues\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959064";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\bxp_regenumvalues\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959064";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bxp_regenumvalues\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959064";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bxp_regenumvalues\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959064";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bxp_regenumvalues\b)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959064";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bxp_regenumvalues\b)
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\b(?i:having)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[=<>]|(?i:\bexecute(\s{1,5}[\w\.$]{1,5}\s{0,3})?\()|\bhaving\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|(?i:\bcreate\s+?table.{0,20}?\()|(?i:\blike\W*?char\W*?\()|(?i:(?:(select(.*)case|from(.*)limit|order\sby)))|exists\s(\sselect|select\Sif(null)?\s\(|select\Stop|select\Sconcat|system\s\(|\b(?i:having)\b\s+(\d{1,10})|'[^=]{1,10}')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959070";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\b(?i:having)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[=<>]|(?i:\bexecute(\s{1,5}[\w\.$]{1,5}\s{0,3})?\()|\bhaving\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|(?i:\bcreate\s+?table.{0,20}?\()|(?i:\blike\W*?char\W*?\()|(?i:(?:(select(.*)case|from(.*)limit|order\sby)))|exists\s(\sselect|select\Sif(null)?\s\(|select\Stop|select\Sconcat|system\s\(|\b(?i:having)\b\s+(\d{1,10})|'[^=]{1,10}')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959070";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\b(?i:having)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[=<>]|(?i:\bexecute(\s{1,5}[\w\.$]{1,5}\s{0,3})?\()|\bhaving\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|(?i:\bcreate\s+?table.{0,20}?\()|(?i:\blike\W*?char\W*?\()|(?i:(?:(select(.*)case|from(.*)limit|order\sby)))|exists\s(\sselect|select\Sif(null)?\s\(|select\Stop|select\Sconcat|system\s\(|\b(?i:having)\b\s+(\d{1,10})|'[^=]{1,10}')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959070";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \b(?i:having)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[=<>]|(?i:\bexecute(\s{1,5}[\w\.$]{1,5}\s{0,3})?\()|\bhaving\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|(?i:\bcreate\s+?table.{0,20}?\()|(?i:\blike\W*?char\W*?\()|(?i:(?:(select(.*)case|from(.*)limit|order\sby)))|exists\s(\sselect|select\Sif(null)?\s\(|select\Stop|select\Sconcat|system\s\(|\b(?i:having)\b\s+(\d{1,10})|'[^=]{1,10}')
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\bor\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|(?i:'\s+x?or\s+.{1,20}[+\-!<>=])|\b(?i:x?or)\b\s+(\d{1,10}|'[^=]{1,10}')|\b(?i:x?or)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[=<>])"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959071";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\bor\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|(?i:'\s+x?or\s+.{1,20}[+\-!<>=])|\b(?i:x?or)\b\s+(\d{1,10}|'[^=]{1,10}')|\b(?i:x?or)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[=<>])"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959071";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\bor\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|(?i:'\s+x?or\s+.{1,20}[+\-!<>=])|\b(?i:x?or)\b\s+(\d{1,10}|'[^=]{1,10}')|\b(?i:x?or)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[=<>])"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959071";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\bor\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|(?i:'\s+x?or\s+.{1,20}[+\-!<>=])|\b(?i:x?or)\b\s+(\d{1,10}|'[^=]{1,10}')|\b(?i:x?or)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[=<>])
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i)\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[=]|\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[<>]|\band\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959072";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i)\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[=]|\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[<>]|\band\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959072";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i)\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[=]|\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[<>]|\band\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959072";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i)\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[=]|\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')\s*[<>]|\band\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:\b(?:coalesce\b|root\@))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleId = "950908";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:\b(?:coalesce\b|root\@))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleId = "950908";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:\b(?:coalesce\b|root\@))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleId = "950908";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:\b(?:coalesce\b|root\@))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleId = "950908";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:\b(?:coalesce\b|root\@))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleId = "950908";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:\b(?:coalesce\b|root\@))
   ## !REQUEST_HEADERS, :via
   # AC via 
   ## Rule: REQUEST_HEADERS rx :via
   # AAA via
   if(req.http.via ~ "(?i:\b(?:coalesce\b|root\@))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleId = "950908";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:(?:s(?:t(?:d(?:dev(_pop|_samp)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha(1|2)?|oundex|chema|ig?n|pace|qrt)|i(?:s(null|_(free_lock|ipv4_compat|ipv4_mapped|ipv4|ipv6|not_null|not|null|used_lock))?|n(?:et6?_(aton|ntoa)|s(?:ert|tr)|terval)?|f(null)?)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(date|time|timestamp)|p(?:datexml|per)|uid(_short)?|case|ser)|l(?:o(?:ca(?:l(timestamp)?|te)|g(2|10)?|ad_file|wer)|ast(_day|_insert_id)?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|t(?:ime(stamp|stampadd|stampdiff|diff|_format|_to_sec)?|o_(base64|days|seconds|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(name)?|d)|d5)|r(?:e(?:p(?:lace|eat)|lease_lock|verse)|o(?:w_count|und)|a(?:dians|nd)|ight|trim|pad)|f(?:i(?:eld(_in_set)?|nd_in_set)|rom_(base64|days|unixtime)|o(?:und_rows|rmat)|loor)|a(?:es_(?:de|en)crypt|s(?:cii(str)?|in)|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|p(?:o(?:sition|w(er)?)|eriod_(add|diff)|rocedure_analyse|assword|i)|b(?:i(?:t_(?:length|count|x?or|and)|n(_to_num)?)|enchmark)|e(?:x(?:p(?:ort_set)?|tract(value)?)|nc(?:rypt|ode)|lt)|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|g(?:r(?:oup_conca|eates)t|et_(format|lock))|o(?:(?:ld_passwo)?rd|ct(et_length)?)|we(?:ek(day|ofyear)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|(rawton?)?hex(toraw)?|qu(?:arter|ote)|(pg_)?sleep|year(week)?|d?count|xmltype|hour)\W*\(|\b(?:(?:s(?:elect\b(?:.{1,100}?\b(?:(?:length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(?:d(?:ump\b.*\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:sqlexec|sp_replwritetovarbin|sp_help|addextendedproc|is_srvrolemember|prepare|sp_password|execute(?:sql)?|makewebtask|oacreate)|ql_(?:longvarchar|variant))|xp_(?:reg(?:re(?:movemultistring|ad)|delete(?:value|key)|enum(?:value|key)s|addmultistring|write)|terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process|e(?:xecresultset|numdsn)|availablemedia|loginconfig|cmdshell|filelist|dirtree|makecab|ntsec)|u(?:nion\b.{1,100}?\bselect|tl_(?:file|http))|d(?:b(?:a_users|ms_java)|elete\b\W*?\bfrom)|group\b.*\bby\b.{1,100}?\bhaving|open(?:rowset|owa_util|query)|load\b\W*?\bdata\b.*\binfile|(?:n?varcha|tbcreato)r|autonomous_transaction)\b|i(?:n(?:to\b\W*?\b(?:dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(?:f(?:\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|print\b\W*?\@\@|cast\b\W*?\()|c(?:(?:ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)\W*\(|o(?:(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|(?:mpres)?s|ercibility|alesce|t)\W*\(|llation\W*\(a))|d(?:(?:a(?:t(?:e(?:(_(add|format|sub))?|diff)|abase)|y(name|ofmonth|ofweek|ofyear)?)|e(?:(?:s_(de|en)cryp|faul)t|grees|code)|ump)\W*\(|bms_pipe\.receive_message\b)|(?:;\W*?\b(?:shutdown|drop)|\@\@version)\b|'(?:s(?:qloledb|a)|msdasql|dbo)'))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959073";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:(?:s(?:t(?:d(?:dev(_pop|_samp)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha(1|2)?|oundex|chema|ig?n|pace|qrt)|i(?:s(null|_(free_lock|ipv4_compat|ipv4_mapped|ipv4|ipv6|not_null|not|null|used_lock))?|n(?:et6?_(aton|ntoa)|s(?:ert|tr)|terval)?|f(null)?)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(date|time|timestamp)|p(?:datexml|per)|uid(_short)?|case|ser)|l(?:o(?:ca(?:l(timestamp)?|te)|g(2|10)?|ad_file|wer)|ast(_day|_insert_id)?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|t(?:ime(stamp|stampadd|stampdiff|diff|_format|_to_sec)?|o_(base64|days|seconds|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(name)?|d)|d5)|r(?:e(?:p(?:lace|eat)|lease_lock|verse)|o(?:w_count|und)|a(?:dians|nd)|ight|trim|pad)|f(?:i(?:eld(_in_set)?|nd_in_set)|rom_(base64|days|unixtime)|o(?:und_rows|rmat)|loor)|a(?:es_(?:de|en)crypt|s(?:cii(str)?|in)|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|p(?:o(?:sition|w(er)?)|eriod_(add|diff)|rocedure_analyse|assword|i)|b(?:i(?:t_(?:length|count|x?or|and)|n(_to_num)?)|enchmark)|e(?:x(?:p(?:ort_set)?|tract(value)?)|nc(?:rypt|ode)|lt)|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|g(?:r(?:oup_conca|eates)t|et_(format|lock))|o(?:(?:ld_passwo)?rd|ct(et_length)?)|we(?:ek(day|ofyear)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|(rawton?)?hex(toraw)?|qu(?:arter|ote)|(pg_)?sleep|year(week)?|d?count|xmltype|hour)\W*\(|\b(?:(?:s(?:elect\b(?:.{1,100}?\b(?:(?:length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(?:d(?:ump\b.*\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:sqlexec|sp_replwritetovarbin|sp_help|addextendedproc|is_srvrolemember|prepare|sp_password|execute(?:sql)?|makewebtask|oacreate)|ql_(?:longvarchar|variant))|xp_(?:reg(?:re(?:movemultistring|ad)|delete(?:value|key)|enum(?:value|key)s|addmultistring|write)|terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process|e(?:xecresultset|numdsn)|availablemedia|loginconfig|cmdshell|filelist|dirtree|makecab|ntsec)|u(?:nion\b.{1,100}?\bselect|tl_(?:file|http))|d(?:b(?:a_users|ms_java)|elete\b\W*?\bfrom)|group\b.*\bby\b.{1,100}?\bhaving|open(?:rowset|owa_util|query)|load\b\W*?\bdata\b.*\binfile|(?:n?varcha|tbcreato)r|autonomous_transaction)\b|i(?:n(?:to\b\W*?\b(?:dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(?:f(?:\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|print\b\W*?\@\@|cast\b\W*?\()|c(?:(?:ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)\W*\(|o(?:(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|(?:mpres)?s|ercibility|alesce|t)\W*\(|llation\W*\(a))|d(?:(?:a(?:t(?:e(?:(_(add|format|sub))?|diff)|abase)|y(name|ofmonth|ofweek|ofyear)?)|e(?:(?:s_(de|en)cryp|faul)t|grees|code)|ump)\W*\(|bms_pipe\.receive_message\b)|(?:;\W*?\b(?:shutdown|drop)|\@\@version)\b|'(?:s(?:qloledb|a)|msdasql|dbo)'))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959073";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:(?:s(?:t(?:d(?:dev(_pop|_samp)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha(1|2)?|oundex|chema|ig?n|pace|qrt)|i(?:s(null|_(free_lock|ipv4_compat|ipv4_mapped|ipv4|ipv6|not_null|not|null|used_lock))?|n(?:et6?_(aton|ntoa)|s(?:ert|tr)|terval)?|f(null)?)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(date|time|timestamp)|p(?:datexml|per)|uid(_short)?|case|ser)|l(?:o(?:ca(?:l(timestamp)?|te)|g(2|10)?|ad_file|wer)|ast(_day|_insert_id)?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|t(?:ime(stamp|stampadd|stampdiff|diff|_format|_to_sec)?|o_(base64|days|seconds|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(name)?|d)|d5)|r(?:e(?:p(?:lace|eat)|lease_lock|verse)|o(?:w_count|und)|a(?:dians|nd)|ight|trim|pad)|f(?:i(?:eld(_in_set)?|nd_in_set)|rom_(base64|days|unixtime)|o(?:und_rows|rmat)|loor)|a(?:es_(?:de|en)crypt|s(?:cii(str)?|in)|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|p(?:o(?:sition|w(er)?)|eriod_(add|diff)|rocedure_analyse|assword|i)|b(?:i(?:t_(?:length|count|x?or|and)|n(_to_num)?)|enchmark)|e(?:x(?:p(?:ort_set)?|tract(value)?)|nc(?:rypt|ode)|lt)|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|g(?:r(?:oup_conca|eates)t|et_(format|lock))|o(?:(?:ld_passwo)?rd|ct(et_length)?)|we(?:ek(day|ofyear)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|(rawton?)?hex(toraw)?|qu(?:arter|ote)|(pg_)?sleep|year(week)?|d?count|xmltype|hour)\W*\(|\b(?:(?:s(?:elect\b(?:.{1,100}?\b(?:(?:length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(?:d(?:ump\b.*\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:sqlexec|sp_replwritetovarbin|sp_help|addextendedproc|is_srvrolemember|prepare|sp_password|execute(?:sql)?|makewebtask|oacreate)|ql_(?:longvarchar|variant))|xp_(?:reg(?:re(?:movemultistring|ad)|delete(?:value|key)|enum(?:value|key)s|addmultistring|write)|terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process|e(?:xecresultset|numdsn)|availablemedia|loginconfig|cmdshell|filelist|dirtree|makecab|ntsec)|u(?:nion\b.{1,100}?\bselect|tl_(?:file|http))|d(?:b(?:a_users|ms_java)|elete\b\W*?\bfrom)|group\b.*\bby\b.{1,100}?\bhaving|open(?:rowset|owa_util|query)|load\b\W*?\bdata\b.*\binfile|(?:n?varcha|tbcreato)r|autonomous_transaction)\b|i(?:n(?:to\b\W*?\b(?:dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(?:f(?:\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|print\b\W*?\@\@|cast\b\W*?\()|c(?:(?:ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)\W*\(|o(?:(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|(?:mpres)?s|ercibility|alesce|t)\W*\(|llation\W*\(a))|d(?:(?:a(?:t(?:e(?:(_(add|format|sub))?|diff)|abase)|y(name|ofmonth|ofweek|ofyear)?)|e(?:(?:s_(de|en)cryp|faul)t|grees|code)|ump)\W*\(|bms_pipe\.receive_message\b)|(?:;\W*?\b(?:shutdown|drop)|\@\@version)\b|'(?:s(?:qloledb|a)|msdasql|dbo)'))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959073";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:(?:s(?:t(?:d(?:dev(_pop|_samp)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha(1|2)?|oundex|chema|ig?n|pace|qrt)|i(?:s(null|_(free_lock|ipv4_compat|ipv4_mapped|ipv4|ipv6|not_null|not|null|used_lock))?|n(?:et6?_(aton|ntoa)|s(?:ert|tr)|terval)?|f(null)?)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(date|time|timestamp)|p(?:datexml|per)|uid(_short)?|case|ser)|l(?:o(?:ca(?:l(timestamp)?|te)|g(2|10)?|ad_file|wer)|ast(_day|_insert_id)?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|t(?:ime(stamp|stampadd|stampdiff|diff|_format|_to_sec)?|o_(base64|days|seconds|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(name)?|d)|d5)|r(?:e(?:p(?:lace|eat)|lease_lock|verse)|o(?:w_count|und)|a(?:dians|nd)|ight|trim|pad)|f(?:i(?:eld(_in_set)?|nd_in_set)|rom_(base64|days|unixtime)|o(?:und_rows|rmat)|loor)|a(?:es_(?:de|en)crypt|s(?:cii(str)?|in)|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|p(?:o(?:sition|w(er)?)|eriod_(add|diff)|rocedure_analyse|assword|i)|b(?:i(?:t_(?:length|count|x?or|and)|n(_to_num)?)|enchmark)|e(?:x(?:p(?:ort_set)?|tract(value)?)|nc(?:rypt|ode)|lt)|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|g(?:r(?:oup_conca|eates)t|et_(format|lock))|o(?:(?:ld_passwo)?rd|ct(et_length)?)|we(?:ek(day|ofyear)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|(rawton?)?hex(toraw)?|qu(?:arter|ote)|(pg_)?sleep|year(week)?|d?count|xmltype|hour)\W*\(|\b(?:(?:s(?:elect\b(?:.{1,100}?\b(?:(?:length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(?:d(?:ump\b.*\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:sqlexec|sp_replwritetovarbin|sp_help|addextendedproc|is_srvrolemember|prepare|sp_password|execute(?:sql)?|makewebtask|oacreate)|ql_(?:longvarchar|variant))|xp_(?:reg(?:re(?:movemultistring|ad)|delete(?:value|key)|enum(?:value|key)s|addmultistring|write)|terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process|e(?:xecresultset|numdsn)|availablemedia|loginconfig|cmdshell|filelist|dirtree|makecab|ntsec)|u(?:nion\b.{1,100}?\bselect|tl_(?:file|http))|d(?:b(?:a_users|ms_java)|elete\b\W*?\bfrom)|group\b.*\bby\b.{1,100}?\bhaving|open(?:rowset|owa_util|query)|load\b\W*?\bdata\b.*\binfile|(?:n?varcha|tbcreato)r|autonomous_transaction)\b|i(?:n(?:to\b\W*?\b(?:dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(?:f(?:\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|print\b\W*?\@\@|cast\b\W*?\()|c(?:(?:ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)\W*\(|o(?:(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|(?:mpres)?s|ercibility|alesce|t)\W*\(|llation\W*\(a))|d(?:(?:a(?:t(?:e(?:(_(add|format|sub))?|diff)|abase)|y(name|ofmonth|ofweek|ofyear)?)|e(?:(?:s_(de|en)cryp|faul)t|grees|code)|ump)\W*\(|bms_pipe\.receive_message\b)|(?:;\W*?\b(?:shutdown|drop)|\@\@version)\b|'(?:s(?:qloledb|a)|msdasql|dbo)'))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959073";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:(?:s(?:t(?:d(?:dev(_pop|_samp)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha(1|2)?|oundex|chema|ig?n|pace|qrt)|i(?:s(null|_(free_lock|ipv4_compat|ipv4_mapped|ipv4|ipv6|not_null|not|null|used_lock))?|n(?:et6?_(aton|ntoa)|s(?:ert|tr)|terval)?|f(null)?)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(date|time|timestamp)|p(?:datexml|per)|uid(_short)?|case|ser)|l(?:o(?:ca(?:l(timestamp)?|te)|g(2|10)?|ad_file|wer)|ast(_day|_insert_id)?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|t(?:ime(stamp|stampadd|stampdiff|diff|_format|_to_sec)?|o_(base64|days|seconds|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(name)?|d)|d5)|r(?:e(?:p(?:lace|eat)|lease_lock|verse)|o(?:w_count|und)|a(?:dians|nd)|ight|trim|pad)|f(?:i(?:eld(_in_set)?|nd_in_set)|rom_(base64|days|unixtime)|o(?:und_rows|rmat)|loor)|a(?:es_(?:de|en)crypt|s(?:cii(str)?|in)|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|p(?:o(?:sition|w(er)?)|eriod_(add|diff)|rocedure_analyse|assword|i)|b(?:i(?:t_(?:length|count|x?or|and)|n(_to_num)?)|enchmark)|e(?:x(?:p(?:ort_set)?|tract(value)?)|nc(?:rypt|ode)|lt)|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|g(?:r(?:oup_conca|eates)t|et_(format|lock))|o(?:(?:ld_passwo)?rd|ct(et_length)?)|we(?:ek(day|ofyear)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|(rawton?)?hex(toraw)?|qu(?:arter|ote)|(pg_)?sleep|year(week)?|d?count|xmltype|hour)\W*\(|\b(?:(?:s(?:elect\b(?:.{1,100}?\b(?:(?:length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(?:d(?:ump\b.*\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:sqlexec|sp_replwritetovarbin|sp_help|addextendedproc|is_srvrolemember|prepare|sp_password|execute(?:sql)?|makewebtask|oacreate)|ql_(?:longvarchar|variant))|xp_(?:reg(?:re(?:movemultistring|ad)|delete(?:value|key)|enum(?:value|key)s|addmultistring|write)|terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process|e(?:xecresultset|numdsn)|availablemedia|loginconfig|cmdshell|filelist|dirtree|makecab|ntsec)|u(?:nion\b.{1,100}?\bselect|tl_(?:file|http))|d(?:b(?:a_users|ms_java)|elete\b\W*?\bfrom)|group\b.*\bby\b.{1,100}?\bhaving|open(?:rowset|owa_util|query)|load\b\W*?\bdata\b.*\binfile|(?:n?varcha|tbcreato)r|autonomous_transaction)\b|i(?:n(?:to\b\W*?\b(?:dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(?:f(?:\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|print\b\W*?\@\@|cast\b\W*?\()|c(?:(?:ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)\W*\(|o(?:(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|(?:mpres)?s|ercibility|alesce|t)\W*\(|llation\W*\(a))|d(?:(?:a(?:t(?:e(?:(_(add|format|sub))?|diff)|abase)|y(name|ofmonth|ofweek|ofyear)?)|e(?:(?:s_(de|en)cryp|faul)t|grees|code)|ump)\W*\(|bms_pipe\.receive_message\b)|(?:;\W*?\b(?:shutdown|drop)|\@\@version)\b|'(?:s(?:qloledb|a)|msdasql|dbo)'))"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-19";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959073";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:(?:s(?:t(?:d(?:dev(_pop|_samp)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha(1|2)?|oundex|chema|ig?n|pace|qrt)|i(?:s(null|_(free_lock|ipv4_compat|ipv4_mapped|ipv4|ipv6|not_null|not|null|used_lock))?|n(?:et6?_(aton|ntoa)|s(?:ert|tr)|terval)?|f(null)?)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(date|time|timestamp)|p(?:datexml|per)|uid(_short)?|case|ser)|l(?:o(?:ca(?:l(timestamp)?|te)|g(2|10)?|ad_file|wer)|ast(_day|_insert_id)?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|t(?:ime(stamp|stampadd|stampdiff|diff|_format|_to_sec)?|o_(base64|days|seconds|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(name)?|d)|d5)|r(?:e(?:p(?:lace|eat)|lease_lock|verse)|o(?:w_count|und)|a(?:dians|nd)|ight|trim|pad)|f(?:i(?:eld(_in_set)?|nd_in_set)|rom_(base64|days|unixtime)|o(?:und_rows|rmat)|loor)|a(?:es_(?:de|en)crypt|s(?:cii(str)?|in)|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|p(?:o(?:sition|w(er)?)|eriod_(add|diff)|rocedure_analyse|assword|i)|b(?:i(?:t_(?:length|count|x?or|and)|n(_to_num)?)|enchmark)|e(?:x(?:p(?:ort_set)?|tract(value)?)|nc(?:rypt|ode)|lt)|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|g(?:r(?:oup_conca|eates)t|et_(format|lock))|o(?:(?:ld_passwo)?rd|ct(et_length)?)|we(?:ek(day|ofyear)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|(rawton?)?hex(toraw)?|qu(?:arter|ote)|(pg_)?sleep|year(week)?|d?count|xmltype|hour)\W*\(|\b(?:(?:s(?:elect\b(?:.{1,100}?\b(?:(?:length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(?:d(?:ump\b.*\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:sqlexec|sp_replwritetovarbin|sp_help|addextendedproc|is_srvrolemember|prepare|sp_password|execute(?:sql)?|makewebtask|oacreate)|ql_(?:longvarchar|variant))|xp_(?:reg(?:re(?:movemultistring|ad)|delete(?:value|key)|enum(?:value|key)s|addmultistring|write)|terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process|e(?:xecresultset|numdsn)|availablemedia|loginconfig|cmdshell|filelist|dirtree|makecab|ntsec)|u(?:nion\b.{1,100}?\bselect|tl_(?:file|http))|d(?:b(?:a_users|ms_java)|elete\b\W*?\bfrom)|group\b.*\bby\b.{1,100}?\bhaving|open(?:rowset|owa_util|query)|load\b\W*?\bdata\b.*\binfile|(?:n?varcha|tbcreato)r|autonomous_transaction)\b|i(?:n(?:to\b\W*?\b(?:dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(?:f(?:\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|print\b\W*?\@\@|cast\b\W*?\()|c(?:(?:ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)\W*\(|o(?:(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|(?:mpres)?s|ercibility|alesce|t)\W*\(|llation\W*\(a))|d(?:(?:a(?:t(?:e(?:(_(add|format|sub))?|diff)|abase)|y(name|ofmonth|ofweek|ofyear)?)|e(?:(?:s_(de|en)cryp|faul)t|grees|code)|ump)\W*\(|bms_pipe\.receive_message\b)|(?:;\W*?\b(?:shutdown|drop)|\@\@version)\b|'(?:s(?:qloledb|a)|msdasql|dbo)'))
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\W{4,}"){
      set req.http.X-Sec-RuleInfo = "SQL Character Anomaly Detection Alert - Repetative Non-Word Characters";
      set req.http.X-Sec-RuleId = "960024-2";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "([\~\!\@\#\$\%\^\&\*\(\)\-\+\=\{\}\[\]\|\:\;\"\'\´\’\‘\`\<\>].*){6,}"){
      set req.http.X-Sec-RuleInfo = "Restricted SQL Character Anomaly Detection Alert - Total # of special characters exceeded";
      set req.http.X-Sec-RuleId = "981172-2";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "([\~\!\@\#\$\%\^\&\*\(\)\-\+\=\{\}\[\]\|\:\;\"\'\´\’\‘\`\<\>].*){6,}"){
      set req.http.X-Sec-RuleInfo = "Restricted SQL Character Anomaly Detection Alert - Total # of special characters exceeded";
      set req.http.X-Sec-RuleId = "981172-2";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "([\~\!\@\#\$\%\^\&\*\(\)\-\+\=\{\}\[\]\|\:\;\"\'\´\’\‘\`\<\>].*){4,}"){
      set req.http.X-Sec-RuleInfo = "Restricted SQL Character Anomaly Detection Alert - Total # of special characters exceeded";
      set req.http.X-Sec-RuleId = "981173-2";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "([\~\!\@\#\$\%\^\&\*\(\)\-\+\=\{\}\[\]\|\:\;\"\'\´\’\‘\`\<\>].*){4,}"){
      set req.http.X-Sec-RuleInfo = "Restricted SQL Character Anomaly Detection Alert - Total # of special characters exceeded";
      set req.http.X-Sec-RuleId = "981173-2";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "([\~\!\@\#\$\%\^\&\*\(\)\-\+\=\{\}\[\]\|\:\;\"\'\´\’\‘\`\<\>].*){4,}"){
      set req.http.X-Sec-RuleInfo = "Restricted SQL Character Anomaly Detection Alert - Total # of special characters exceeded";
      set req.http.X-Sec-RuleId = "981173-2";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* ([\~\!\@\#\$\%\^\&\*\(\)\-\+\=\{\}\[\]\|\:\;\"\'\´\’\‘\`\<\>].*){4,}
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:(sleep\((\s*)(\d*)(\s*)\)|benchmark\((.*)\,(.*)\))))"){
      set req.http.X-Sec-RuleInfo = "Detects blind sqli tests using sleep() or benchmark().";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981272";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:(sleep\((\s*)(\d*)(\s*)\)|benchmark\((.*)\,(.*)\))))"){
      set req.http.X-Sec-RuleInfo = "Detects blind sqli tests using sleep() or benchmark().";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981272";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:(sleep\((\s*)(\d*)(\s*)\)|benchmark\((.*)\,(.*)\))))"){
      set req.http.X-Sec-RuleInfo = "Detects blind sqli tests using sleep() or benchmark().";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981272";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:(sleep\((\s*)(\d*)(\s*)\)|benchmark\((.*)\,(.*)\))))"){
      set req.http.X-Sec-RuleInfo = "Detects blind sqli tests using sleep() or benchmark().";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981272";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:(sleep\((\s*)(\d*)(\s*)\)|benchmark\((.*)\,(.*)\))))"){
      set req.http.X-Sec-RuleInfo = "Detects blind sqli tests using sleep() or benchmark().";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981272";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:(sleep\((\s*)(\d*)(\s*)\)|benchmark\((.*)\,(.*)\))))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:\d(\"|'|`|´|’|‘)\s+(\"|'|`|´|’|‘)\s+\d)|(?:^admin\s*(\"|'|`|´|’|‘)|(\/\*)+(\"|'|`|´|’|‘)+\s?(?:--|#|\/\*|{)?)|(?:(\"|'|`|´|’|‘)\s*x?or|div|like|between|and[\w\s-]+\s*[+<>=(),-]\s*[\d(\"|'|`|´|’|‘)])|(?:(\"|'|`|´|’|‘)\s*[^\w\s]?=\s*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\W*[+=]+\W*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[!=|][\d\s!=+-]+.*[(\"|'|`|´|’|‘)(].*$)|(?:(\"|'|`|´|’|‘)\s*[!=|][\d\s!=]+.*\d+$)|(?:(\"|'|`|´|’|‘)\s*like\W+[\w(\"|'|`|´|’|‘)(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:(\"|'|`|´|’|‘)[<>~]+(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 1/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981244";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:\d(\"|'|`|´|’|‘)\s+(\"|'|`|´|’|‘)\s+\d)|(?:^admin\s*(\"|'|`|´|’|‘)|(\/\*)+(\"|'|`|´|’|‘)+\s?(?:--|#|\/\*|{)?)|(?:(\"|'|`|´|’|‘)\s*x?or|div|like|between|and[\w\s-]+\s*[+<>=(),-]\s*[\d(\"|'|`|´|’|‘)])|(?:(\"|'|`|´|’|‘)\s*[^\w\s]?=\s*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\W*[+=]+\W*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[!=|][\d\s!=+-]+.*[(\"|'|`|´|’|‘)(].*$)|(?:(\"|'|`|´|’|‘)\s*[!=|][\d\s!=]+.*\d+$)|(?:(\"|'|`|´|’|‘)\s*like\W+[\w(\"|'|`|´|’|‘)(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:(\"|'|`|´|’|‘)[<>~]+(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 1/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981244";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:\d(\"|'|`|´|’|‘)\s+(\"|'|`|´|’|‘)\s+\d)|(?:^admin\s*(\"|'|`|´|’|‘)|(\/\*)+(\"|'|`|´|’|‘)+\s?(?:--|#|\/\*|{)?)|(?:(\"|'|`|´|’|‘)\s*x?or|div|like|between|and[\w\s-]+\s*[+<>=(),-]\s*[\d(\"|'|`|´|’|‘)])|(?:(\"|'|`|´|’|‘)\s*[^\w\s]?=\s*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\W*[+=]+\W*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[!=|][\d\s!=+-]+.*[(\"|'|`|´|’|‘)(].*$)|(?:(\"|'|`|´|’|‘)\s*[!=|][\d\s!=]+.*\d+$)|(?:(\"|'|`|´|’|‘)\s*like\W+[\w(\"|'|`|´|’|‘)(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:(\"|'|`|´|’|‘)[<>~]+(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 1/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981244";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:\d(\"|'|`|´|’|‘)\s+(\"|'|`|´|’|‘)\s+\d)|(?:^admin\s*(\"|'|`|´|’|‘)|(\/\*)+(\"|'|`|´|’|‘)+\s?(?:--|#|\/\*|{)?)|(?:(\"|'|`|´|’|‘)\s*x?or|div|like|between|and[\w\s-]+\s*[+<>=(),-]\s*[\d(\"|'|`|´|’|‘)])|(?:(\"|'|`|´|’|‘)\s*[^\w\s]?=\s*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\W*[+=]+\W*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[!=|][\d\s!=+-]+.*[(\"|'|`|´|’|‘)(].*$)|(?:(\"|'|`|´|’|‘)\s*[!=|][\d\s!=]+.*\d+$)|(?:(\"|'|`|´|’|‘)\s*like\W+[\w(\"|'|`|´|’|‘)(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:(\"|'|`|´|’|‘)[<>~]+(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 1/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981244";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:\d(\"|'|`|´|’|‘)\s+(\"|'|`|´|’|‘)\s+\d)|(?:^admin\s*(\"|'|`|´|’|‘)|(\/\*)+(\"|'|`|´|’|‘)+\s?(?:--|#|\/\*|{)?)|(?:(\"|'|`|´|’|‘)\s*x?or|div|like|between|and[\w\s-]+\s*[+<>=(),-]\s*[\d(\"|'|`|´|’|‘)])|(?:(\"|'|`|´|’|‘)\s*[^\w\s]?=\s*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\W*[+=]+\W*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[!=|][\d\s!=+-]+.*[(\"|'|`|´|’|‘)(].*$)|(?:(\"|'|`|´|’|‘)\s*[!=|][\d\s!=]+.*\d+$)|(?:(\"|'|`|´|’|‘)\s*like\W+[\w(\"|'|`|´|’|‘)(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:(\"|'|`|´|’|‘)[<>~]+(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 1/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981244";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:\d(\"|'|`|´|’|‘)\s+(\"|'|`|´|’|‘)\s+\d)|(?:^admin\s*(\"|'|`|´|’|‘)|(\/\*)+(\"|'|`|´|’|‘)+\s?(?:--|#|\/\*|{)?)|(?:(\"|'|`|´|’|‘)\s*x?or|div|like|between|and[\w\s-]+\s*[+<>=(),-]\s*[\d(\"|'|`|´|’|‘)])|(?:(\"|'|`|´|’|‘)\s*[^\w\s]?=\s*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\W*[+=]+\W*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[!=|][\d\s!=+-]+.*[(\"|'|`|´|’|‘)(].*$)|(?:(\"|'|`|´|’|‘)\s*[!=|][\d\s!=]+.*\d+$)|(?:(\"|'|`|´|’|‘)\s*like\W+[\w(\"|'|`|´|’|‘)(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:(\"|'|`|´|’|‘)[<>~]+(\"|'|`|´|’|‘)))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:\sexec\s+xp_cmdshell)|(?:(\"|'|`|´|’|‘)\s*!\s*[(\"|'|`|´|’|‘)\w])|(?:from\W+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*\([^\)]*)|(?:(\"|'|`|´|’|‘);?\s*(?:select|union|having)\s*[^\s])|(?:\wiif\s*\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*select)|(?:select.*\w?user\()|(?:into[\s+]+(?:dump|out)file\s*(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects MSSQL code execution and information gathering attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981255";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:\sexec\s+xp_cmdshell)|(?:(\"|'|`|´|’|‘)\s*!\s*[(\"|'|`|´|’|‘)\w])|(?:from\W+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*\([^\)]*)|(?:(\"|'|`|´|’|‘);?\s*(?:select|union|having)\s*[^\s])|(?:\wiif\s*\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*select)|(?:select.*\w?user\()|(?:into[\s+]+(?:dump|out)file\s*(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects MSSQL code execution and information gathering attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981255";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:\sexec\s+xp_cmdshell)|(?:(\"|'|`|´|’|‘)\s*!\s*[(\"|'|`|´|’|‘)\w])|(?:from\W+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*\([^\)]*)|(?:(\"|'|`|´|’|‘);?\s*(?:select|union|having)\s*[^\s])|(?:\wiif\s*\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*select)|(?:select.*\w?user\()|(?:into[\s+]+(?:dump|out)file\s*(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects MSSQL code execution and information gathering attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981255";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:\sexec\s+xp_cmdshell)|(?:(\"|'|`|´|’|‘)\s*!\s*[(\"|'|`|´|’|‘)\w])|(?:from\W+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*\([^\)]*)|(?:(\"|'|`|´|’|‘);?\s*(?:select|union|having)\s*[^\s])|(?:\wiif\s*\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*select)|(?:select.*\w?user\()|(?:into[\s+]+(?:dump|out)file\s*(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects MSSQL code execution and information gathering attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981255";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:\sexec\s+xp_cmdshell)|(?:(\"|'|`|´|’|‘)\s*!\s*[(\"|'|`|´|’|‘)\w])|(?:from\W+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*\([^\)]*)|(?:(\"|'|`|´|’|‘);?\s*(?:select|union|having)\s*[^\s])|(?:\wiif\s*\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*select)|(?:select.*\w?user\()|(?:into[\s+]+(?:dump|out)file\s*(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects MSSQL code execution and information gathering attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981255";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:\sexec\s+xp_cmdshell)|(?:(\"|'|`|´|’|‘)\s*!\s*[(\"|'|`|´|’|‘)\w])|(?:from\W+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*\([^\)]*)|(?:(\"|'|`|´|’|‘);?\s*(?:select|union|having)\s*[^\s])|(?:\wiif\s*\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*select)|(?:select.*\w?user\()|(?:into[\s+]+(?:dump|out)file\s*(\"|'|`|´|’|‘)))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:,.*[)\da-f(\"|'|`|´|’|‘)](\"|'|`|´|’|‘)(?:(\"|'|`|´|’|‘).*(\"|'|`|´|’|‘)|\Z|[^(\"|'|`|´|’|‘)]+))|(?:\Wselect.+\W*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*\(\s*space\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL comment-/space-obfuscated injections and backtick termination";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981257";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:,.*[)\da-f(\"|'|`|´|’|‘)](\"|'|`|´|’|‘)(?:(\"|'|`|´|’|‘).*(\"|'|`|´|’|‘)|\Z|[^(\"|'|`|´|’|‘)]+))|(?:\Wselect.+\W*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*\(\s*space\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL comment-/space-obfuscated injections and backtick termination";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981257";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:,.*[)\da-f(\"|'|`|´|’|‘)](\"|'|`|´|’|‘)(?:(\"|'|`|´|’|‘).*(\"|'|`|´|’|‘)|\Z|[^(\"|'|`|´|’|‘)]+))|(?:\Wselect.+\W*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*\(\s*space\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL comment-/space-obfuscated injections and backtick termination";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981257";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:,.*[)\da-f(\"|'|`|´|’|‘)](\"|'|`|´|’|‘)(?:(\"|'|`|´|’|‘).*(\"|'|`|´|’|‘)|\Z|[^(\"|'|`|´|’|‘)]+))|(?:\Wselect.+\W*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*\(\s*space\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL comment-/space-obfuscated injections and backtick termination";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981257";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:,.*[)\da-f(\"|'|`|´|’|‘)](\"|'|`|´|’|‘)(?:(\"|'|`|´|’|‘).*(\"|'|`|´|’|‘)|\Z|[^(\"|'|`|´|’|‘)]+))|(?:\Wselect.+\W*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*\(\s*space\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL comment-/space-obfuscated injections and backtick termination";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981257";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:,.*[)\da-f(\"|'|`|´|’|‘)](\"|'|`|´|’|‘)(?:(\"|'|`|´|’|‘).*(\"|'|`|´|’|‘)|\Z|[^(\"|'|`|´|’|‘)]+))|(?:\Wselect.+\W*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*\(\s*space\s*\())
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:@.+=\s*\(\s*select)|(?:\d+\s*x?or|div|like|between|and\s*\d+\s*[\-+])|(?:\/\w+;?\s+(?:having|and|x?or|div|like|between|and|select)\W)|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[(\"|'|`|´|’|‘)=()]))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981248";
      # chained rule
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:@.+=\s*\(\s*select)|(?:\d+\s*x?or|div|like|between|and\s*\d+\s*[\-+])|(?:\/\w+;?\s+(?:having|and|x?or|div|like|between|and|select)\W)|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[(\"|'|`|´|’|‘)=()]))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981248";
      # chained rule
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:@.+=\s*\(\s*select)|(?:\d+\s*x?or|div|like|between|and\s*\d+\s*[\-+])|(?:\/\w+;?\s+(?:having|and|x?or|div|like|between|and|select)\W)|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[(\"|'|`|´|’|‘)=()]))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981248";
      # chained rule
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:@.+=\s*\(\s*select)|(?:\d+\s*x?or|div|like|between|and\s*\d+\s*[\-+])|(?:\/\w+;?\s+(?:having|and|x?or|div|like|between|and|select)\W)|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[(\"|'|`|´|’|‘)=()]))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981248";
      # chained rule
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:@.+=\s*\(\s*select)|(?:\d+\s*x?or|div|like|between|and\s*\d+\s*[\-+])|(?:\/\w+;?\s+(?:having|and|x?or|div|like|between|and|select)\W)|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[(\"|'|`|´|’|‘)=()]))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981248";
      # chained rule
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:@.+=\s*\(\s*select)|(?:\d+\s*x?or|div|like|between|and\s*\d+\s*[\-+])|(?:\/\w+;?\s+(?:having|and|x?or|div|like|between|and|select)\W)|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[(\"|'|`|´|’|‘)=()]))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:^(-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|2.2250738585072007e-308|1e309)$))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981277";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:^(-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|2.2250738585072007e-308|1e309)$))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981277";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:^(-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|2.2250738585072007e-308|1e309)$))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981277";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:^(-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|2.2250738585072007e-308|1e309)$))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981277";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:^(-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|2.2250738585072007e-308|1e309)$))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981277";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:^(-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|2.2250738585072007e-308|1e309)$))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*\(?\s*\w+))"){
      set req.http.X-Sec-RuleInfo = "Detects SQL benchmark and sleep injection attempts including conditional queries";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981250";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*\(?\s*\w+))"){
      set req.http.X-Sec-RuleInfo = "Detects SQL benchmark and sleep injection attempts including conditional queries";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981250";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*\(?\s*\w+))"){
      set req.http.X-Sec-RuleInfo = "Detects SQL benchmark and sleep injection attempts including conditional queries";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981250";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*\(?\s*\w+))"){
      set req.http.X-Sec-RuleInfo = "Detects SQL benchmark and sleep injection attempts including conditional queries";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981250";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*\(?\s*\w+))"){
      set req.http.X-Sec-RuleInfo = "Detects SQL benchmark and sleep injection attempts including conditional queries";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981250";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*\(?\s*\w+))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~]))"){
      set req.http.X-Sec-RuleInfo = "Detects conditional SQL injection attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981241";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~]))"){
      set req.http.X-Sec-RuleInfo = "Detects conditional SQL injection attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981241";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~]))"){
      set req.http.X-Sec-RuleInfo = "Detects conditional SQL injection attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981241";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~]))"){
      set req.http.X-Sec-RuleInfo = "Detects conditional SQL injection attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981241";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~]))"){
      set req.http.X-Sec-RuleInfo = "Detects conditional SQL injection attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981241";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~]))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:alter\s*\w+.*character\s+set\s+\w+)|((\"|'|`|´|’|‘);\s*waitfor\s+time\s+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘);.*:\s*goto))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL charset switch and MSSQL DoS attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981252";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:alter\s*\w+.*character\s+set\s+\w+)|((\"|'|`|´|’|‘);\s*waitfor\s+time\s+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘);.*:\s*goto))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL charset switch and MSSQL DoS attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981252";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:alter\s*\w+.*character\s+set\s+\w+)|((\"|'|`|´|’|‘);\s*waitfor\s+time\s+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘);.*:\s*goto))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL charset switch and MSSQL DoS attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981252";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:alter\s*\w+.*character\s+set\s+\w+)|((\"|'|`|´|’|‘);\s*waitfor\s+time\s+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘);.*:\s*goto))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL charset switch and MSSQL DoS attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981252";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:alter\s*\w+.*character\s+set\s+\w+)|((\"|'|`|´|’|‘);\s*waitfor\s+time\s+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘);.*:\s*goto))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL charset switch and MSSQL DoS attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981252";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:alter\s*\w+.*character\s+set\s+\w+)|((\"|'|`|´|’|‘);\s*waitfor\s+time\s+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘);.*:\s*goto))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:merge.*using\s*\()|(execute\s*immediate\s*(\"|'|`|´|’|‘))|(?:\W+\d*\s*having\s*[^\s\-])|(?:match\s*[\w(),+-]+\s*against\s*\())"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981256";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:merge.*using\s*\()|(execute\s*immediate\s*(\"|'|`|´|’|‘))|(?:\W+\d*\s*having\s*[^\s\-])|(?:match\s*[\w(),+-]+\s*against\s*\())"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981256";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:merge.*using\s*\()|(execute\s*immediate\s*(\"|'|`|´|’|‘))|(?:\W+\d*\s*having\s*[^\s\-])|(?:match\s*[\w(),+-]+\s*against\s*\())"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981256";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:merge.*using\s*\()|(execute\s*immediate\s*(\"|'|`|´|’|‘))|(?:\W+\d*\s*having\s*[^\s\-])|(?:match\s*[\w(),+-]+\s*against\s*\())"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981256";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:merge.*using\s*\()|(execute\s*immediate\s*(\"|'|`|´|’|‘))|(?:\W+\d*\s*having\s*[^\s\-])|(?:match\s*[\w(),+-]+\s*against\s*\())"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981256";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:merge.*using\s*\()|(execute\s*immediate\s*(\"|'|`|´|’|‘))|(?:\W+\d*\s*having\s*[^\s\-])|(?:match\s*[\w(),+-]+\s*against\s*\())
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:union\s*(?:all|distinct|[(!@]*)?\s*[([]*\s*select)|(?:\w+\s+like\s+(\"|'|`|´|’|‘))|(?:like\s*(\"|'|`|´|’|‘)\%)|(?:(\"|'|`|´|’|‘)\s*like\W*[(\"|'|`|´|’|‘)\d])|(?:(\"|'|`|´|’|‘)\s*(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:(\"|'|`|´|’|‘)\s*\*\s*\w+\W+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[^?\w\s=.,;)(]+\s*[(@(\"|'|`|´|’|‘)]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,(\"|'|`|´|’|‘)-]+from)|(?:find_in_set\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 2/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981245";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:union\s*(?:all|distinct|[(!@]*)?\s*[([]*\s*select)|(?:\w+\s+like\s+(\"|'|`|´|’|‘))|(?:like\s*(\"|'|`|´|’|‘)\%)|(?:(\"|'|`|´|’|‘)\s*like\W*[(\"|'|`|´|’|‘)\d])|(?:(\"|'|`|´|’|‘)\s*(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:(\"|'|`|´|’|‘)\s*\*\s*\w+\W+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[^?\w\s=.,;)(]+\s*[(@(\"|'|`|´|’|‘)]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,(\"|'|`|´|’|‘)-]+from)|(?:find_in_set\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 2/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981245";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:union\s*(?:all|distinct|[(!@]*)?\s*[([]*\s*select)|(?:\w+\s+like\s+(\"|'|`|´|’|‘))|(?:like\s*(\"|'|`|´|’|‘)\%)|(?:(\"|'|`|´|’|‘)\s*like\W*[(\"|'|`|´|’|‘)\d])|(?:(\"|'|`|´|’|‘)\s*(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:(\"|'|`|´|’|‘)\s*\*\s*\w+\W+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[^?\w\s=.,;)(]+\s*[(@(\"|'|`|´|’|‘)]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,(\"|'|`|´|’|‘)-]+from)|(?:find_in_set\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 2/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981245";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:union\s*(?:all|distinct|[(!@]*)?\s*[([]*\s*select)|(?:\w+\s+like\s+(\"|'|`|´|’|‘))|(?:like\s*(\"|'|`|´|’|‘)\%)|(?:(\"|'|`|´|’|‘)\s*like\W*[(\"|'|`|´|’|‘)\d])|(?:(\"|'|`|´|’|‘)\s*(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:(\"|'|`|´|’|‘)\s*\*\s*\w+\W+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[^?\w\s=.,;)(]+\s*[(@(\"|'|`|´|’|‘)]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,(\"|'|`|´|’|‘)-]+from)|(?:find_in_set\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 2/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981245";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:union\s*(?:all|distinct|[(!@]*)?\s*[([]*\s*select)|(?:\w+\s+like\s+(\"|'|`|´|’|‘))|(?:like\s*(\"|'|`|´|’|‘)\%)|(?:(\"|'|`|´|’|‘)\s*like\W*[(\"|'|`|´|’|‘)\d])|(?:(\"|'|`|´|’|‘)\s*(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:(\"|'|`|´|’|‘)\s*\*\s*\w+\W+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[^?\w\s=.,;)(]+\s*[(@(\"|'|`|´|’|‘)]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,(\"|'|`|´|’|‘)-]+from)|(?:find_in_set\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 2/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981245";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:union\s*(?:all|distinct|[(!@]*)?\s*[([]*\s*select)|(?:\w+\s+like\s+(\"|'|`|´|’|‘))|(?:like\s*(\"|'|`|´|’|‘)\%)|(?:(\"|'|`|´|’|‘)\s*like\W*[(\"|'|`|´|’|‘)\d])|(?:(\"|'|`|´|’|‘)\s*(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:(\"|'|`|´|’|‘)\s*\*\s*\w+\W+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[^?\w\s=.,;)(]+\s*[(@(\"|'|`|´|’|‘)]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,(\"|'|`|´|’|‘)-]+from)|(?:find_in_set\s*\())
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:(union(.*)select(.*)from)))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981276";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:(union(.*)select(.*)from)))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981276";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:(union(.*)select(.*)from)))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981276";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:(union(.*)select(.*)from)))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981276";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:(union(.*)select(.*)from)))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981276";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:(union(.*)select(.*)from)))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:select\s*pg_sleep)|(?:waitfor\s*delay\s?(\"|'|`|´|’|‘)+\s?\d)|(?:;\s*shutdown\s*(?:;|--|#|\/\*|{)))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981254";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:select\s*pg_sleep)|(?:waitfor\s*delay\s?(\"|'|`|´|’|‘)+\s?\d)|(?:;\s*shutdown\s*(?:;|--|#|\/\*|{)))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981254";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:select\s*pg_sleep)|(?:waitfor\s*delay\s?(\"|'|`|´|’|‘)+\s?\d)|(?:;\s*shutdown\s*(?:;|--|#|\/\*|{)))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981254";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:select\s*pg_sleep)|(?:waitfor\s*delay\s?(\"|'|`|´|’|‘)+\s?\d)|(?:;\s*shutdown\s*(?:;|--|#|\/\*|{)))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981254";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:select\s*pg_sleep)|(?:waitfor\s*delay\s?(\"|'|`|´|’|‘)+\s?\d)|(?:;\s*shutdown\s*(?:;|--|#|\/\*|{)))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981254";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:select\s*pg_sleep)|(?:waitfor\s*delay\s?(\"|'|`|´|’|‘)+\s?\d)|(?:;\s*shutdown\s*(?:;|--|#|\/\*|{)))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|x?or|div|like|between|and)\]))"){
      set req.http.X-Sec-RuleInfo = "Finds basic MongoDB SQL injection attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981270";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|x?or|div|like|between|and)\]))"){
      set req.http.X-Sec-RuleInfo = "Finds basic MongoDB SQL injection attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981270";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|x?or|div|like|between|and)\]))"){
      set req.http.X-Sec-RuleInfo = "Finds basic MongoDB SQL injection attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981270";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|x?or|div|like|between|and)\]))"){
      set req.http.X-Sec-RuleInfo = "Finds basic MongoDB SQL injection attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981270";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|x?or|div|like|between|and)\]))"){
      set req.http.X-Sec-RuleInfo = "Finds basic MongoDB SQL injection attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981270";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|x?or|div|like|between|and)\]))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:\)\s*when\s*\d+\s*then)|(?:(\"|'|`|´|’|‘)\s*(?:#|--|{))|(?:\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?x?or|div|like|between|and|not)\s+|\|\||\&\&)\s*\w+\())"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981240";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:\)\s*when\s*\d+\s*then)|(?:(\"|'|`|´|’|‘)\s*(?:#|--|{))|(?:\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?x?or|div|like|between|and|not)\s+|\|\||\&\&)\s*\w+\())"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981240";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:\)\s*when\s*\d+\s*then)|(?:(\"|'|`|´|’|‘)\s*(?:#|--|{))|(?:\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?x?or|div|like|between|and|not)\s+|\|\||\&\&)\s*\w+\())"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981240";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:\)\s*when\s*\d+\s*then)|(?:(\"|'|`|´|’|‘)\s*(?:#|--|{))|(?:\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?x?or|div|like|between|and|not)\s+|\|\||\&\&)\s*\w+\())"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981240";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:\)\s*when\s*\d+\s*then)|(?:(\"|'|`|´|’|‘)\s*(?:#|--|{))|(?:\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?x?or|div|like|between|and|not)\s+|\|\||\&\&)\s*\w+\())"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981240";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:\)\s*when\s*\d+\s*then)|(?:(\"|'|`|´|’|‘)\s*(?:#|--|{))|(?:\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?x?or|div|like|between|and|not)\s+|\|\||\&\&)\s*\w+\())
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:(\"|'|`|´|’|‘)\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w(\"|'|`|´|’|‘)\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+(\"|'|`|´|’|‘)\w)|(?:(\"|'|`|´|’|‘);\s*(?:if|while|begin))|(?:(\"|'|`|´|’|‘)[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(]))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981249";
      # chained rule
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:(\"|'|`|´|’|‘)\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w(\"|'|`|´|’|‘)\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+(\"|'|`|´|’|‘)\w)|(?:(\"|'|`|´|’|‘);\s*(?:if|while|begin))|(?:(\"|'|`|´|’|‘)[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(]))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981249";
      # chained rule
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:(\"|'|`|´|’|‘)\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w(\"|'|`|´|’|‘)\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+(\"|'|`|´|’|‘)\w)|(?:(\"|'|`|´|’|‘);\s*(?:if|while|begin))|(?:(\"|'|`|´|’|‘)[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(]))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981249";
      # chained rule
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:(\"|'|`|´|’|‘)\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w(\"|'|`|´|’|‘)\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+(\"|'|`|´|’|‘)\w)|(?:(\"|'|`|´|’|‘);\s*(?:if|while|begin))|(?:(\"|'|`|´|’|‘)[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(]))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981249";
      # chained rule
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:(\"|'|`|´|’|‘)\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w(\"|'|`|´|’|‘)\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+(\"|'|`|´|’|‘)\w)|(?:(\"|'|`|´|’|‘);\s*(?:if|while|begin))|(?:(\"|'|`|´|’|‘)[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(]))"){
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981249";
      # chained rule
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:(\"|'|`|´|’|‘)\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w(\"|'|`|´|’|‘)\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+(\"|'|`|´|’|‘)\w)|(?:(\"|'|`|´|’|‘);\s*(?:if|while|begin))|(?:(\"|'|`|´|’|‘)[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(]))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL and PostgreSQL stored procedure/function injections";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981253";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL and PostgreSQL stored procedure/function injections";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981253";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL and PostgreSQL stored procedure/function injections";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981253";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL and PostgreSQL stored procedure/function injections";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981253";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL and PostgreSQL stored procedure/function injections";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981253";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:(\"|'|`|´|’|‘)\s*(x?or|div|like|between|and)\s*(\"|'|`|´|’|‘)?\d)|(?:\\\\x(?:23|27|3d))|(?:^.?(\"|'|`|´|’|‘)$)|(?:(?:^[(\"|'|`|´|’|‘)\\\\]*(?:[\d(\"|'|`|´|’|‘)]+|[^(\"|'|`|´|’|‘)]+(\"|'|`|´|’|‘)))+\s*(?:n?and|x?x?or|div|like|between|and|not|\|\||\&\&)\s*[\w(\"|'|`|´|’|‘)[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*(\"|'|`|´|’|‘)\s*\w)|(?:@\w+\s+(and|x?or|div|like|between|and)\s*[(\"|'|`|´|’|‘)\d]+)|(?:@[\w-]+\s(and|x?or|div|like|between|and)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*(\"|'|`|´|’|‘).)|(?:\Winformation_schema|table_name\W))"){
      set req.http.X-Sec-RuleInfo = "Detects classic SQL injection probings 1/2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981242";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:(\"|'|`|´|’|‘)\s*(x?or|div|like|between|and)\s*(\"|'|`|´|’|‘)?\d)|(?:\\\\x(?:23|27|3d))|(?:^.?(\"|'|`|´|’|‘)$)|(?:(?:^[(\"|'|`|´|’|‘)\\\\]*(?:[\d(\"|'|`|´|’|‘)]+|[^(\"|'|`|´|’|‘)]+(\"|'|`|´|’|‘)))+\s*(?:n?and|x?x?or|div|like|between|and|not|\|\||\&\&)\s*[\w(\"|'|`|´|’|‘)[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*(\"|'|`|´|’|‘)\s*\w)|(?:@\w+\s+(and|x?or|div|like|between|and)\s*[(\"|'|`|´|’|‘)\d]+)|(?:@[\w-]+\s(and|x?or|div|like|between|and)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*(\"|'|`|´|’|‘).)|(?:\Winformation_schema|table_name\W))"){
      set req.http.X-Sec-RuleInfo = "Detects classic SQL injection probings 1/2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981242";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:(\"|'|`|´|’|‘)\s*(x?or|div|like|between|and)\s*(\"|'|`|´|’|‘)?\d)|(?:\\\\x(?:23|27|3d))|(?:^.?(\"|'|`|´|’|‘)$)|(?:(?:^[(\"|'|`|´|’|‘)\\\\]*(?:[\d(\"|'|`|´|’|‘)]+|[^(\"|'|`|´|’|‘)]+(\"|'|`|´|’|‘)))+\s*(?:n?and|x?x?or|div|like|between|and|not|\|\||\&\&)\s*[\w(\"|'|`|´|’|‘)[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*(\"|'|`|´|’|‘)\s*\w)|(?:@\w+\s+(and|x?or|div|like|between|and)\s*[(\"|'|`|´|’|‘)\d]+)|(?:@[\w-]+\s(and|x?or|div|like|between|and)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*(\"|'|`|´|’|‘).)|(?:\Winformation_schema|table_name\W))"){
      set req.http.X-Sec-RuleInfo = "Detects classic SQL injection probings 1/2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981242";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:(\"|'|`|´|’|‘)\s*(x?or|div|like|between|and)\s*(\"|'|`|´|’|‘)?\d)|(?:\\\\x(?:23|27|3d))|(?:^.?(\"|'|`|´|’|‘)$)|(?:(?:^[(\"|'|`|´|’|‘)\\\\]*(?:[\d(\"|'|`|´|’|‘)]+|[^(\"|'|`|´|’|‘)]+(\"|'|`|´|’|‘)))+\s*(?:n?and|x?x?or|div|like|between|and|not|\|\||\&\&)\s*[\w(\"|'|`|´|’|‘)[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*(\"|'|`|´|’|‘)\s*\w)|(?:@\w+\s+(and|x?or|div|like|between|and)\s*[(\"|'|`|´|’|‘)\d]+)|(?:@[\w-]+\s(and|x?or|div|like|between|and)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*(\"|'|`|´|’|‘).)|(?:\Winformation_schema|table_name\W))"){
      set req.http.X-Sec-RuleInfo = "Detects classic SQL injection probings 1/2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981242";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:(\"|'|`|´|’|‘)\s*(x?or|div|like|between|and)\s*(\"|'|`|´|’|‘)?\d)|(?:\\\\x(?:23|27|3d))|(?:^.?(\"|'|`|´|’|‘)$)|(?:(?:^[(\"|'|`|´|’|‘)\\\\]*(?:[\d(\"|'|`|´|’|‘)]+|[^(\"|'|`|´|’|‘)]+(\"|'|`|´|’|‘)))+\s*(?:n?and|x?x?or|div|like|between|and|not|\|\||\&\&)\s*[\w(\"|'|`|´|’|‘)[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*(\"|'|`|´|’|‘)\s*\w)|(?:@\w+\s+(and|x?or|div|like|between|and)\s*[(\"|'|`|´|’|‘)\d]+)|(?:@[\w-]+\s(and|x?or|div|like|between|and)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*(\"|'|`|´|’|‘).)|(?:\Winformation_schema|table_name\W))"){
      set req.http.X-Sec-RuleInfo = "Detects classic SQL injection probings 1/2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981242";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:(\"|'|`|´|’|‘)\s*(x?or|div|like|between|and)\s*(\"|'|`|´|’|‘)?\d)|(?:\\\\x(?:23|27|3d))|(?:^.?(\"|'|`|´|’|‘)$)|(?:(?:^[(\"|'|`|´|’|‘)\\\\]*(?:[\d(\"|'|`|´|’|‘)]+|[^(\"|'|`|´|’|‘)]+(\"|'|`|´|’|‘)))+\s*(?:n?and|x?x?or|div|like|between|and|not|\|\||\&\&)\s*[\w(\"|'|`|´|’|‘)[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*(\"|'|`|´|’|‘)\s*\w)|(?:@\w+\s+(and|x?or|div|like|between|and)\s*[(\"|'|`|´|’|‘)\d]+)|(?:@[\w-]+\s(and|x?or|div|like|between|and)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*(\"|'|`|´|’|‘).)|(?:\Winformation_schema|table_name\W))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:in\s*\(+\s*select)|(?:(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*(\"|'|`|´|’|‘)|[=\d]+x))|((\"|'|`|´|’|‘)\s*\d\s*(?:--|#))|(?:(\"|'|`|´|’|‘)[\%&<>^=]+\d\s*(=|x?or|div|like|between|and))|(?:(\"|'|`|´|’|‘)\W+[\w+-]+\s*=\s*\d\W+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*is\s*\d.+(\"|'|`|´|’|‘)?\w)|(?:(\"|'|`|´|’|‘)\|?[\w-]{3,}[^\w\s.,]+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*is\s*[\d.]+\s*\W.*(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 3/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981246";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:in\s*\(+\s*select)|(?:(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*(\"|'|`|´|’|‘)|[=\d]+x))|((\"|'|`|´|’|‘)\s*\d\s*(?:--|#))|(?:(\"|'|`|´|’|‘)[\%&<>^=]+\d\s*(=|x?or|div|like|between|and))|(?:(\"|'|`|´|’|‘)\W+[\w+-]+\s*=\s*\d\W+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*is\s*\d.+(\"|'|`|´|’|‘)?\w)|(?:(\"|'|`|´|’|‘)\|?[\w-]{3,}[^\w\s.,]+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*is\s*[\d.]+\s*\W.*(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 3/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981246";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:in\s*\(+\s*select)|(?:(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*(\"|'|`|´|’|‘)|[=\d]+x))|((\"|'|`|´|’|‘)\s*\d\s*(?:--|#))|(?:(\"|'|`|´|’|‘)[\%&<>^=]+\d\s*(=|x?or|div|like|between|and))|(?:(\"|'|`|´|’|‘)\W+[\w+-]+\s*=\s*\d\W+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*is\s*\d.+(\"|'|`|´|’|‘)?\w)|(?:(\"|'|`|´|’|‘)\|?[\w-]{3,}[^\w\s.,]+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*is\s*[\d.]+\s*\W.*(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 3/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981246";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:in\s*\(+\s*select)|(?:(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*(\"|'|`|´|’|‘)|[=\d]+x))|((\"|'|`|´|’|‘)\s*\d\s*(?:--|#))|(?:(\"|'|`|´|’|‘)[\%&<>^=]+\d\s*(=|x?or|div|like|between|and))|(?:(\"|'|`|´|’|‘)\W+[\w+-]+\s*=\s*\d\W+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*is\s*\d.+(\"|'|`|´|’|‘)?\w)|(?:(\"|'|`|´|’|‘)\|?[\w-]{3,}[^\w\s.,]+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*is\s*[\d.]+\s*\W.*(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 3/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981246";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:in\s*\(+\s*select)|(?:(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*(\"|'|`|´|’|‘)|[=\d]+x))|((\"|'|`|´|’|‘)\s*\d\s*(?:--|#))|(?:(\"|'|`|´|’|‘)[\%&<>^=]+\d\s*(=|x?or|div|like|between|and))|(?:(\"|'|`|´|’|‘)\W+[\w+-]+\s*=\s*\d\W+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*is\s*\d.+(\"|'|`|´|’|‘)?\w)|(?:(\"|'|`|´|’|‘)\|?[\w-]{3,}[^\w\s.,]+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*is\s*[\d.]+\s*\W.*(\"|'|`|´|’|‘)))"){
      set req.http.X-Sec-RuleInfo = "Detects basic SQL authentication bypass attempts 3/3";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981246";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:in\s*\(+\s*select)|(?:(?:n?and|x?x?or|div|like|between|and|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*(\"|'|`|´|’|‘)|[=\d]+x))|((\"|'|`|´|’|‘)\s*\d\s*(?:--|#))|(?:(\"|'|`|´|’|‘)[\%&<>^=]+\d\s*(=|x?or|div|like|between|and))|(?:(\"|'|`|´|’|‘)\W+[\w+-]+\s*=\s*\d\W+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*is\s*\d.+(\"|'|`|´|’|‘)?\w)|(?:(\"|'|`|´|’|‘)\|?[\w-]{3,}[^\w\s.,]+(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*is\s*[\d.]+\s*\W.*(\"|'|`|´|’|‘)))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,}))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL UDF injection and other data/structure manipulation attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981251";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,}))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL UDF injection and other data/structure manipulation attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981251";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,}))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL UDF injection and other data/structure manipulation attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981251";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,}))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL UDF injection and other data/structure manipulation attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981251";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,}))"){
      set req.http.X-Sec-RuleInfo = "Detects MySQL UDF injection and other data/structure manipulation attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981251";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,}))
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:[\d\W]\s+as\s*[(\"|'|`|´|’|‘)\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:(?:group_)concat|char|load_file)\s?\(?)|(?:end\s*\);)|((\"|'|`|´|’|‘)\s+regexp\W)|(?:[\s(]load_file\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects concatenated basic SQL injection and SQLLFI attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981247";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:[\d\W]\s+as\s*[(\"|'|`|´|’|‘)\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:(?:group_)concat|char|load_file)\s?\(?)|(?:end\s*\);)|((\"|'|`|´|’|‘)\s+regexp\W)|(?:[\s(]load_file\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects concatenated basic SQL injection and SQLLFI attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981247";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:[\d\W]\s+as\s*[(\"|'|`|´|’|‘)\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:(?:group_)concat|char|load_file)\s?\(?)|(?:end\s*\);)|((\"|'|`|´|’|‘)\s+regexp\W)|(?:[\s(]load_file\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects concatenated basic SQL injection and SQLLFI attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981247";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:[\d\W]\s+as\s*[(\"|'|`|´|’|‘)\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:(?:group_)concat|char|load_file)\s?\(?)|(?:end\s*\);)|((\"|'|`|´|’|‘)\s+regexp\W)|(?:[\s(]load_file\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects concatenated basic SQL injection and SQLLFI attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981247";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:[\d\W]\s+as\s*[(\"|'|`|´|’|‘)\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:(?:group_)concat|char|load_file)\s?\(?)|(?:end\s*\);)|((\"|'|`|´|’|‘)\s+regexp\W)|(?:[\s(]load_file\s*\())"){
      set req.http.X-Sec-RuleInfo = "Detects concatenated basic SQL injection and SQLLFI attempts";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981247";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:[\d\W]\s+as\s*[(\"|'|`|´|’|‘)\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:(?:group_)concat|char|load_file)\s?\(?)|(?:end\s*\);)|((\"|'|`|´|’|‘)\s+regexp\W)|(?:[\s(]load_file\s*\())
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?i:(?:(\"|'|`|´|’|‘)\s*\*.+(?:x?or|div|like|between|and|id)\W*(\"|'|`|´|’|‘)\d)|(?:\^(\"|'|`|´|’|‘))|(?:^[\w\s(\"|'|`|´|’|‘)-]+(?<=and\s)(?<=or|xor|div|like|between|and\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:(\"|'|`|´|’|‘)[\s\d]*[^\w\s]+\W*\d\W*.*[(\"|'|`|´|’|‘)\d])|(?:(\"|'|`|´|’|‘)\s*[^\w\s?]+\s*[^\w\s]+\s*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:(\"|'|`|´|’|‘).*\*\s*\d)|(?:(\"|'|`|´|’|‘)\s*x?or|div|like|between|and\s[^\d]+[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+(\"|'|`|´|’|‘)[^,]))"){
      set req.http.X-Sec-RuleInfo = "Detects classic SQL injection probings 2/2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981243";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?i:(?:(\"|'|`|´|’|‘)\s*\*.+(?:x?or|div|like|between|and|id)\W*(\"|'|`|´|’|‘)\d)|(?:\^(\"|'|`|´|’|‘))|(?:^[\w\s(\"|'|`|´|’|‘)-]+(?<=and\s)(?<=or|xor|div|like|between|and\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:(\"|'|`|´|’|‘)[\s\d]*[^\w\s]+\W*\d\W*.*[(\"|'|`|´|’|‘)\d])|(?:(\"|'|`|´|’|‘)\s*[^\w\s?]+\s*[^\w\s]+\s*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:(\"|'|`|´|’|‘).*\*\s*\d)|(?:(\"|'|`|´|’|‘)\s*x?or|div|like|between|and\s[^\d]+[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+(\"|'|`|´|’|‘)[^,]))"){
      set req.http.X-Sec-RuleInfo = "Detects classic SQL injection probings 2/2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981243";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?i:(?:(\"|'|`|´|’|‘)\s*\*.+(?:x?or|div|like|between|and|id)\W*(\"|'|`|´|’|‘)\d)|(?:\^(\"|'|`|´|’|‘))|(?:^[\w\s(\"|'|`|´|’|‘)-]+(?<=and\s)(?<=or|xor|div|like|between|and\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:(\"|'|`|´|’|‘)[\s\d]*[^\w\s]+\W*\d\W*.*[(\"|'|`|´|’|‘)\d])|(?:(\"|'|`|´|’|‘)\s*[^\w\s?]+\s*[^\w\s]+\s*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:(\"|'|`|´|’|‘).*\*\s*\d)|(?:(\"|'|`|´|’|‘)\s*x?or|div|like|between|and\s[^\d]+[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+(\"|'|`|´|’|‘)[^,]))"){
      set req.http.X-Sec-RuleInfo = "Detects classic SQL injection probings 2/2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981243";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:(?:(\"|'|`|´|’|‘)\s*\*.+(?:x?or|div|like|between|and|id)\W*(\"|'|`|´|’|‘)\d)|(?:\^(\"|'|`|´|’|‘))|(?:^[\w\s(\"|'|`|´|’|‘)-]+(?<=and\s)(?<=or|xor|div|like|between|and\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:(\"|'|`|´|’|‘)[\s\d]*[^\w\s]+\W*\d\W*.*[(\"|'|`|´|’|‘)\d])|(?:(\"|'|`|´|’|‘)\s*[^\w\s?]+\s*[^\w\s]+\s*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:(\"|'|`|´|’|‘).*\*\s*\d)|(?:(\"|'|`|´|’|‘)\s*x?or|div|like|between|and\s[^\d]+[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+(\"|'|`|´|’|‘)[^,]))"){
      set req.http.X-Sec-RuleInfo = "Detects classic SQL injection probings 2/2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981243";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?i:(?:(\"|'|`|´|’|‘)\s*\*.+(?:x?or|div|like|between|and|id)\W*(\"|'|`|´|’|‘)\d)|(?:\^(\"|'|`|´|’|‘))|(?:^[\w\s(\"|'|`|´|’|‘)-]+(?<=and\s)(?<=or|xor|div|like|between|and\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:(\"|'|`|´|’|‘)[\s\d]*[^\w\s]+\W*\d\W*.*[(\"|'|`|´|’|‘)\d])|(?:(\"|'|`|´|’|‘)\s*[^\w\s?]+\s*[^\w\s]+\s*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:(\"|'|`|´|’|‘).*\*\s*\d)|(?:(\"|'|`|´|’|‘)\s*x?or|div|like|between|and\s[^\d]+[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+(\"|'|`|´|’|‘)[^,]))"){
      set req.http.X-Sec-RuleInfo = "Detects classic SQL injection probings 2/2";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQLI";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/ID";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LFI";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "981243";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?i:(?:(\"|'|`|´|’|‘)\s*\*.+(?:x?or|div|like|between|and|id)\W*(\"|'|`|´|’|‘)\d)|(?:\^(\"|'|`|´|’|‘))|(?:^[\w\s(\"|'|`|´|’|‘)-]+(?<=and\s)(?<=or|xor|div|like|between|and\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:(\"|'|`|´|’|‘)[\s\d]*[^\w\s]+\W*\d\W*.*[(\"|'|`|´|’|‘)\d])|(?:(\"|'|`|´|’|‘)\s*[^\w\s?]+\s*[^\w\s]+\s*(\"|'|`|´|’|‘))|(?:(\"|'|`|´|’|‘)\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:(\"|'|`|´|’|‘).*\*\s*\d)|(?:(\"|'|`|´|’|‘)\s*x?or|div|like|between|and\s[^\d]+[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+(\"|'|`|´|’|‘)[^,]))
}

