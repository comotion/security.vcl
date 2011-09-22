sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950907";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950907";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950907";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950907";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950907";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  (?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|Referer|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|Referer|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|Referer|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      call sec_default_handler;
   }
   if(req.http.Referer ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))"){
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcf(?:usion_(?:d(?:bconnections_flush|ecrypt)|set(?:tings_refresh|odbcini)|getodbc(?:dsn|ini)|verifymail|encrypt)|_(?:(?:iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(?:password|username))|newinternal(?:adminsecurit|registr)y|admin_registry_(?:delete|set)|internaldebug|execute)\b"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950009";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcf(?:usion_(?:d(?:bconnections_flush|ecrypt)|set(?:tings_refresh|odbcini)|getodbc(?:dsn|ini)|verifymail|encrypt)|_(?:(?:iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(?:password|username))|newinternal(?:adminsecurit|registr)y|admin_registry_(?:delete|set)|internaldebug|execute)\b"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950009";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bcf(?:usion_(?:d(?:bconnections_flush|ecrypt)|set(?:tings_refresh|odbcini)|getodbc(?:dsn|ini)|verifymail|encrypt)|_(?:(?:iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(?:password|username))|newinternal(?:adminsecurit|registr)y|admin_registry_(?:delete|set)|internaldebug|execute)\b"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950009";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bcf(?:usion_(?:d(?:bconnections_flush|ecrypt)|set(?:tings_refresh|odbcini)|getodbc(?:dsn|ini)|verifymail|encrypt)|_(?:(?:iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(?:password|username))|newinternal(?:adminsecurit|registr)y|admin_registry_(?:delete|set)|internaldebug|execute)\b"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950009";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bcf(?:usion_(?:d(?:bconnections_flush|ecrypt)|set(?:tings_refresh|odbcini)|getodbc(?:dsn|ini)|verifymail|encrypt)|_(?:(?:iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(?:password|username))|newinternal(?:adminsecurit|registr)y|admin_registry_(?:delete|set)|internaldebug|execute)\b"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950009";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bcf(?:usion_(?:d(?:bconnections_flush|ecrypt)|set(?:tings_refresh|odbcini)|getodbc(?:dsn|ini)|verifymail|encrypt)|_(?:(?:iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(?:password|username))|newinternal(?:adminsecurit|registr)y|admin_registry_(?:delete|set)|internaldebug|execute)\b
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bcf(?:usion_(?:d(?:bconnections_flush|ecrypt)|set(?:tings_refresh|odbcini)|getodbc(?:dsn|ini)|verifymail|encrypt)|_(?:(?:iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(?:password|username))|newinternal(?:adminsecurit|registr)y|admin_registry_(?:delete|set)|internaldebug|execute)\b"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bcf(?:usion_(?:d(?:bconnections_flush|ecrypt)|set(?:tings_refresh|odbcini)|getodbc(?:dsn|ini)|verifymail|encrypt)|_(?:(?:iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(?:password|username))|newinternal(?:adminsecurit|registr)y|admin_registry_(?:delete|set)|internaldebug|execute)\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bcf(?:usion_(?:d(?:bconnections_flush|ecrypt)|set(?:tings_refresh|odbcini)|getodbc(?:dsn|ini)|verifymail|encrypt)|_(?:(?:iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(?:password|username))|newinternal(?:adminsecurit|registr)y|admin_registry_(?:delete|set)|internaldebug|execute)\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bcf(?:usion_(?:d(?:bconnections_flush|ecrypt)|set(?:tings_refresh|odbcini)|getodbc(?:dsn|ini)|verifymail|encrypt)|_(?:(?:iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(?:password|username))|newinternal(?:adminsecurit|registr)y|admin_registry_(?:delete|set)|internaldebug|execute)\b"){
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?:\((?:\W*?(?:objectc(?:ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])"){
      set req.http.X-Sec-RuleInfo = "LDAP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LDAP_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-29";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950010";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?:\((?:\W*?(?:objectc(?:ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])"){
      set req.http.X-Sec-RuleInfo = "LDAP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LDAP_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-29";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950010";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?:\((?:\W*?(?:objectc(?:ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])"){
      set req.http.X-Sec-RuleInfo = "LDAP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LDAP_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-29";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950010";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?:\((?:\W*?(?:objectc(?:ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])"){
      set req.http.X-Sec-RuleInfo = "LDAP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LDAP_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-29";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950010";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\((?:\W*?(?:objectc(?:ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])"){
      set req.http.X-Sec-RuleInfo = "LDAP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LDAP_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-29";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950010";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?:\((?:\W*?(?:objectc(?:ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "(?:\((?:\W*?(?:objectc(?:ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\((?:\W*?(?:objectc(?:ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  (?:\((?:\W*?(?:objectc(?:ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "(?:\((?:\W*?(?:objectc(?:ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])"){
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "<!--\W*?#\W*?(?:e(?:cho|xec)|printenv|include|cmd)"){
      set req.http.X-Sec-RuleInfo = "SSI injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SSI_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-36";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950011";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "<!--\W*?#\W*?(?:e(?:cho|xec)|printenv|include|cmd)"){
      set req.http.X-Sec-RuleInfo = "SSI injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SSI_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-36";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950011";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "<!--\W*?#\W*?(?:e(?:cho|xec)|printenv|include|cmd)"){
      set req.http.X-Sec-RuleInfo = "SSI injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SSI_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-36";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950011";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "<!--\W*?#\W*?(?:e(?:cho|xec)|printenv|include|cmd)"){
      set req.http.X-Sec-RuleInfo = "SSI injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SSI_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-36";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950011";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "<!--\W*?#\W*?(?:e(?:cho|xec)|printenv|include|cmd)"){
      set req.http.X-Sec-RuleInfo = "SSI injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SSI_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-36";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950011";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* <!--\W*?#\W*?(?:e(?:cho|xec)|printenv|include|cmd)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "<!--\W*?#\W*?(?:e(?:cho|xec)|printenv|include|cmd)"){
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "<!--\W*?#\W*?(?:e(?:cho|xec)|printenv|include|cmd)"){
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "<!--\W*?#\W*?(?:e(?:cho|xec)|printenv|include|cmd)"){
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "<!--\W*?#\W*?(?:e(?:cho|xec)|printenv|include|cmd)"){
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "<!--\W*?#\W*?(?:e(?:cho|xec)|printenv|include|cmd)"){
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* <!--\W*?#\W*?(?:e(?:cho|xec)|printenv|include|cmd)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "http:\/\/[\w\.]+?\/.*?\.pdf\b[^\x0d\x0a]*#"){
      set req.http.X-Sec-RuleId = "950018";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "http:\/\/[\w\.]+?\/.*?\.pdf\b[^\x0d\x0a]*#"){
      set req.http.X-Sec-RuleId = "950018";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "http:\/\/[\w\.]+?\/.*?\.pdf\b[^\x0d\x0a]*#"){
      set req.http.X-Sec-RuleId = "950018";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "http:\/\/[\w\.]+?\/.*?\.pdf\b[^\x0d\x0a]*#"){
      set req.http.X-Sec-RuleId = "950018";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "http:\/\/[\w\.]+?\/.*?\.pdf\b[^\x0d\x0a]*#"){
      set req.http.X-Sec-RuleId = "950018";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* http:\/\/[\w\.]+?\/.*?\.pdf\b[^\x0d\x0a]*#
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\n\r]\s*\b(?:to|b?cc)\b\s*:.*?\@"){
      set req.http.X-Sec-RuleInfo = "Email Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950019";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\n\r]\s*\b(?:to|b?cc)\b\s*:.*?\@"){
      set req.http.X-Sec-RuleInfo = "Email Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950019";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\n\r]\s*\b(?:to|b?cc)\b\s*:.*?\@"){
      set req.http.X-Sec-RuleInfo = "Email Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950019";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\n\r]\s*\b(?:to|b?cc)\b\s*:.*?\@"){
      set req.http.X-Sec-RuleInfo = "Email Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950019";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\n\r]\s*\b(?:to|b?cc)\b\s*:.*?\@"){
      set req.http.X-Sec-RuleInfo = "Email Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950019";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\n\r]\s*\b(?:to|b?cc)\b\s*:.*?\@
   ## REQUEST_HEADERS, :'/(Content-Length|Transfer-Encoding)/'
   # AA 
   ## Rule: REQUEST_HEADERS rx :Content-Length|Transfer-Encoding
   # AAA Content-Length|Transfer-Encoding
   if(req.http.Content-Length ~ ","){
      set req.http.X-Sec-RuleInfo = "HTTP Request Smuggling Attack.";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/REQUEST_SMUGGLING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-26";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950012";
      call sec_default_handler;
   }
   if(req.http.Transfer-Encoding ~ ","){
      set req.http.X-Sec-RuleInfo = "HTTP Request Smuggling Attack.";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/REQUEST_SMUGGLING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-26";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950012";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\n\r]content-(type|length):"){
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950910";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\n\r]content-(type|length):"){
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950910";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\n\r]content-(type|length):"){
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950910";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\n\r]content-(type|length):"){
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950910";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\n\r]content-(type|length):"){
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950910";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\n\r]content-(type|length):
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?:\bhttp\/(?:0\.9|1\.[01])|<(?:html|meta)\b)"){
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950911";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?:\bhttp\/(?:0\.9|1\.[01])|<(?:html|meta)\b)"){
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950911";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?:\bhttp\/(?:0\.9|1\.[01])|<(?:html|meta)\b)"){
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950911";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?:\bhttp\/(?:0\.9|1\.[01])|<(?:html|meta)\b)"){
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950911";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\bhttp\/(?:0\.9|1\.[01])|<(?:html|meta)\b)"){
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950911";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?:\bhttp\/(?:0\.9|1\.[01])|<(?:html|meta)\b)
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "^(?:ht|f)tps?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Remote File Inclusion Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950117";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\binclude\s*\([^)]*(ht|f)tps?:\/\/)"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Remote File Inclusion Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950118";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:ft|htt)ps?.*\?+$"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Remote File Inclusion Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950119";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "^(?:ht|f)tps?://(.*)\?$"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Remote File Inclusion Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950120";
      # chained rule
   }
   ## TX, :1
   # AC 1 
   ## Rule: TX beginsWith :1
   ## REQUEST_COOKIES, 
   # skipped   REQUEST_COOKIES pmFromFile  modsecurity_40_generic_attacks.data
   ## REQUEST_COOKIES_NAMES, 
   # skipped   REQUEST_COOKIES_NAMES pmFromFile  modsecurity_40_generic_attacks.data
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pmFromFile  modsecurity_40_generic_attacks.data
   ## ARGS_NAMES, 
   # skipped   ARGS_NAMES pmFromFile  modsecurity_40_generic_attacks.data
   ## ARGS, 
   # skipped   ARGS pmFromFile  modsecurity_40_generic_attacks.data
   ## XML, :/*
   # AC /* 
   # skipped   XML pmFromFile /* modsecurity_40_generic_attacks.data
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## REQUEST_URI, 
   # skipped   REQUEST_URI pmFromFile  modsecurity_40_generic_attacks.data
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY pmFromFile  modsecurity_40_generic_attacks.data
   ## REQUEST_HEADERS_NAMES, 
   # skipped   REQUEST_HEADERS_NAMES pmFromFile  modsecurity_40_generic_attacks.data
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS pmFromFile  modsecurity_40_generic_attacks.data
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   # skipped !  REQUEST_HEADERS pmFromFile Referer modsecurity_40_generic_attacks.data
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   # skipped   TX pmFromFile HPP_DATA modsecurity_40_generic_attacks.data
   ## TX, :PM_SCORE
   # AC PM_SCORE 
   # skipped   TX eq PM_SCORE 0
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\.cookie\b.*?\;\W*?expires\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950301";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\.cookie\b.*?\;\W*?expires\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950301";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\.cookie\b.*?\;\W*?expires\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950301";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\.cookie\b.*?\;\W*?expires\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950301";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\.cookie\b.*?\;\W*?expires\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950301";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \.cookie\b.*?\;\W*?expires\W*?\=
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\.cookie\b.*?\;\W*?domain\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950300";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\.cookie\b.*?\;\W*?domain\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950300";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\.cookie\b.*?\;\W*?domain\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950300";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\.cookie\b.*?\;\W*?domain\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950300";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\.cookie\b.*?\;\W*?domain\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950300";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \.cookie\b.*?\;\W*?domain\W*?\=
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bhttp-equiv\W+set-cookie\b"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950302";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bhttp-equiv\W+set-cookie\b"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950302";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bhttp-equiv\W+set-cookie\b"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950302";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bhttp-equiv\W+set-cookie\b"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950302";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bhttp-equiv\W+set-cookie\b"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950302";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bhttp-equiv\W+set-cookie\b
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\.cookie\b.*?\;\W*?expires\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950304";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \.cookie\b.*?\;\W*?expires\W*?\=
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \.cookie\b.*?\;\W*?expires\W*?\=
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\.cookie\b.*?\;\W*?expires\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950304";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\.cookie\b.*?\;\W*?domain\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950303";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \.cookie\b.*?\;\W*?domain\W*?\=
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \.cookie\b.*?\;\W*?domain\W*?\=
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\.cookie\b.*?\;\W*?domain\W*?\="){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950303";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bhttp-equiv\W+set-cookie\b"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950305";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bhttp-equiv\W+set-cookie\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bhttp-equiv\W+set-cookie\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bhttp-equiv\W+set-cookie\b"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-37";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A3";
      set req.http.X-Sec-RuleName = "PCI/6.5.7";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950305";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bboot\.ini\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958711";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bboot\.ini\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958711";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bboot\.ini\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958711";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bboot\.ini\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958711";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bboot\.ini\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958711";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bboot\.ini\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\/etc\/"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958700";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\/etc\/"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958700";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\/etc\/"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958700";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\/etc\/"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958700";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\/etc\/"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958700";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \/etc\/
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\b\.htaccess\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958706";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\b\.htaccess\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958706";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\b\.htaccess\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958706";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\b\.htaccess\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958706";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\b\.htaccess\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958706";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \b\.htaccess\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\b\.htpasswd\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958708";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\b\.htpasswd\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958708";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\b\.htpasswd\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958708";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\b\.htpasswd\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958708";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\b\.htpasswd\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958708";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \b\.htpasswd\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bhttpd\.conf\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958705";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bhttpd\.conf\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958705";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bhttpd\.conf\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958705";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bhttpd\.conf\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958705";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bhttpd\.conf\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958705";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bhttpd\.conf\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bglobal\.asa\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958712";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bglobal\.asa\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958712";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bglobal\.asa\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958712";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bglobal\.asa\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958712";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bglobal\.asa\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958712";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bglobal\.asa\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\b\.wwwacl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958710";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\b\.wwwacl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958710";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\b\.wwwacl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958710";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\b\.wwwacl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958710";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\b\.wwwacl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958710";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \b\.wwwacl\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\b\.www_acl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958709";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\b\.www_acl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958709";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\b\.www_acl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958709";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\b\.www_acl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958709";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\b\.www_acl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958709";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \b\.www_acl\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\b\.htgroup\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958707";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\b\.htgroup\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958707";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\b\.htgroup\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958707";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\b\.htgroup\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958707";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\b\.htgroup\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958707";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \b\.htgroup\b
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bboot\.ini\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958721";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bboot\.ini\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bboot\.ini\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bboot\.ini\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958721";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\/etc\/"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958710";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \/etc\/
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \/etc\/
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\/etc\/"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958710";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\b\.htaccess\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958716";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \b\.htaccess\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \b\.htaccess\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\b\.htaccess\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958716";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\b\.htpasswd\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958718";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \b\.htpasswd\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \b\.htpasswd\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\b\.htpasswd\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958718";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bhttpd\.conf\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958715";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bhttpd\.conf\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bhttpd\.conf\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bhttpd\.conf\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958715";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bglobal\.asa\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958722";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bglobal\.asa\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bglobal\.asa\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bglobal\.asa\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958722";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\b\.wwwacl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958720";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \b\.wwwacl\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \b\.wwwacl\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\b\.wwwacl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958720";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\b\.www_acl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958719";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \b\.www_acl\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \b\.www_acl\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\b\.www_acl\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958719";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\b\.htgroup\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958717";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \b\.htgroup\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \b\.htgroup\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\b\.htgroup\b"){
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-33";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A4";
      set req.http.X-Sec-RuleName = "PCI/6.5.4";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958717";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958503";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958503";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958503";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958503";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958503";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bnc\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958500";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958500";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958500";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958500";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958500";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bcmd\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958504";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958504";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958504";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958504";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958504";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bnet\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972022";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972022";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972022";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972022";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972022";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \btelnet\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972032";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972032";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972032";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972032";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972032";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bwsh\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958502";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958502";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958502";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958502";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958502";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bftp\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972030";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972030";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972030";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972030";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972030";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bcmd\b\W*?\/c
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972029";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972029";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972029";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972029";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972029";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bnmap\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972031";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972031";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972031";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972031";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972031";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bwguest\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcmd32\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958501";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcmd32\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958501";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bcmd32\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958501";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bcmd32\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958501";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bcmd32\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958501";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bcmd32\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958505";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958505";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958505";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958505";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958505";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \brcmd\.exe\b
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958514";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bnc\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bnc\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958514";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958511";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bcmd\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bcmd\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958511";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958515";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bnet\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bnet\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958515";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972033";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \btelnet\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \btelnet\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972033";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972043";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bwsh\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bwsh\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972043";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958513";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bftp\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bftp\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958513";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972041";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bcmd\b\W*?\/c
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bcmd\b\W*?\/c
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972041";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972040";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bnmap\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bnmap\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972040";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972042";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bwguest\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bwguest\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "972042";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bcmd32\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958512";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bcmd32\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bcmd32\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bcmd32\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958512";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958516";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \brcmd\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \brcmd\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958516";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btclsh8\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958929";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btclsh8\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958929";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\btclsh8\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958929";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\btclsh8\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958929";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\btclsh8\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958929";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \btclsh8\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958870";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958870";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958870";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958870";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958870";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bnmap\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bperl\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958873";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bperl\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958873";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bperl\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958873";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bperl\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958873";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bperl\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958873";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bperl\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bcpp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958928";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bcpp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958928";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bcpp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958928";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bcpp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958928";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bcpp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958928";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bcpp\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bpython\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958887";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bpython\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958887";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bpython\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958887";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bpython\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958887";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bpython\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958887";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bpython\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958828";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958828";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958828";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958828";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958828";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bnc\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\buname\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958898";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\buname\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958898";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\buname\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958898";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\buname\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958898";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\buname\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958898";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\buname\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bpasswd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958888";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bpasswd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958888";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bpasswd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958888";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bpasswd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958888";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bpasswd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958888";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bpasswd\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bnet\b\W+?\blocalgroup\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958830";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bnet\b\W+?\blocalgroup\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958830";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bnet\b\W+?\blocalgroup\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958830";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bnet\b\W+?\blocalgroup\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958830";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bnet\b\W+?\blocalgroup\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958830";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bnet\b\W+?\blocalgroup\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bls\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958883";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bls\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958883";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bls\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958883";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bls\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958883";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bls\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958883";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bls\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchown\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958877";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchown\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958877";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bchown\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958877";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bchown\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958877";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bchown\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958877";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bchown\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958832";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958832";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958832";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958832";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958832";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \brcmd\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958891";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958891";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bnc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958891";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bnc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958891";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bnc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958891";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bnc\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\brm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958894";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\brm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958894";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\brm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958894";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\brm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958894";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\brm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958894";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\brm\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958839";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958839";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958839";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958839";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958839";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bwsh\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bfinger\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958881";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bfinger\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958881";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bfinger\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958881";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bfinger\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958881";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bfinger\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958881";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bfinger\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958890";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958890";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958890";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958890";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958890";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bftp\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\becho\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958872";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\becho\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958872";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\becho\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958872";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\becho\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958872";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\becho\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958872";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\becho\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bxterm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958879";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bxterm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958879";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bxterm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958879";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bxterm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958879";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bxterm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958879";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bxterm\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bkill\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958884";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bkill\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958884";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bkill\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958884";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bkill\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958884";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bkill\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958884";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bkill\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958927";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958927";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bchsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958927";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bchsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958927";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bchsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958927";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bchsh\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bping\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958893";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bping\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958893";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bping\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958893";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bping\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958893";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bping\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958893";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bping\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcd\b\W*?[\\/]"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958821";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcd\b\W*?[\\/]"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958821";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bcd\b\W*?[\\/]"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958821";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bcd\b\W*?[\\/]"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958821";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bcd\b\W*?[\\/]"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958821";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bcd\b\W*?[\\/]
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\btelnet\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958889";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\btelnet\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958889";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\btelnet\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958889";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\btelnet\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958889";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\btelnet\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958889";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\btelnet\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchmod\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958876";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchmod\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958876";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bchmod\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958876";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bchmod\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958876";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bchmod\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958876";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bchmod\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958838";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958838";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958838";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958838";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958838";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bwguest\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958871";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958871";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958871";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958871";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958871";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bcmd\b\W*?\/c
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958829";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958829";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958829";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958829";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958829";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bnet\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bg\+\+"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958875";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bg\+\+"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958875";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bg\+\+"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958875";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bg\+\+"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958875";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bg\+\+"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958875";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bg\+\+
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnasm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958882";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnasm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958882";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bnasm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958882";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bnasm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958882";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bnasm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958882";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bnasm\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcmd32\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958824";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcmd32\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958824";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bcmd32\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958824";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bcmd32\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958824";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bcmd32\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958824";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bcmd32\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\blsof\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958897";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\blsof\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958897";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\blsof\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958897";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\blsof\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958897";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\blsof\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958897";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\blsof\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bid\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958885";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bid\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958885";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bid\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958885";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bid\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958885";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bid\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958885";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bid\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958834";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958834";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958834";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958834";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958834";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \btelnet\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btracert\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958926";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btracert\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958926";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\btracert\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958926";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\btracert\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958926";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\btracert\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958926";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \btracert\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnmap\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958896";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnmap\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958896";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bnmap\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958896";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bnmap\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958896";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bnmap\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958896";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bnmap\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\becho\b\W*?\by+\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958826";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\becho\b\W*?\by+\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958826";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\becho\b\W*?\by+\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958826";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\becho\b\W*?\by+\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958826";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\becho\b\W*?\by+\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958826";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \becho\b\W*?\by+\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btraceroute\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958837";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btraceroute\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958837";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\btraceroute\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958837";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\btraceroute\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958837";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\btraceroute\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958837";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \btraceroute\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958836";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958836";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\btftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958836";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\btftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958836";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\btftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958836";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \btftp\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bgcc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958874";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bgcc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958874";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bgcc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958874";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bgcc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958874";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bgcc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958874";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bgcc\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bchmod.{0,40}?\+.{0,3}x"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958822";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bchmod.{0,40}?\+.{0,3}x"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958822";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bchmod.{0,40}?\+.{0,3}x"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958822";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bchmod.{0,40}?\+.{0,3}x"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958822";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bchmod.{0,40}?\+.{0,3}x"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958822";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bchmod.{0,40}?\+.{0,3}x
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bps\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958886";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bps\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958886";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bps\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958886";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bps\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958886";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bps\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958886";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bps\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958827";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958827";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958827";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958827";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958827";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bftp\.exe\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bcmd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958892";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bcmd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958892";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bcmd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958892";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bcmd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958892";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bcmd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958892";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bcmd\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btclsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958833";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btclsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958833";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\btclsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958833";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\btclsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958833";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\btclsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958833";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \btclsh\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bmail\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958895";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bmail\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958895";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bmail\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958895";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bmail\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958895";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bmail\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958895";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bmail\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchgrp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958878";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchgrp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958878";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\;\|\`]\W*?\bchgrp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958878";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\;\|\`]\W*?\bchgrp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958878";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\;\|\`]\W*?\bchgrp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958878";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\;\|\`]\W*?\bchgrp\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcd\W*?\.\."){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958925";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcd\W*?\.\."){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958925";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bcd\W*?\.\."){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958925";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bcd\W*?\.\."){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958925";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bcd\W*?\.\."){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958925";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bcd\W*?\.\.
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958823";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958823";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958823";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958823";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958823";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bcmd\.exe\b
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\btclsh8\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958929";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \btclsh8\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \btclsh8\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\btclsh8\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958929";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\btclsh8\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958929";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\btclsh8\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958929";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\btclsh8\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958929";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btclsh8\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958929";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btclsh8\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958929";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958870";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bnmap\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bnmap\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958870";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958870";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958870";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958870";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958870";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bnmap\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958870";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bperl\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958873";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bperl\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bperl\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bperl\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958873";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bperl\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958873";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bperl\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958873";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bperl\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958873";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bperl\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958873";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bperl\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958873";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bcpp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958928";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bcpp\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bcpp\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bcpp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958928";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bcpp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958928";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bcpp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958928";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bcpp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958928";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bcpp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958928";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bcpp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958928";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bpython\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958887";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bpython\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bpython\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bpython\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958887";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bpython\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958887";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bpython\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958887";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bpython\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958887";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bpython\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958887";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bpython\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958887";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958828";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bnc\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bnc\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958828";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958828";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958828";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958828";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958828";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bnc\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958828";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\buname\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958898";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\buname\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\buname\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\buname\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958898";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\buname\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958898";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\buname\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958898";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\buname\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958898";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\buname\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958898";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\buname\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958898";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bpasswd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958888";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bpasswd\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bpasswd\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bpasswd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958888";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bpasswd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958888";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bpasswd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958888";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bpasswd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958888";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bpasswd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958888";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bpasswd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958888";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bnet\b\W+?\blocalgroup\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958830";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bnet\b\W+?\blocalgroup\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bnet\b\W+?\blocalgroup\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bnet\b\W+?\blocalgroup\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958830";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bnet\b\W+?\blocalgroup\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958830";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bnet\b\W+?\blocalgroup\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958830";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bnet\b\W+?\blocalgroup\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958830";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bnet\b\W+?\blocalgroup\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958830";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bnet\b\W+?\blocalgroup\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958830";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bls\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958883";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bls\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bls\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bls\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958883";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bls\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958883";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bls\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958883";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bls\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958883";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bls\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958883";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bls\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958883";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bchown\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958877";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bchown\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bchown\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bchown\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958877";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchown\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958877";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bchown\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958877";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bchown\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958877";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchown\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958877";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchown\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958877";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958832";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \brcmd\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \brcmd\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958832";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958832";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958832";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958832";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958832";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\brcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958832";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bnc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958891";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bnc\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bnc\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bnc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958891";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958891";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bnc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958891";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bnc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958891";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958891";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958891";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\brm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958894";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\brm\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\brm\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\brm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958894";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\brm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958894";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\brm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958894";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\brm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958894";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\brm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958894";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\brm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958894";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958839";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bwsh\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bwsh\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958839";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958839";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958839";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958839";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958839";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bwsh\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958839";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bfinger\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958881";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bfinger\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bfinger\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bfinger\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958881";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bfinger\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958881";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bfinger\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958881";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bfinger\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958881";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bfinger\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958881";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bfinger\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958881";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958890";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bftp\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bftp\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958890";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958890";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958890";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958890";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958890";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958890";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\becho\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958872";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\becho\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\becho\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\becho\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958872";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\becho\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958872";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\becho\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958872";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\becho\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958872";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\becho\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958872";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\becho\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958872";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bxterm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958879";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bxterm\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bxterm\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bxterm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958879";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bxterm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958879";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bxterm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958879";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bxterm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958879";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bxterm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958879";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bxterm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958879";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bkill\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958884";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bkill\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bkill\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bkill\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958884";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bkill\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958884";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bkill\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958884";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bkill\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958884";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bkill\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958884";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bkill\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958884";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bchsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958927";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bchsh\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bchsh\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bchsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958927";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958927";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bchsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958927";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bchsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958927";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958927";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958927";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bping\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958893";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bping\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bping\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bping\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958893";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bping\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958893";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bping\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958893";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bping\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958893";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bping\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958893";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bping\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958893";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bcd\b\W*?[\\/]"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958821";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bcd\b\W*?[\\/]
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bcd\b\W*?[\\/]
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bcd\b\W*?[\\/]"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958821";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bcd\b\W*?[\\/]"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958821";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bcd\b\W*?[\\/]"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958821";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bcd\b\W*?[\\/]"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958821";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcd\b\W*?[\\/]"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958821";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcd\b\W*?[\\/]"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958821";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\btelnet\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958889";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\btelnet\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\btelnet\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\btelnet\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958889";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\btelnet\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958889";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\btelnet\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958889";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\btelnet\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958889";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\btelnet\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958889";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\btelnet\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958889";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bchmod\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958876";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bchmod\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bchmod\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bchmod\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958876";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchmod\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958876";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bchmod\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958876";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bchmod\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958876";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchmod\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958876";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchmod\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958876";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958838";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bwguest\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bwguest\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958838";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958838";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958838";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958838";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958838";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bwguest\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958838";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958871";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bcmd\b\W*?\/c
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bcmd\b\W*?\/c
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958871";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958871";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958871";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958871";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958871";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcmd\b\W*?\/c"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958871";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958829";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bnet\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bnet\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958829";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958829";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958829";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958829";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958829";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958829";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bg\+\+"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958875";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bg\+\+
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bg\+\+
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bg\+\+"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958875";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bg\+\+"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958875";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bg\+\+"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958875";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bg\+\+"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958875";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bg\+\+"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958875";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bg\+\+"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958875";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bnasm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958882";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bnasm\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bnasm\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bnasm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958882";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnasm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958882";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bnasm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958882";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bnasm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958882";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnasm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958882";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnasm\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958882";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bcmd32\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958824";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bcmd32\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bcmd32\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bcmd32\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958824";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bcmd32\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958824";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bcmd32\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958824";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bcmd32\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958824";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcmd32\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958824";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcmd32\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958824";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\blsof\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958897";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\blsof\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\blsof\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\blsof\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958897";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\blsof\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958897";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\blsof\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958897";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\blsof\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958897";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\blsof\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958897";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\blsof\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958897";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bid\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958885";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bid\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bid\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bid\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958885";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bid\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958885";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bid\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958885";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bid\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958885";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bid\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958885";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bid\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958885";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958834";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \btelnet\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \btelnet\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958834";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958834";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958834";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958834";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958834";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btelnet\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958834";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\btracert\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958926";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \btracert\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \btracert\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\btracert\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958926";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\btracert\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958926";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\btracert\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958926";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\btracert\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958926";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btracert\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958926";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btracert\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958926";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bnmap\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958896";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bnmap\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bnmap\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bnmap\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958896";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnmap\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958896";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bnmap\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958896";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bnmap\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958896";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnmap\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958896";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bnmap\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958896";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\becho\b\W*?\by+\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958826";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \becho\b\W*?\by+\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \becho\b\W*?\by+\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\becho\b\W*?\by+\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958826";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\becho\b\W*?\by+\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958826";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\becho\b\W*?\by+\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958826";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\becho\b\W*?\by+\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958826";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\becho\b\W*?\by+\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958826";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\becho\b\W*?\by+\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958826";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\btraceroute\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958837";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \btraceroute\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \btraceroute\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\btraceroute\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958837";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\btraceroute\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958837";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\btraceroute\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958837";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\btraceroute\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958837";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btraceroute\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958837";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btraceroute\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958837";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\btftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958836";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \btftp\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \btftp\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\btftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958836";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\btftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958836";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\btftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958836";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\btftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958836";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958836";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btftp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958836";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bgcc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958874";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bgcc\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bgcc\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bgcc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958874";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bgcc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958874";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bgcc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958874";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bgcc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958874";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bgcc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958874";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bgcc\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958874";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bchmod.{0,40}?\+.{0,3}x"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958822";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bchmod.{0,40}?\+.{0,3}x
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bchmod.{0,40}?\+.{0,3}x
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bchmod.{0,40}?\+.{0,3}x"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958822";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bchmod.{0,40}?\+.{0,3}x"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958822";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bchmod.{0,40}?\+.{0,3}x"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958822";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bchmod.{0,40}?\+.{0,3}x"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958822";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bchmod.{0,40}?\+.{0,3}x"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958822";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bchmod.{0,40}?\+.{0,3}x"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958822";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bps\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958886";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bps\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bps\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bps\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958886";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bps\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958886";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bps\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958886";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bps\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958886";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bps\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958886";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bps\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958886";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958827";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bftp\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bftp\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958827";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958827";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958827";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958827";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958827";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bftp\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958827";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bcmd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958892";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bcmd\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bcmd\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bcmd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958892";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bcmd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958892";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bcmd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958892";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bcmd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958892";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bcmd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958892";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bcmd\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958892";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\btclsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958833";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \btclsh\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \btclsh\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\btclsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958833";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\btclsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958833";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\btclsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958833";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\btclsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958833";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\btclsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958833";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\btclsh\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958833";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bmail\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958895";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bmail\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bmail\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bmail\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958895";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bmail\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958895";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bmail\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958895";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bmail\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958895";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bmail\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958895";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bmail\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958895";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "[\;\|\`]\W*?\bchgrp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958878";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  [\;\|\`]\W*?\bchgrp\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\;\|\`]\W*?\bchgrp\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "[\;\|\`]\W*?\bchgrp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958878";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchgrp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958878";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "[\;\|\`]\W*?\bchgrp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958878";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "[\;\|\`]\W*?\bchgrp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958878";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchgrp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958878";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "[\;\|\`]\W*?\bchgrp\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958878";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bcd\W*?\.\."){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958925";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bcd\W*?\.\.
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bcd\W*?\.\.
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bcd\W*?\.\."){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958925";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bcd\W*?\.\."){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958925";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bcd\W*?\.\."){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958925";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bcd\W*?\.\."){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958925";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcd\W*?\.\."){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958925";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcd\W*?\.\."){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958925";
      call sec_default_handler;
   }
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958823";
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  \bcmd\.exe\b
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bcmd\.exe\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958823";
      call sec_default_handler;
   }
   ## TX, :HPP_DATA
   # AC HPP_DATA 
   ## Rule: TX rx :HPP_DATA
   ## !REQUEST_HEADERS, :'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958823";
      call sec_default_handler;
   }
   if(req.http.X-OS-Prefs ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958823";
      call sec_default_handler;
   }
   if(req.http.User-Agent ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958823";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958823";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcmd\.exe\b"){
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-31";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958823";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "<\?(?!xml)"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959151";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "<\?(?!xml)"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959151";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "<\?(?!xml)"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959151";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "<\?(?!xml)"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959151";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "<\?(?!xml)"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959151";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* <\?(?!xml)
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bproc_open\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958976";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bproc_open\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958976";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bproc_open\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958976";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bproc_open\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958976";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bproc_open\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958976";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bproc_open\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bgzread\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958972";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bgzread\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958972";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bgzread\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958972";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bgzread\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958972";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bgzread\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958972";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bgzread\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bftp_nb_fget\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958963";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bftp_nb_fget\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958963";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bftp_nb_fget\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958963";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bftp_nb_fget\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958963";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bftp_nb_fget\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958963";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bftp_nb_fget\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bftp_nb_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958965";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bftp_nb_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958965";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bftp_nb_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958965";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bftp_nb_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958965";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bftp_nb_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958965";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bftp_nb_get\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bfscanf\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958959";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bfscanf\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958959";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bfscanf\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958959";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bfscanf\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958959";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bfscanf\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958959";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bfscanf\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\breadfile\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958978";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\breadfile\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958978";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\breadfile\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958978";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\breadfile\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958978";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\breadfile\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958978";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \breadfile\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bfgetss\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958955";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bfgetss\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958955";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bfgetss\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958955";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bfgetss\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958955";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bfgetss\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958955";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bfgetss\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\$_post\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958941";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\$_post\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958941";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\$_post\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958941";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\$_post\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958941";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\$_post\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958941";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \$_post\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bsession_start\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958982";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bsession_start\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958982";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bsession_start\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958982";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bsession_start\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958982";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bsession_start\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958982";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bsession_start\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\breaddir\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958977";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\breaddir\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958977";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\breaddir\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958977";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\breaddir\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958977";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\breaddir\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958977";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \breaddir\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bgzwrite\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958973";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bgzwrite\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958973";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bgzwrite\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958973";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bgzwrite\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958973";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bgzwrite\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958973";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bgzwrite\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bscandir\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958981";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bscandir\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958981";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bscandir\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958981";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bscandir\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958981";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bscandir\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958981";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bscandir\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bftp_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958962";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bftp_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958962";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bftp_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958962";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bftp_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958962";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bftp_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958962";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bftp_get\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bfread\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958958";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bfread\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958958";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bfread\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958958";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bfread\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958958";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bfread\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958958";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bfread\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\breadgzfile\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958979";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\breadgzfile\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958979";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\breadgzfile\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958979";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\breadgzfile\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958979";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\breadgzfile\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958979";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \breadgzfile\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bftp_put\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958967";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bftp_put\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958967";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bftp_put\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958967";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bftp_put\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958967";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bftp_put\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958967";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bftp_put\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bfwrite\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958968";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bfwrite\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958968";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bfwrite\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958968";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bfwrite\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958968";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bfwrite\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958968";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bfwrite\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bgzencode\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958970";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bgzencode\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958970";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bgzencode\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958970";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bgzencode\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958970";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bgzencode\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958970";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bgzencode\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bfopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958957";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bfopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958957";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bfopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958957";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bfopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958957";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bfopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958957";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bfopen\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\$_session\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958942";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\$_session\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958942";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\$_session\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958942";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\$_session\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958942";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\$_session\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958942";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \$_session\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bftp_nb_fput\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958964";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bftp_nb_fput\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958964";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bftp_nb_fput\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958964";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bftp_nb_fput\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958964";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bftp_nb_fput\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958964";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bftp_nb_fput\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bftp_fput\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958961";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bftp_fput\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958961";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bftp_fput\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958961";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bftp_fput\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958961";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bftp_fput\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958961";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bftp_fput\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bgzcompress\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958969";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bgzcompress\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958969";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bgzcompress\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958969";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bgzcompress\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958969";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bgzcompress\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958969";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bgzcompress\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bbzopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958946";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bbzopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958946";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bbzopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958946";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bbzopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958946";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bbzopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958946";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bbzopen\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bgzopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958971";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bgzopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958971";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bgzopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958971";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bgzopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958971";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bgzopen\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958971";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bgzopen\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bfgetc\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958953";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bfgetc\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958953";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bfgetc\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958953";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bfgetc\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958953";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bfgetc\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958953";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bfgetc\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bmove_uploaded_file\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958975";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bmove_uploaded_file\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958975";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bmove_uploaded_file\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958975";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bmove_uploaded_file\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958975";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bmove_uploaded_file\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958975";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bmove_uploaded_file\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bftp_nb_put\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958966";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bftp_nb_put\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958966";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bftp_nb_put\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958966";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bftp_nb_put\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958966";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bftp_nb_put\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958966";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bftp_nb_put\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bcall_user_func\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958983";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bcall_user_func\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958983";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bcall_user_func\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958983";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bcall_user_func\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958983";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bcall_user_func\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958983";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bcall_user_func\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\$_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958940";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\$_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958940";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\$_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958940";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\$_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958940";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\$_get\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958940";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \$_get\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bfgets\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958954";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bfgets\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958954";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bfgets\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958954";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bfgets\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958954";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bfgets\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958954";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bfgets\b
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "\bftp_fget\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958960";
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "\bftp_fget\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958960";
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bftp_fget\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958960";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bftp_fget\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958960";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bftp_fget\b"){
      set req.http.X-Sec-RuleInfo = "PHP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/PHP_INJECTION";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/HTTP_RESPONSE_SPLITTING";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-15";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A6";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-25";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A1";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/CIE4";
      set req.http.X-Sec-RuleName = "PCI/6.5.2";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "958960";
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bftp_fget\b
}

