sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## Script, 
   ## Rule: Script rx :
   ## TX, :re(centrifuge_ratio)
   # AC re(centrifuge_ratio) 
   ## Rule: TX rx :re(centrifuge_ratio)
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\<\w*:?\s(?:[^\>]*)t(?!rong))|(?:\<scri)|(<\w+:\w+)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\<\w*:?\s(?:[^\>]*)t(?!rong))|(?:\<scri)|(<\w+:\w+)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\<\w*:?\s(?:[^\>]*)t(?!rong))|(?:\<scri)|(<\w+:\w+)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:[^\w\s=]on(?!g\&gt;)\w+[^=_+-]*=[^$]+(?:\W|\&gt;)?)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:[^\w\s=]on(?!g\&gt;)\w+[^=_+-]*=[^$]+(?:\W|\&gt;)?)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:[^\w\s=]on(?!g\&gt;)\w+[^=_+-]*=[^$]+(?:\W|\&gt;)?)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:[\w.-]+@[\w.-]+%(?:[01][\db-ce-f])+\w+:)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:[\w.-]+@[\w.-]+%(?:[01][\db-ce-f])+\w+:)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:[\w.-]+@[\w.-]+%(?:[01][\db-ce-f])+\w+:)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:,\s*(?:alert|showmodaldialog|eval)\s*,)|(?::\s*eval\s*[^\s])|([^:\s\w,.\/?+-]\s*)?(?<![a-z\/_@])(\s*return\s*)?(?:(?:document\s*\.)?(?:.+\/)?(?:alert|eval|msgbox|showmodaldialog|prompt|write(?:ln)?|confirm|dialog|open))\s*(?:[^a-z\s\-]|(?:\s*[^\s\w,.@\/+-]))|(?:java[\s\/]*\.[\s\/]*lang)|(?:\w\s*=\s*new\s+\w+)|(?:&\s*\w+\s*\)[^,])|(?:\+[\W\d]*new\s+\w+[\W\d]*\+)|(?:document\.\w)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:,\s*(?:alert|showmodaldialog|eval)\s*,)|(?::\s*eval\s*[^\s])|([^:\s\w,.\/?+-]\s*)?(?<![a-z\/_@])(\s*return\s*)?(?:(?:document\s*\.)?(?:.+\/)?(?:alert|eval|msgbox|showmodaldialog|prompt|write(?:ln)?|confirm|dialog|open))\s*(?:[^a-z\s\-]|(?:\s*[^\s\w,.@\/+-]))|(?:java[\s\/]*\.[\s\/]*lang)|(?:\w\s*=\s*new\s+\w+)|(?:&\s*\w+\s*\)[^,])|(?:\+[\W\d]*new\s+\w+[\W\d]*\+)|(?:document\.\w)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:,\s*(?:alert|showmodaldialog|eval)\s*,)|(?::\s*eval\s*[^\s])|([^:\s\w,.\/?+-]\s*)?(?<![a-z\/_@])(\s*return\s*)?(?:(?:document\s*\.)?(?:.+\/)?(?:alert|eval|msgbox|showmodaldialog|prompt|write(?:ln)?|confirm|dialog|open))\s*(?:[^a-z\s\-]|(?:\s*[^\s\w,.@\/+-]))|(?:java[\s\/]*\.[\s\/]*lang)|(?:\w\s*=\s*new\s+\w+)|(?:&\s*\w+\s*\)[^,])|(?:\+[\W\d]*new\s+\w+[\W\d]*\+)|(?:document\.\w)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:[\s\d\/\"]+(?:on\w+|style|poster|background)=[$\"\w])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:[\s\d\/\"]+(?:on\w+|style|poster|background)=[$\"\w])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:[\s\d\/\"]+(?:on\w+|style|poster|background)=[$\"\w])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:[=(].+\?.+:)|(?:with\([^)]*\)\))|(?:\.\s*source\W)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:[=(].+\?.+:)|(?:with\([^)]*\)\))|(?:\.\s*source\W)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:[=(].+\?.+:)|(?:with\([^)]*\)\))|(?:\.\s*source\W)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:[^:\s\w]+\s*[^\w\/](href|protocol|host|hostname|pathname|hash|port|cookie)[^\w])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:[^:\s\w]+\s*[^\w\/](href|protocol|host|hostname|pathname|hash|port|cookie)[^\w])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:[^:\s\w]+\s*[^\w\/](href|protocol|host|hostname|pathname|hash|port|cookie)[^\w])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@>\-\|])(\s*return\s*)?(?:join|pop|push|reverse|reduce|concat|map|shift|sp?lice|sort|unshift)(?(1)[^\w%\"]|(?:\s*[^@\s\w%,.+\-]))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  ([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@>\-\|])(\s*return\s*)?(?:join|pop|push|reverse|reduce|concat|map|shift|sp?lice|sort|unshift)(?(1)[^\w%\"]|(?:\s*[^@\s\w%,.+\-]))
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@>\-\|])(\s*return\s*)?(?:join|pop|push|reverse|reduce|concat|map|shift|sp?lice|sort|unshift)(?(1)[^\w%\"]|(?:\s*[^@\s\w%,.+\-]))"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "([^*\s\w,.\/?+-]\s*)?(?<![a-mo-z]\s)(?<![a-z\/_@>])(\s*return\s*)?(?:alert|inputbox|showmodaldialog|infinity|isnan|isnull|iterator|msgbox|expression|prompt|write(?:ln)?|confirm|dialog|urn|(?:un)?eval|exec|execscript|tostring|status|execute|window|unescape|navigate|jquery|getscript|extend|prototype)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\",.:\/+\-]))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  ([^*\s\w,.\/?+-]\s*)?(?<![a-mo-z]\s)(?<![a-z\/_@>])(\s*return\s*)?(?:alert|inputbox|showmodaldialog|infinity|isnan|isnull|iterator|msgbox|expression|prompt|write(?:ln)?|confirm|dialog|urn|(?:un)?eval|exec|execscript|tostring|status|execute|window|unescape|navigate|jquery|getscript|extend|prototype)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\",.:\/+\-]))
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "([^*\s\w,.\/?+-]\s*)?(?<![a-mo-z]\s)(?<![a-z\/_@>])(\s*return\s*)?(?:alert|inputbox|showmodaldialog|infinity|isnan|isnull|iterator|msgbox|expression|prompt|write(?:ln)?|confirm|dialog|urn|(?:un)?eval|exec|execscript|tostring|status|execute|window|unescape|navigate|jquery|getscript|extend|prototype)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\",.:\/+\-]))"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\d\"\s+\"\s+\d)|(?:^admin\s*\"|(\/\*)+\"+\s?(?:--|#|\/\*|{)?)|(?:\"\s*or[\w\s-]+\s*[+<>=(),-]\s*[\d\"])|(?:\"\s*[^\w\s]?=\s*\")|(?:\"\W*[+=]+\W*\")|(?:\"\s*[!=|][\d\s!=+-]+.*[\"(].*$)|(?:\"\s*[!=|][\d\s!=]+.*\d+$)|(?:\"\s*like\W+[\w\"(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:\"[<>~]+\")"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\d\"\s+\"\s+\d)|(?:^admin\s*\"|(\/\*)+\"+\s?(?:--|#|\/\*|{)?)|(?:\"\s*or[\w\s-]+\s*[+<>=(),-]\s*[\d\"])|(?:\"\s*[^\w\s]?=\s*\")|(?:\"\W*[+=]+\W*\")|(?:\"\s*[!=|][\d\s!=+-]+.*[\"(].*$)|(?:\"\s*[!=|][\d\s!=]+.*\d+$)|(?:\"\s*like\W+[\w\"(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:\"[<>~]+\")
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\d\"\s+\"\s+\d)|(?:^admin\s*\"|(\/\*)+\"+\s?(?:--|#|\/\*|{)?)|(?:\"\s*or[\w\s-]+\s*[+<>=(),-]\s*[\d\"])|(?:\"\s*[^\w\s]?=\s*\")|(?:\"\W*[+=]+\W*\")|(?:\"\s*[!=|][\d\s!=+-]+.*[\"(].*$)|(?:\"\s*[!=|][\d\s!=]+.*\d+$)|(?:\"\s*like\W+[\w\"(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:\"[<>~]+\")"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\sexec\s+xp_cmdshell)|(?:\"\s*!\s*[\"\w])|(?:from\s+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*\([^\)]*)|(?:\";?\s*(?:select|union|having)\s*[^\s])|(?:\wiif\s*\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*select)|(?:select.*\w?user\()|(?:into[\s+]+(?:dump|out)file\s*\")"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\sexec\s+xp_cmdshell)|(?:\"\s*!\s*[\"\w])|(?:from\s+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*\([^\)]*)|(?:\";?\s*(?:select|union|having)\s*[^\s])|(?:\wiif\s*\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*select)|(?:select.*\w?user\()|(?:into[\s+]+(?:dump|out)file\s*\")
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\sexec\s+xp_cmdshell)|(?:\"\s*!\s*[\"\w])|(?:from\s+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*\([^\)]*)|(?:\";?\s*(?:select|union|having)\s*[^\s])|(?:\wiif\s*\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*select)|(?:select.*\w?user\()|(?:into[\s+]+(?:dump|out)file\s*\")"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:data:.*,)|(?:\w+\s*=\W*(?!https?)\w+:)|(jar:\w+:)|(=\s*\"?\s*vbs(?:ript)?:)|(language\s*=\s?\"?\s*vbs(?:ript)?)|on\w+\s*=\*\w+\-\"?"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:data:.*,)|(?:\w+\s*=\W*(?!https?)\w+:)|(jar:\w+:)|(=\s*\"?\s*vbs(?:ript)?:)|(language\s*=\s?\"?\s*vbs(?:ript)?)|on\w+\s*=\*\w+\-\"?
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:data:.*,)|(?:\w+\s*=\W*(?!https?)\w+:)|(jar:\w+:)|(=\s*\"?\s*vbs(?:ript)?:)|(language\s*=\s?\"?\s*vbs(?:ript)?)|on\w+\s*=\*\w+\-\"?"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:,.*[)\da-f\"]\"(?:\".*\"|\Z|[^\"]+))|(?:select\s*\*\s*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*\(\s*space\s*\()"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:,.*[)\da-f\"]\"(?:\".*\"|\Z|[^\"]+))|(?:select\s*\*\s*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*\(\s*space\s*\()
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:,.*[)\da-f\"]\"(?:\".*\"|\Z|[^\"]+))|(?:select\s*\*\s*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*\(\s*space\s*\()"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\w+]?(?<!href)(?<!src)(?<!longdesc)(?<!returnurl)=(?:https?|ftp):)|(?:\{\s*\$\s*\{)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\w+]?(?<!href)(?<!src)(?<!longdesc)(?<!returnurl)=(?:https?|ftp):)|(?:\{\s*\$\s*\{)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\w+]?(?<!href)(?<!src)(?<!longdesc)(?<!returnurl)=(?:https?|ftp):)|(?:\{\s*\$\s*\{)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\)\s*\[)|(?:\/\w*\s*\)\s*\W)|([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z_@>\|])(\s*return\s*)?(?:globalstorage|sessionstorage|postmessage|callee|constructor|content|domain|prototype|try|catch|top|call|apply|url|function|object|array|string|math|if|for\s*(?:each)?|elseif|case|switch|regex|boolean|location|settimeout|setinterval|void|setexpression|namespace|while)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\".+\-]))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\)\s*\[)|(?:\/\w*\s*\)\s*\W)|([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z_@>\|])(\s*return\s*)?(?:globalstorage|sessionstorage|postmessage|callee|constructor|content|domain|prototype|try|catch|top|call|apply|url|function|object|array|string|math|if|for\s*(?:each)?|elseif|case|switch|regex|boolean|location|settimeout|setinterval|void|setexpression|namespace|while)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\".+\-]))
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\)\s*\[)|(?:\/\w*\s*\)\s*\W)|([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z_@>\|])(\s*return\s*)?(?:globalstorage|sessionstorage|postmessage|callee|constructor|content|domain|prototype|try|catch|top|call|apply|url|function|object|array|string|math|if|for\s*(?:each)?|elseif|case|switch|regex|boolean|location|settimeout|setinterval|void|setexpression|namespace|while)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\".+\-]))"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:(?:\/|\\\\\\\\)?\.+(\/|\\\\\\\\)(?:\.+)?)|(?:\w+\.exe\??\s)|(?:;\s*\w+\s*\/[\w*-]+\/)|(?:\d\.\dx\|)|(?:%(?:c0\.|af\.|5c\.))|(?:\/(?:%2e){2})"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:(?:\/|\\\\\\\\)?\.+(\/|\\\\\\\\)(?:\.+)?)|(?:\w+\.exe\??\s)|(?:;\s*\w+\s*\/[\w*-]+\/)|(?:\d\.\dx\|)|(?:%(?:c0\.|af\.|5c\.))|(?:\/(?:%2e){2})
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:(?:\/|\\\\\\\\)?\.+(\/|\\\\\\\\)(?:\.+)?)|(?:\w+\.exe\??\s)|(?:;\s*\w+\s*\/[\w*-]+\/)|(?:\d\.\dx\|)|(?:%(?:c0\.|af\.|5c\.))|(?:\/(?:%2e){2})"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:=\s*\d*\.\d*\?\d*\.\d*)|(?:[|&]{2,}\s*\")|(?:!\d+\.\d*\?\")|(?:\/:[\w.]+,)|(?:=[\d\W\s]*\[[^]]+\])|(?:\?\w+:\w+)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:=\s*\d*\.\d*\?\d*\.\d*)|(?:[|&]{2,}\s*\")|(?:!\d+\.\d*\?\")|(?:\/:[\w.]+,)|(?:=[\d\W\s]*\[[^]]+\])|(?:\?\w+:\w+)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:=\s*\d*\.\d*\?\d*\.\d*)|(?:[|&]{2,}\s*\")|(?:!\d+\.\d*\?\")|(?:\/:[\w.]+,)|(?:=[\d\W\s]*\[[^]]+\])|(?:\?\w+:\w+)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:--[^\n]*$)|(?:\<!-|-->)|(?:[^*]\/\*|\*\/[^*])|(?:(?:[\W\d]#|--|{)$)|(?:\/{3,}.*$)|(?:<!\[\W)|(?:\]!>)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:--[^\n]*$)|(?:\<!-|-->)|(?:[^*]\/\*|\*\/[^*])|(?:(?:[\W\d]#|--|{)$)|(?:\/{3,}.*$)|(?:<!\[\W)|(?:\]!>)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:--[^\n]*$)|(?:\<!-|-->)|(?:[^*]\/\*|\*\/[^*])|(?:(?:[\W\d]#|--|{)$)|(?:\/{3,}.*$)|(?:<!\[\W)|(?:\]!>)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:%c0%ae\/)|(?:(?:\/|\\\\\\\\)(home|conf|usr|etc|proc|opt|s?bin|local|dev|tmp|kern|[br]oot|sys|system|windows|winnt|program|%[a-z_-]{3,}%)(?:\/|\\\\\\\\))|(?:(?:\/|\\\\\\\\)inetpub|localstart\.asp|boot\.ini)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:%c0%ae\/)|(?:(?:\/|\\\\\\\\)(home|conf|usr|etc|proc|opt|s?bin|local|dev|tmp|kern|[br]oot|sys|system|windows|winnt|program|%[a-z_-]{3,}%)(?:\/|\\\\\\\\))|(?:(?:\/|\\\\\\\\)inetpub|localstart\.asp|boot\.ini)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:%c0%ae\/)|(?:(?:\/|\\\\\\\\)(home|conf|usr|etc|proc|opt|s?bin|local|dev|tmp|kern|[br]oot|sys|system|windows|winnt|program|%[a-z_-]{3,}%)(?:\/|\\\\\\\\))|(?:(?:\/|\\\\\\\\)inetpub|localstart\.asp|boot\.ini)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\d+\s*or\s*\d+\s*[\-+])|(?:\/\w+;?\s+(?:having|and|or|select))|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?or|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[\"=()])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\d+\s*or\s*\d+\s*[\-+])|(?:\/\w+;?\s+(?:having|and|or|select))|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?or|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[\"=()])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\d+\s*or\s*\d+\s*[\-+])|(?:\/\w+;?\s+(?:having|and|or|select))|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?or|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[\"=()])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:(^|\W)const\s+[\w\-]+\s*=)|(?:(?:do|for|while)\s*\([^;]+;+\))|(?:(?:^|\W)on\w+\s*=[\w\W]*(?:on\w+|alert|eval|print|confirm|prompt))|(?:groups=\d+\(\w+\))|(?:(.)\1{128,})"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:(^|\W)const\s+[\w\-]+\s*=)|(?:(?:do|for|while)\s*\([^;]+;+\))|(?:(?:^|\W)on\w+\s*=[\w\W]*(?:on\w+|alert|eval|print|confirm|prompt))|(?:groups=\d+\(\w+\))|(?:(.)\1{128,})
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:(^|\W)const\s+[\w\-]+\s*=)|(?:(?:do|for|while)\s*\([^;]+;+\))|(?:(?:^|\W)on\w+\s*=[\w\W]*(?:on\w+|alert|eval|print|confirm|prompt))|(?:groups=\d+\(\w+\))|(?:(.)\1{128,})"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:binding\s?=|moz-binding|behavior\s?=)|(?:[\s\/]style\s*=\s*[-\\\\\\\\])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:binding\s?=|moz-binding|behavior\s?=)|(?:[\s\/]style\s*=\s*[-\\\\\\\\])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:binding\s?=|moz-binding|behavior\s?=)|(?:[\s\/]style\s*=\s*[-\\\\\\\\])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*\(?\s*\w+)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*\(?\s*\w+)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*\(?\s*\w+)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\\\\\\\\x[01fe][\db-ce-f])|(?:%[01fe][\db-ce-f])|(?:&#[01fe][\db-ce-f])|(?:\\\\\\\\[01fe][\db-ce-f])|(?:&#x[01fe][\db-ce-f])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\\\\\\\\x[01fe][\db-ce-f])|(?:%[01fe][\db-ce-f])|(?:&#[01fe][\db-ce-f])|(?:\\\\\\\\[01fe][\db-ce-f])|(?:&#x[01fe][\db-ce-f])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\\\\\\\\x[01fe][\db-ce-f])|(?:%[01fe][\db-ce-f])|(?:&#[01fe][\db-ce-f])|(?:\\\\\\\\[01fe][\db-ce-f])|(?:&#x[01fe][\db-ce-f])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\.pl\?\w+=\w?\|\w+;)|(?:\|\(\w+=\*)|(?:\*\s*\)+\s*;)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\.pl\?\w+=\w?\|\w+;)|(?:\|\(\w+=\*)|(?:\*\s*\)+\s*;)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\.pl\?\w+=\w?\|\w+;)|(?:\|\(\w+=\*)|(?:\*\s*\)+\s*;)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:@[\w-]+\s*\()|(?:]\s*\(\s*[\"!]\s*\w)|(?:<[?%](?:php)?.*(?:[?%]>)?)|(?:;[\s\w|]*\$\w+\s*=)|(?:\$\w+\s*=(?:(?:\s*\$?\w+\s*[(;])|\s*\".*\"))|(?:;\s*\{\W*\w+\s*\()"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:@[\w-]+\s*\()|(?:]\s*\(\s*[\"!]\s*\w)|(?:<[?%](?:php)?.*(?:[?%]>)?)|(?:;[\s\w|]*\$\w+\s*=)|(?:\$\w+\s*=(?:(?:\s*\$?\w+\s*[(;])|\s*\".*\"))|(?:;\s*\{\W*\w+\s*\()
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:@[\w-]+\s*\()|(?:]\s*\(\s*[\"!]\s*\w)|(?:<[?%](?:php)?.*(?:[?%]>)?)|(?:;[\s\w|]*\$\w+\s*=)|(?:\$\w+\s*=(?:(?:\s*\$?\w+\s*[(;])|\s*\".*\"))|(?:;\s*\{\W*\w+\s*\()"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:etc\/\W*passwd)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:etc\/\W*passwd)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:etc\/\W*passwd)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@>\-\|])(\s*return\s*)?(?:create(?:element|attribute|textnode)|[a-z]+events?|setattribute|getelement\w+|appendchild|createrange|createcontextualfragment|removenode|parentnode|decodeuricomponent|\wettimeout|option|useragent)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\",.+\-]))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  ([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@>\-\|])(\s*return\s*)?(?:create(?:element|attribute|textnode)|[a-z]+events?|setattribute|getelement\w+|appendchild|createrange|createcontextualfragment|removenode|parentnode|decodeuricomponent|\wettimeout|option|useragent)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\",.+\-]))
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@>\-\|])(\s*return\s*)?(?:create(?:element|attribute|textnode)|[a-z]+events?|setattribute|getelement\w+|appendchild|createrange|createcontextualfragment|removenode|parentnode|decodeuricomponent|\wettimeout|option|useragent)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\",.+\-]))"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:alter\s*\w+.*character\s+set\s+\w+)|(\";\s*waitfor\s+time\s+\")|(?:\";.*:\s*goto)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:alter\s*\w+.*character\s+set\s+\w+)|(\";\s*waitfor\s+time\s+\")|(?:\";.*:\s*goto)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:alter\s*\w+.*character\s+set\s+\w+)|(\";\s*waitfor\s+time\s+\")|(?:\";.*:\s*goto)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:(?:[;]+|(<[?%](?:php)?)).*[^\w](?:echo|print|print_r|var_dump|[fp]open))|(?:;\s*rm\s+-\w+\s+)|(?:;.*{.*\$\w+\s*=)|(?:\$\w+\s*\[\]\s*=\s*)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:(?:[;]+|(<[?%](?:php)?)).*[^\w](?:echo|print|print_r|var_dump|[fp]open))|(?:;\s*rm\s+-\w+\s+)|(?:;.*{.*\$\w+\s*=)|(?:\$\w+\s*\[\]\s*=\s*)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:(?:[;]+|(<[?%](?:php)?)).*[^\w](?:echo|print|print_r|var_dump|[fp]open))|(?:;\s*rm\s+-\w+\s+)|(?:;.*{.*\$\w+\s*=)|(?:\$\w+\s*\[\]\s*=\s*)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:merge.*using\s*\()|(execute\s*immediate\s*\")|(?:\W+\d*\s*having\s*[^\s])|(?:match\s*[\w(),+-]+\s*against\s*\()"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:merge.*using\s*\()|(execute\s*immediate\s*\")|(?:\W+\d*\s*having\s*[^\s])|(?:match\s*[\w(),+-]+\s*against\s*\()
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:merge.*using\s*\()|(execute\s*immediate\s*\")|(?:\W+\d*\s*having\s*[^\s])|(?:match\s*[\w(),+-]+\s*against\s*\()"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:union\s*(?:all|distinct|[(!@]*)?\s*[([]*\s*select)|(?:\w+\s+like\s+\")|(?:like\s*\"\%)|(?:\"\s*like\W*[\"\d])|(?:\"\s*(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:\"\s*\*\s*\w+\W+\")|(?:\"\s*[^?\w\s=.,;)(]+\s*[(@\"]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,-]+from)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:union\s*(?:all|distinct|[(!@]*)?\s*[([]*\s*select)|(?:\w+\s+like\s+\")|(?:like\s*\"\%)|(?:\"\s*like\W*[\"\d])|(?:\"\s*(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:\"\s*\*\s*\w+\W+\")|(?:\"\s*[^?\w\s=.,;)(]+\s*[(@\"]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,-]+from)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:union\s*(?:all|distinct|[(!@]*)?\s*[([]*\s*select)|(?:\w+\s+like\s+\")|(?:like\s*\"\%)|(?:\"\s*like\W*[\"\d])|(?:\"\s*(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:\"\s*\*\s*\w+\W+\")|(?:\"\s*[^?\w\s=.,;)(]+\s*[(@\"]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,-]+from)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@>\-\|])(\s*return\s*)?(?:set|atob|btoa|charat|charcodeat|charset|concat|crypto|frames|fromcharcode|indexof|lastindexof|match|navigator|toolbar|menubar|replace|regexp|slice|split|substr|substring|escape|\w+codeuri\w*)(?(1)[^\w%\"]|(?:\s*[^@\s\w%,.+\-]))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  ([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@>\-\|])(\s*return\s*)?(?:set|atob|btoa|charat|charcodeat|charset|concat|crypto|frames|fromcharcode|indexof|lastindexof|match|navigator|toolbar|menubar|replace|regexp|slice|split|substr|substring|escape|\w+codeuri\w*)(?(1)[^\w%\"]|(?:\s*[^@\s\w%,.+\-]))
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@>\-\|])(\s*return\s*)?(?:set|atob|btoa|charat|charcodeat|charset|concat|crypto|frames|fromcharcode|indexof|lastindexof|match|navigator|toolbar|menubar|replace|regexp|slice|split|substr|substring|escape|\w+codeuri\w*)(?(1)[^\w%\"]|(?:\s*[^@\s\w%,.+\-]))"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:function[^(]*\([^)]*\))|(?:(?:delete|void|throw|instanceof|new|typeof)[^\w.]+\w+\s*[([])|([)\]]\s*\.\s*\w+\s*=)|(?:\(\s*new\s+\w+\s*\)\.)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:function[^(]*\([^)]*\))|(?:(?:delete|void|throw|instanceof|new|typeof)[^\w.]+\w+\s*[([])|([)\]]\s*\.\s*\w+\s*=)|(?:\(\s*new\s+\w+\s*\)\.)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:function[^(]*\([^)]*\))|(?:(?:delete|void|throw|instanceof|new|typeof)[^\w.]+\w+\s*[([])|([)\]]\s*\.\s*\w+\s*=)|(?:\(\s*new\s+\w+\s*\)\.)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:select\s*pg_sleep)|(?:waitfor\s*delay\s?\"+\s?\d)|(?:;\s*shutdown\s*(?:;|--|#|\/\*|{))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:select\s*pg_sleep)|(?:waitfor\s*delay\s?\"+\s?\d)|(?:;\s*shutdown\s*(?:;|--|#|\/\*|{))
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:select\s*pg_sleep)|(?:waitfor\s*delay\s?\"+\s?\d)|(?:;\s*shutdown\s*(?:;|--|#|\/\*|{))"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\({2,}\+{2,}:{2,})|(?:\({2,}\+{2,}:+)|(?:\({3,}\++:{2,})|(?:\$\[!!!\])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\({2,}\+{2,}:{2,})|(?:\({2,}\+{2,}:+)|(?:\({3,}\++:{2,})|(?:\$\[!!!\])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\({2,}\+{2,}:{2,})|(?:\({2,}\+{2,}:+)|(?:\({3,}\++:{2,})|(?:\$\[!!!\])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:[\s\/\"]+[-\w\/\\\\\\\\\*]+\s*=.+(?:\/\s*>))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:[\s\/\"]+[-\w\/\\\\\\\\\*]+\s*=.+(?:\/\s*>))
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:[\s\/\"]+[-\w\/\\\\\\\\\*]+\s*=.+(?:\/\s*>))"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\"+.*[<=]\s*\"[^\"]+\")|(?:\"\w+\s*=)|(?:>\w=\/)|(?:#.+\)[\"\s]*>)|(?:\"\s*(?:src|style|on\w+)\s*=\s*\")|(?:[^\"]?\"[,;\s]+\w*[\[\(])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\"+.*[<=]\s*\"[^\"]+\")|(?:\"\w+\s*=)|(?:>\w=\/)|(?:#.+\)[\"\s]*>)|(?:\"\s*(?:src|style|on\w+)\s*=\s*\")|(?:[^\"]?\"[,;\s]+\w*[\[\(])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\"+.*[<=]\s*\"[^\"]+\")|(?:\"\w+\s*=)|(?:>\w=\/)|(?:#.+\)[\"\s]*>)|(?:\"\s*(?:src|style|on\w+)\s*=\s*\")|(?:[^\"]?\"[,;\s]+\w*[\[\(])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@>])(\s*return\s*)?(?:hash|name|href|navigateandfind|source|pathname|close|constructor|port|protocol|assign|replace|back|forward|document|ownerdocument|window|top|this|self|parent|frames|_?content|date|cookie|innerhtml|innertext|csstext+?|outerhtml|print|moveby|resizeto|createstylesheet|stylesheets)(?(1)[^\w%\"]|(?:\s*[^@\/\s\w%.+\-]))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  ([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@>])(\s*return\s*)?(?:hash|name|href|navigateandfind|source|pathname|close|constructor|port|protocol|assign|replace|back|forward|document|ownerdocument|window|top|this|self|parent|frames|_?content|date|cookie|innerhtml|innertext|csstext+?|outerhtml|print|moveby|resizeto|createstylesheet|stylesheets)(?(1)[^\w%\"]|(?:\s*[^@\/\s\w%.+\-]))
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@>])(\s*return\s*)?(?:hash|name|href|navigateandfind|source|pathname|close|constructor|port|protocol|assign|replace|back|forward|document|ownerdocument|window|top|this|self|parent|frames|_?content|date|cookie|innerhtml|innertext|csstext+?|outerhtml|print|moveby|resizeto|createstylesheet|stylesheets)(?(1)[^\w%\"]|(?:\s*[^@\/\s\w%.+\-]))"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\"[^\"]*[^-]?>)|(?:[^\w\s]\s*\/>)|(?:>\")"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\"[^\"]*[^-]?>)|(?:[^\w\s]\s*\/>)|(?:>\")
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\"[^\"]*[^-]?>)|(?:[^\w\s]\s*\/>)|(?:>\")"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:=\s*\w+\s*\+\s*\")|(?:\+=\s*\(\s\")|(?:!+\s*[\d.,]+\w?\d*\s*\?)|(?:=\s*\[s*\])|(?:\"\s*\+\s*\")|(?:[^\s]\[\s*\d+\s*\]\s*[;+])|(?:\"\s*[&|]+\s*\")|(?:\/\s*\?\s*\")|(?:\/\s*\)\s*\[)|(?:\d\?.+:\d)|(?:]\s*\[\W*\w)|(?:[^\s]\s*=\s*\/)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:=\s*\w+\s*\+\s*\")|(?:\+=\s*\(\s\")|(?:!+\s*[\d.,]+\w?\d*\s*\?)|(?:=\s*\[s*\])|(?:\"\s*\+\s*\")|(?:[^\s]\[\s*\d+\s*\]\s*[;+])|(?:\"\s*[&|]+\s*\")|(?:\/\s*\?\s*\")|(?:\/\s*\)\s*\[)|(?:\d\?.+:\d)|(?:]\s*\[\W*\w)|(?:[^\s]\s*=\s*\/)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:=\s*\w+\s*\+\s*\")|(?:\+=\s*\(\s\")|(?:!+\s*[\d.,]+\w?\d*\s*\?)|(?:=\s*\[s*\])|(?:\"\s*\+\s*\")|(?:[^\s]\[\s*\d+\s*\]\s*[;+])|(?:\"\s*[&|]+\s*\")|(?:\/\s*\?\s*\")|(?:\/\s*\)\s*\[)|(?:\d\?.+:\d)|(?:]\s*\[\W*\w)|(?:[^\s]\s*=\s*\/)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:=\s*[$\w]\s*[\(\[])|(?:\(\s*(?:this|top|window|self|parent|_?content)\s*\))|(?:src\s*=s*(?:\w+:|\/\/))|(?:\w+\[(\"\w+\"|\w+\|\|))|(?:[\d\W]\|\|[\d\W]|\W=\w+,)|(?:\/\s*\+\s*[a-z\"])|(?:=\s*\$[^([]*\()|(?:=\s*\(\s*\")"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:=\s*[$\w]\s*[\(\[])|(?:\(\s*(?:this|top|window|self|parent|_?content)\s*\))|(?:src\s*=s*(?:\w+:|\/\/))|(?:\w+\[(\"\w+\"|\w+\|\|))|(?:[\d\W]\|\|[\d\W]|\W=\w+,)|(?:\/\s*\+\s*[a-z\"])|(?:=\s*\$[^([]*\()|(?:=\s*\(\s*\")
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:=\s*[$\w]\s*[\(\[])|(?:\(\s*(?:this|top|window|self|parent|_?content)\s*\))|(?:src\s*=s*(?:\w+:|\/\/))|(?:\w+\[(\"\w+\"|\w+\|\|))|(?:[\d\W]\|\|[\d\W]|\W=\w+,)|(?:\/\s*\+\s*[a-z\"])|(?:=\s*\$[^([]*\()|(?:=\s*\(\s*\")"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:firefoxurl:\w+\|)|(?:(?:file|res|telnet|nntp|news|mailto|chrome)\s*:\s*[\%&#xu\/]+)|(wyciwyg|firefoxurl\s*:\s*\/\s*\/)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:firefoxurl:\w+\|)|(?:(?:file|res|telnet|nntp|news|mailto|chrome)\s*:\s*[\%&#xu\/]+)|(wyciwyg|firefoxurl\s*:\s*\/\s*\/)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:firefoxurl:\w+\|)|(?:(?:file|res|telnet|nntp|news|mailto|chrome)\s*:\s*[\%&#xu\/]+)|(wyciwyg|firefoxurl\s*:\s*\/\s*\/)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\)\s*when\s*\d+\s*then)|(?:\"\s*(?:#|--|{))|(?:\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?or|not)\s+|\|\||\&\&)\s*\w+\()"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\)\s*when\s*\d+\s*then)|(?:\"\s*(?:#|--|{))|(?:\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?or|not)\s+|\|\||\&\&)\s*\w+\()
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\)\s*when\s*\d+\s*then)|(?:\"\s*(?:#|--|{))|(?:\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?or|not)\s+|\|\||\&\&)\s*\w+\()"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:#@~\^\w+)|(?:\w+script:|@import[^\w]|;base64|base64,)|(?:\w+\s*\([\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+\))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:#@~\^\w+)|(?:\w+script:|@import[^\w]|;base64|base64,)|(?:\w+\s*\([\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+\))
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:#@~\^\w+)|(?:\w+script:|@import[^\w]|;base64|base64,)|(?:\w+\s*\([\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+\))"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:(?:msgbox|eval)\s*\+|(?:language\s*=\*vbscript))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:(?:msgbox|eval)\s*\+|(?:language\s*=\*vbscript))
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:(?:msgbox|eval)\s*\+|(?:language\s*=\*vbscript))"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:(?:[;]+|(<[?%](?:php)?)).*(?:define|eval|file_get_contents|include|require|require_once|set|shell_exec|phpinfo|system|passthru|preg_\w+|execute)\s*[\"(@])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:(?:[;]+|(<[?%](?:php)?)).*(?:define|eval|file_get_contents|include|require|require_once|set|shell_exec|phpinfo|system|passthru|preg_\w+|execute)\s*[\"(@])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:(?:[;]+|(<[?%](?:php)?)).*(?:define|eval|file_get_contents|include|require|require_once|set|shell_exec|phpinfo|system|passthru|preg_\w+|execute)\s*[\"(@])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\"\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w\"\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+\"\w)|(?:\";\s*(?:if|while|begin))|(?:\"[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\"\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w\"\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+\"\w)|(?:\";\s*(?:if|while|begin))|(?:\"[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\"\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w\"\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+\"\w)|(?:\";\s*(?:if|while|begin))|(?:\"[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:[\".]script\s*\()|(?:\$\$?\s*\(\s*[\w\"])|(?:\/[\w\s]+\/\.)|(?:=\s*\/\w+\/\s*\.)|(?:(?:this|window|top|parent|frames|self|content)\[\s*[(,\"]*\s*[\w\$])|(?:,\s*new\s+\w+\s*[,;)])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:[\".]script\s*\()|(?:\$\$?\s*\(\s*[\w\"])|(?:\/[\w\s]+\/\.)|(?:=\s*\/\w+\/\s*\.)|(?:(?:this|window|top|parent|frames|self|content)\[\s*[(,\"]*\s*[\w\$])|(?:,\s*new\s+\w+\s*[,;)])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:[\".]script\s*\()|(?:\$\$?\s*\(\s*[\w\"])|(?:\/[\w\s]+\/\.)|(?:=\s*\/\w+\/\s*\.)|(?:(?:this|window|top|parent|frames|self|content)\[\s*[(,\"]*\s*[\w\$])|(?:,\s*new\s+\w+\s*[,;)])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:=\s*(?:top|this|window|content|self|frames|_content))|(?:\/\s*\w*\s*[)}])|(?:[^\s]\s*=\s*script)|(?:\.\s*constructor)|(?:default\s+xml\s+namespace\s*=)|(?:\/\s*\+[^+]+\s*\+\s*\/)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:=\s*(?:top|this|window|content|self|frames|_content))|(?:\/\s*\w*\s*[)}])|(?:[^\s]\s*=\s*script)|(?:\.\s*constructor)|(?:default\s+xml\s+namespace\s*=)|(?:\/\s*\+[^+]+\s*\+\s*\/)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:=\s*(?:top|this|window|content|self|frames|_content))|(?:\/\s*\w*\s*[)}])|(?:[^\s]\s*=\s*script)|(?:\.\s*constructor)|(?:default\s+xml\s+namespace\s*=)|(?:\/\s*\+[^+]+\s*\+\s*\/)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\"\s*or\s*\d)|(?:\\\\\\\\x(?:23|27|3d))|(?:^.?\"$)|(?:^.*\\\\\\\\\".+(?<!\\\\\\\\)\")|(?:(?:^[\"\\\\\\\\]*(?:[\d\"]+|[^\"]+\"))+\s*(?:n?and|x?or|not|\|\||\&\&)\s*[\w\"[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*\"\s*\w)|(?:@\w+\s+(and|or)\s*[\"\d]+)|(?:@[\w-]+\s(and|or)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*\".)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\"\s*or\s*\d)|(?:\\\\\\\\x(?:23|27|3d))|(?:^.?\"$)|(?:^.*\\\\\\\\\".+(?<!\\\\\\\\)\")|(?:(?:^[\"\\\\\\\\]*(?:[\d\"]+|[^\"]+\"))+\s*(?:n?and|x?or|not|\|\||\&\&)\s*[\w\"[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*\"\s*\w)|(?:@\w+\s+(and|or)\s*[\"\d]+)|(?:@[\w-]+\s(and|or)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*\".)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\"\s*or\s*\d)|(?:\\\\\\\\x(?:23|27|3d))|(?:^.?\"$)|(?:^.*\\\\\\\\\".+(?<!\\\\\\\\)\")|(?:(?:^[\"\\\\\\\\]*(?:[\d\"]+|[^\"]+\"))+\s*(?:n?and|x?or|not|\|\||\&\&)\s*[\w\"[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*\"\s*\w)|(?:@\w+\s+(and|or)\s*[\"\d]+)|(?:@[\w-]+\s(and|or)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*\".)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:in\s*\(+\s*select)|(?:(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*\"|[=\d]+x))|(\"\s*\d\s*(?:--|#))|(?:\"[\%&<>^=]+\d\s*(=|or))|(?:\"\W+[\w+-]+\s*=\s*\d\W+\")|(?:\"\s*is\s*\d.+\"?\w)|(?:\"\|?[\w-]{3,}[^\w\s.,]+\")|(?:\"\s*is\s*[\d.]+\s*\W.*\")"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:in\s*\(+\s*select)|(?:(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*\"|[=\d]+x))|(\"\s*\d\s*(?:--|#))|(?:\"[\%&<>^=]+\d\s*(=|or))|(?:\"\W+[\w+-]+\s*=\s*\d\W+\")|(?:\"\s*is\s*\d.+\"?\w)|(?:\"\|?[\w-]{3,}[^\w\s.,]+\")|(?:\"\s*is\s*[\d.]+\s*\W.*\")
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:in\s*\(+\s*select)|(?:(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*\"|[=\d]+x))|(\"\s*\d\s*(?:--|#))|(?:\"[\%&<>^=]+\d\s*(=|or))|(?:\"\W+[\w+-]+\s*=\s*\d\W+\")|(?:\"\s*is\s*\d.+\"?\w)|(?:\"\|?[\w-]{3,}[^\w\s.,]+\")|(?:\"\s*is\s*[\d.]+\s*\W.*\")"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\.\s*\w+\W*=)|(?:\W\s*(?:location|document)\s*\W[^({[;]+[({[;])|(?:\(\w+\?[:\w]+\))|(?:\w{2,}\s*=\s*\d+[^&\w]\w+)|(?:\]\s*\(\s*\w+)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\.\s*\w+\W*=)|(?:\W\s*(?:location|document)\s*\W[^({[;]+[({[;])|(?:\(\w+\?[:\w]+\))|(?:\w{2,}\s*=\s*\d+[^&\w]\w+)|(?:\]\s*\(\s*\w+)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\.\s*\w+\W*=)|(?:\W\s*(?:location|document)\s*\W[^({[;]+[({[;])|(?:\(\w+\?[:\w]+\))|(?:\w{2,}\s*=\s*\d+[^&\w]\w+)|(?:\]\s*\(\s*\w+)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:%u(?:ff|00|e\d)\w\w)|(?:(?:%(?:e\w|c[^3\W]|))(?:%\w\w)(?:%\w\w)?)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:%u(?:ff|00|e\d)\w\w)|(?:(?:%(?:e\w|c[^3\W]|))(?:%\w\w)(?:%\w\w)?)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:%u(?:ff|00|e\d)\w\w)|(?:(?:%(?:e\w|c[^3\W]|))(?:%\w\w)(?:%\w\w)?)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:with\s*\(\s*.+\s*\)\s*\w+\s*\()|(?:(?:do|while|for)\s*\([^)]*\)\s*\{)|(?:\/[\w\s]*\[\W*\w)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:with\s*\(\s*.+\s*\)\s*\w+\s*\()|(?:(?:do|while|for)\s*\([^)]*\)\s*\{)|(?:\/[\w\s]*\[\W*\w)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:with\s*\(\s*.+\s*\)\s*\w+\s*\()|(?:(?:do|while|for)\s*\([^)]*\)\s*\{)|(?:\/[\w\s]*\[\W*\w)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:^>[\w\s]*<\/?\w{2,}>)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:^>[\w\s]*<\/?\w{2,}>)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:^>[\w\s]*<\/?\w{2,}>)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\\\\\\\\u00[a-f0-9]{2})|(?:\\\\\\\\x0*[a-f0-9]{2})|(?:\\\\\\\\\d{2,3})"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\\\\\\\\u00[a-f0-9]{2})|(?:\\\\\\\\x0*[a-f0-9]{2})|(?:\\\\\\\\\d{2,3})
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\\\\\\\\u00[a-f0-9]{2})|(?:\\\\\\\\x0*[a-f0-9]{2})|(?:\\\\\\\\\d{2,3})"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,})"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,})
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,})"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:[\d\W]\s+as\s*[\"\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:concat|char|load_file)\s?\(?)|(?:end\s*\);)|(\"\s+regexp\W)|(?:[\s(]load_file\s*\()"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:[\d\W]\s+as\s*[\"\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:concat|char|load_file)\s?\(?)|(?:end\s*\);)|(\"\s+regexp\W)|(?:[\s(]load_file\s*\()
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:[\d\W]\s+as\s*[\"\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:concat|char|load_file)\s?\(?)|(?:end\s*\);)|(\"\s+regexp\W)|(?:[\s(]load_file\s*\()"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\/\w*\s*\)\s*\()|(?:\(.*\/.+\/\w*\s*\))|(?:\([\w\s]+\([\w\s]+\)[\w\s]+\))|(?:(?<!(?:mozilla\/\d\.\d\s))\([^)[]+\[[^\]]+\][^)]*\))|(?:[^\s!][{([][^({[]+[{([][^}\])]+[}\])][\s+\",\d]*[}\])])|(?:\"\)?\]\W*\[)|(?:=\s*[^\s:;]+\s*[{([][^}\])]+[}\])];)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\/\w*\s*\)\s*\()|(?:\(.*\/.+\/\w*\s*\))|(?:\([\w\s]+\([\w\s]+\)[\w\s]+\))|(?:(?<!(?:mozilla\/\d\.\d\s))\([^)[]+\[[^\]]+\][^)]*\))|(?:[^\s!][{([][^({[]+[{([][^}\])]+[}\])][\s+\",\d]*[}\])])|(?:\"\)?\]\W*\[)|(?:=\s*[^\s:;]+\s*[{([][^}\])]+[}\])];)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\/\w*\s*\)\s*\()|(?:\(.*\/.+\/\w*\s*\))|(?:\([\w\s]+\([\w\s]+\)[\w\s]+\))|(?:(?<!(?:mozilla\/\d\.\d\s))\([^)[]+\[[^\]]+\][^)]*\))|(?:[^\s!][{([][^({[]+[{([][^}\])]+[}\])][\s+\",\d]*[}\])])|(?:\"\)?\]\W*\[)|(?:=\s*[^\s:;]+\s*[{([][^}\])]+[}\])];)"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\<[\/]?(?:[i]?frame|applet|isindex|marquee|keygen|script|audio|video|input|button|textarea|style|base|body|meta|link|object|embed|param|plaintext|xm\w+|image|im(?:g|port)))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\<[\/]?(?:[i]?frame|applet|isindex|marquee|keygen|script|audio|video|input|button|textarea|style|base|body|meta|link|object|embed|param|plaintext|xm\w+|image|im(?:g|port)))
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\<[\/]?(?:[i]?frame|applet|isindex|marquee|keygen|script|audio|video|input|button|textarea|style|base|body|meta|link|object|embed|param|plaintext|xm\w+|image|im(?:g|port)))"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:[+\/]\s*name[\W\d]*[)+])|(?:;\W*url\s*=)|(?:[^\w\s\/?:>]\s*(?:location|referrer|name)\s*[^\/\w\s-])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:[+\/]\s*name[\W\d]*[)+])|(?:;\W*url\s*=)|(?:[^\w\s\/?:>]\s*(?:location|referrer|name)\s*[^\/\w\s-])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:[+\/]\s*name[\W\d]*[)+])|(?:;\W*url\s*=)|(?:[^\w\s\/?:>]\s*(?:location|referrer|name)\s*[^\/\w\s-])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\<\/\w+\s\w+)|(?:@(?:cc_on|set)[\s@,\"=])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\<\/\w+\s\w+)|(?:@(?:cc_on|set)[\s@,\"=])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\<\/\w+\s\w+)|(?:@(?:cc_on|set)[\s@,\"=])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\<base\s+)|(?:<!(?:element|entity|\[CDATA))"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\<base\s+)|(?:<!(?:element|entity|\[CDATA))
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\<base\s+)|(?:<!(?:element|entity|\[CDATA))"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\"\s*\*.+(?:or|id)\W*\"\d)|(?:\^\")|(?:^[\w\s\"-]+(?<=and\s)(?<=or\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:\"[\s\d]*[^\w\s]+\W*\d\W*.*[\"\d])|(?:\"\s*[^\w\s?]+\s*[^\w\s]+\s*\")|(?:\"\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:\".*\*\s*\d)|(?:\"\s*or\s[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+\"[^,])"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\"\s*\*.+(?:or|id)\W*\"\d)|(?:\^\")|(?:^[\w\s\"-]+(?<=and\s)(?<=or\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:\"[\s\d]*[^\w\s]+\W*\d\W*.*[\"\d])|(?:\"\s*[^\w\s?]+\s*[^\w\s]+\s*\")|(?:\"\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:\".*\*\s*\d)|(?:\"\s*or\s[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+\"[^,])
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\"\s*\*.+(?:or|id)\W*\"\d)|(?:\^\")|(?:^[\w\s\"-]+(?<=and\s)(?<=or\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:\"[\s\d]*[^\w\s]+\W*\d\W*.*[\"\d])|(?:\"\s*[^\w\s?]+\s*[^\w\s]+\s*\")|(?:\"\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:\".*\*\s*\d)|(?:\"\s*or\s[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+\"[^,])"){
      call sec_default_handler;
   }
   ## TX, :re(_normalized)
   # AC re(_normalized) 
   ## Rule: TX rx :re(_normalized)
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\W\s*hash\s*[^\w\s-])|(?:\w+=\W*[^,]*,[^\s(]\s*\()|(?:\?\"[^\s\"]\":)|(?:(?<!\/)__[a-z]+__)|(?:(?:^|[\s)\]\}])(?:s|g)etter\s*=)"){
      call sec_default_handler;
   }
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?:\W\s*hash\s*[^\w\s-])|(?:\w+=\W*[^,]*,[^\s(]\s*\()|(?:\?\"[^\s\"]\":)|(?:(?<!\/)__[a-z]+__)|(?:(?:^|[\s)\]\}])(?:s|g)etter\s*=)
   ## REQUEST_URI_RAW, 
   ## Rule: REQUEST_URI_RAW rx :
   if(req.url ~ "(?:\W\s*hash\s*[^\w\s-])|(?:\w+=\W*[^,]*,[^\s(]\s*\()|(?:\?\"[^\s\"]\":)|(?:(?<!\/)__[a-z]+__)|(?:(?:^|[\s)\]\}])(?:s|g)etter\s*=)"){
      call sec_default_handler;
   }
}

