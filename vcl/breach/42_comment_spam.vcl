sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## IP, :PREVIOUS_RBL_CHECK
   # AC PREVIOUS_RBL_CHECK 
   # skipped   IP eq PREVIOUS_RBL_CHECK 1
   ## REMOTE_ADDR, 
   # skipped   REMOTE_ADDR rbl  sbl-xbl.spamhaus.org
   ## IP, :SPAMMER
   # AC SPAMMER 
   # skipped   IP eq SPAMMER 1
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   # skipped   REQUEST_HEADERS pmFromFile User-Agent modsecurity_42_comment_spam.data
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "^(?:m(?:o(?:zilla\/4\.0\+?\(|vable type)|i(?:crosoft url|ssigua)|j12bot\/v1\.0\.8|sie)|e(?:mail(?:collector| ?siphon)|collector)|(?:blogsearchbot-marti|super happy fu)n|i(?:nternet explorer|sc systems irc)|ja(?:karta commons|va(?:\/| )1\.)|c(?:ore-project\/|herrypicker)|p(?:sycheclone|ussycat|ycurl)|(?:grub crawl|omniexplor)er|a(?:utoemailspider|dwords)|w(?:innie poh|ordpress)|nut(?:scrape/|chcvs)|8484 boston project|user(?:[- ]agent:)?|l(?:ibwww-perl|wp)|di(?:amond|gger)|trackback\/|httpproxy|<sc)"){
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bhttp:"){
      set req.http.X-Sec-Severity = "6";
      set req.http.X-Sec-RuleId = "999010";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bhttp:"){
      set req.http.X-Sec-Severity = "6";
      set req.http.X-Sec-RuleId = "999010";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\[url\b"){
      set req.http.X-Sec-RuleInfo = "Comment Spam";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950923";
      # chained rule
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\[url\b"){
      set req.http.X-Sec-RuleInfo = "Comment Spam";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950923";
      # chained rule
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\<a"){
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\<a"){
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(http:\/.*?){4}"){
      set req.http.X-Sec-RuleInfo = "Comment Spam";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950020";
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(http:\/.*?){4}"){
      set req.http.X-Sec-RuleInfo = "Comment Spam";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950020";
      call sec_default_handler;
   }
}

