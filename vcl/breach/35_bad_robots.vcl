sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "(\b(m(ozilla\/4\.0 \(compatible\)|etis)|webtrends security analyzer|pmafind)\b|n(-stealth|sauditor|essus|ikto)|b(lack ?widow|rutus|ilbo)|(jaascoi|paro)s|webinspect|\.nasl)"){
      set req.http.X-Sec-Return = "404";
      set req.http.X-Sec-RuleInfo = "Request Indicates a Security Scanner Scanned the Site";
      set req.http.X-Sec-RuleName = "AUTOMATION/SECURITY_SCANNER";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "990002";
      call sec_sev1;
   }
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "^/nessustest"){
      set req.http.X-Sec-Return = "404";
      set req.http.X-Sec-RuleInfo = "Request Indicates a Security Scanner Scanned the Site";
      set req.http.X-Sec-RuleName = "AUTOMATION/SECURITY_SCANNER";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "990902";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "(e(mail((collec|harves|magne)t|( extracto|reape)r|siphon|wolf)|(collecto|irgrabbe)r|xtractorpro|o browse)|m(ozilla\/4\.0 \(compatible; advanced email extractor|ailto:craftbot\@yahoo\.com)|a(t(tache|hens)|utoemailspider|dsarobot)|w(eb(emailextrac| by mail)|3mir)|f(astlwspider|loodgate)|p(cbrowser|ackrat|surf)|(digout4uagen|takeou)t|\bdatacha0s\b|hhjhj@yahoo|chinaclaw|rsync|shai|zeus)"){
      set req.http.X-Sec-Return = "404";
      set req.http.X-Sec-RuleInfo = "Rogue web site crawler";
      set req.http.X-Sec-RuleName = "AUTOMATION/MALICIOUS";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "990012";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "(\b((indy librar|snoop)y|microsoft url control|lynx)\b|mozilla\/2\.0 \(compatible; newt activex; win32\)|w(3mirror|get)|download demon|l(ibwww|wp)|p(avuk|erl)|big brother|autohttp|netants|eCatch|curl)"){
      set req.http.X-Sec-RuleInfo = "Request Indicates an automated program explored the site";
      set req.http.X-Sec-RuleName = "AUTOMATION/MISC";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "990011";
      # chained rule
   }
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "^apache.*perl"){
      call sec_sev1;
   }
}

