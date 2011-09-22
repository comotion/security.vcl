sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "msn(?:bot|ptc)"){
      set req.http.X-Sec-RuleInfo = "MSN robot activity";
      set req.http.X-Sec-Severity = "6";
      set req.http.X-Sec-RuleId = "910008";
      call sec_default_handler;
   }
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "\byahoo(?:-(?:mmcrawler|blogs)|! slurp)\b"){
      set req.http.X-Sec-RuleInfo = "Yahoo robot activity";
      set req.http.X-Sec-Severity = "6";
      set req.http.X-Sec-RuleId = "910007";
      call sec_default_handler;
   }
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "(?:(?:gsa-crawler \(enterprise; s4-e9lj2b82fjjaa; me\@mycompany\.com|adsbot-google \(\+http:\/\/www\.google\.com\/adsbot\.html)\)|\b(?:google(?:-sitemaps|bot)|mediapartners-google)\b)"){
      set req.http.X-Sec-RuleInfo = "Google robot activity";
      set req.http.X-Sec-Severity = "6";
      set req.http.X-Sec-RuleId = "910006";
      call sec_default_handler;
   }
}

