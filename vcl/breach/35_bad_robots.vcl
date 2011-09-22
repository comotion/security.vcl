sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   # skipped   REQUEST_HEADERS pmFromFile User-Agent modsecurity_35_scanners.data
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "^/nessustest"){
      set req.http.X-Sec-RuleInfo = "Request Indicates a Security Scanner Scanned the Site";
      set req.http.X-Sec-RuleName = "AUTOMATION/SECURITY_SCANNER";
      set req.http.X-Sec-RuleName = "WASCTC/WASC-21";
      set req.http.X-Sec-RuleName = "OWASP_TOP_10/A7";
      set req.http.X-Sec-RuleName = "PCI/6.5.10";
      set req.http.X-Sec-Severity = "4";
      set req.http.X-Sec-RuleId = "990902";
      call sec_default_handler;
   }
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   # skipped   REQUEST_HEADERS pmFromFile User-Agent modsecurity_35_bad_robots.data
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "(?i:(?:c(?:o(?:n(?:t(?:entsmartz|actbot/)|cealed defense|veracrawler)|mpatible(?: ;(?: msie|\.)|-)|py(?:rightcheck|guard)|re-project/1.0)|h(?:ina(?: local browse 2\.|claw)|e(?:rrypicker|esebot))|rescent internet toolpak)|w(?:e(?:b(?: (?:downloader|by mail)|(?:(?:altb|ro)o|bandi)t|emailextract?|vulnscan|mole)|lls search ii|p Search 00)|i(?:ndows(?:-update-agent| xp 5)|se(?:nut)?bot)|ordpress(?: hash grabber|\/4\.01)|3mir)|m(?:o(?:r(?:feus fucking scanner|zilla)|zilla\/3\.mozilla\/2\.01$|siac 1.)|i(?:crosoft (?:internet explorer\/5\.0$|url control)|ssigua)|ailto:craftbot\@yahoo\.com|urzillo compatible)|p(?:ro(?:gram shareware 1\.0\.|duction bot|webwalker)|a(?:nscient\.com|ckrat)|oe-component-client|s(?:ycheclone|urf)|leasecrawl\/1\.|cbrowser|e 1\.4|mafind)|e(?:mail(?:(?:collec|harves|magne)t|(?: extracto|reape)r|(siphon|spider)|siphon|wolf)|(?:collecto|irgrabbe)r|ducate search vxb|xtractorpro|o browse)|t(?:(?: ?h ?a ?t ?' ?s g ?o ?t ?t ?a ? h ?u ?r ?|his is an exploi|akeou)t|oata dragostea mea pentru diavola|ele(?:port pro|soft)|uring machine)|a(?:t(?:(?:omic_email_hunt|spid)er|tache|hens)|d(?:vanced email extractor|sarobot)|gdm79\@mail\.ru|miga-aweb\/3\.4|utoemailspider| href=)|^(?:(google|i?explorer?\.exe|(ms)?ie( [0-9.]+)?\ ?(compatible( browser)?)?)$|www\.weblogs\.com|(?:jakart|vi)a|microsoft url|user-Agent)|s(?:e(?:archbot admin@google.com|curity scan)|(?:tress tes|urveybo)t|\.t\.a\.l\.k\.e\.r\.|afexplorer tl|itesnagger|hai)|n(?:o(?:kia-waptoolkit.* googlebot.*googlebot| browser)|e(?:(?:wt activeX; win3|uralbot\/0\.)2|ssus)|ameofagent|ikto)|f(?:a(?:(?:ntombrows|stlwspid)er|xobot)|(?:ranklin locato|iddle)r|ull web bot|loodgate|oobar/)|i(?:n(?:ternet(?: (?:exploiter sux|ninja)|-exprorer)|dy library)|sc systems irc search 2\.1)|g(?:ameBoy, powered by nintendo|rub(?: crawler|-client)|ecko\/25)|(myie2|libwen-us|murzillo compatible|webaltbot|wisenutbot)|b(?:wh3_user_agent|utch__2\.1\.1|lack hole|ackdoor)|d(?:ig(?:imarc webreader|out4uagent)|ts agent)|(?:(script|sql) inject|$botname/$botvers)ion|(msie .+; .*windows xp|compatible \; msie)|h(?:l_ftien_spider|hjhj@yahoo|anzoweb)|(?:8484 boston projec|xmlrpc exploi)t|u(?:nder the rainbow 2\.|ser-agent:)|(sogou develop spider|sohu agent)|(?:(?:d|e)browse|demo bot)|zeus(?: .*webster pro)?|[a-z]surf[0-9][0-9]|v(?:adixbot|oideye)|larbin@unspecified|\bdatacha0s\b|kenjin spider|; widows|rsync|\\\r))"){
      call sec_default_handler;
   }
}

