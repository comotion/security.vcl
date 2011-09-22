sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pmFromFile  modsecurity_46_slr_et_joomla.data
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /models/category.php
   ## ARGS, :catid
   # AC catid 
   ## Rule: ARGS rx :catid
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /models/category.php
   ## ARGS, :catid
   # AC catid 
   ## Rule: ARGS rx :catid
   if(req.url ~ "(?i:UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /models/category.php
   ## ARGS, :catid
   # AC catid 
   ## Rule: ARGS rx :catid
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /models/category.php
   ## ARGS, :catid
   # AC catid 
   ## Rule: ARGS rx :catid
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /models/category.php
   ## ARGS, :catid
   # AC catid 
   ## Rule: ARGS rx :catid
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /models/category.php
   ## ARGS, :catid
   # AC catid 
   ## Rule: ARGS rx :catid
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /letterman.class.php
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /letterman.class.php
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /letterman.class.php
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /letterman.class.php
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /letterman.class.php
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /letterman.class.php
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/user/example.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/user/example.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION\s+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/user/example.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/user/example.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/user/example.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:ASCII\(.+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/user/example.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gmail.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gmail.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION\s+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gmail.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gmail.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gmail.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:ASCII\(.+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gmail.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /example.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /example.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION\s+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /example.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /example.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /example.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:ASCII\(.+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /example.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/authentication/ldap.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/authentication/ldap.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION\s+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/authentication/ldap.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/authentication/ldap.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/authentication/ldap.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:ASCII\(.+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/authentication/ldap.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/mod_mainmenu/menu.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/mod_mainmenu/menu.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION\s+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/mod_mainmenu/menu.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/mod_mainmenu/menu.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/mod_mainmenu/menu.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:ASCII\(.+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/mod_mainmenu/menu.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/content.php
   ## ARGS, :where
   # AC where 
   ## Rule: ARGS rx :where
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/content.php
   ## ARGS, :where
   # AC where 
   ## Rule: ARGS rx :where
   if(req.url ~ "(?i:UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/content.php
   ## ARGS, :where
   # AC where 
   ## Rule: ARGS rx :where
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/content.php
   ## ARGS, :where
   # AC where 
   ## Rule: ARGS rx :where
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/content.php
   ## ARGS, :where
   # AC where 
   ## Rule: ARGS rx :where
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/content.php
   ## ARGS, :where
   # AC where 
   ## Rule: ARGS rx :where
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/weblinks.php
   ## ARGS, :where
   # AC where 
   ## Rule: ARGS rx :where
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/weblinks.php
   ## ARGS, :where
   # AC where 
   ## Rule: ARGS rx :where
   if(req.url ~ "(?i:UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/weblinks.php
   ## ARGS, :where
   # AC where 
   ## Rule: ARGS rx :where
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/weblinks.php
   ## ARGS, :where
   # AC where 
   ## Rule: ARGS rx :where
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/weblinks.php
   ## ARGS, :where
   # AC where 
   ## Rule: ARGS rx :where
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/weblinks.php
   ## ARGS, :where
   # AC where 
   ## Rule: ARGS rx :where
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/contacts.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/contacts.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/contacts.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/contacts.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/contacts.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/contacts.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/categories.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/categories.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/categories.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/categories.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/categories.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/categories.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/sections.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/sections.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/sections.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/sections.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/sections.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/sections.php
   ## ARGS, :text
   # AC text 
   ## Rule: ARGS rx :text
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /database/table/user.php
   ## ARGS, :email
   # AC email 
   ## Rule: ARGS rx :email
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /database/table/user.php
   ## ARGS, :email
   # AC email 
   ## Rule: ARGS rx :email
   if(req.url ~ "(?i:UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /database/table/user.php
   ## ARGS, :email
   # AC email 
   ## Rule: ARGS rx :email
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /database/table/user.php
   ## ARGS, :email
   # AC email 
   ## Rule: ARGS rx :email
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /database/table/user.php
   ## ARGS, :email
   # AC email 
   ## Rule: ARGS rx :email
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /database/table/user.php
   ## ARGS, :email
   # AC email 
   ## Rule: ARGS rx :email
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index2.php?option=ds-syndicate
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  version=1
   ## ARGS, :feed_id
   # AC feed_id 
   ## Rule: ARGS rx :feed_id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_pro_desk
   ## ARGS, :include_file
   # AC include_file 
   ## Rule: ARGS rx :include_file
   if(req.url ~ "(?i:(\.\.\/){1,})"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin.rssreader.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_live_site
   # AC mosConfig_live_site 
   ## Rule: ARGS rx :mosConfig_live_site
   if(req.url ~ "(?i:mosConfig_live_site=\s*(https?|ftps?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  INSER
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "="){
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:target)"){
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleInfo = "SLR: ET WEB_SPECIFIC_APPS Possible Joomla! com_album Component Local File Inclusion Attempt";
      set req.http.X-Sec-RuleName = "web-application-attack";
      set req.http.X-Sec-RuleId = "2009929-4";
      # chained rule
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_album&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  Itemid=128&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /com_koesubmit/koesubmit.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:\x2Ephp\x3F.{0,300}\x3D(http\x3A|ftp\x3A|https\x3A|ftps\x3A))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_moofaq/includes/file_includer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :file
   # AC file 
   ## Rule: ARGS contains :file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_surveymanager
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=editsurvey&
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_surveymanager
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=editsurvey&
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_surveymanager
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=editsurvey&
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION.+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_surveymanager
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=editsurvey&
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_surveymanager
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=editsurvey&
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_jbudgetsmagic
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=mybudget&
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_jbudgetsmagic
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=mybudget&
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_jbudgetsmagic
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=mybudget&
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION.+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_jbudgetsmagic
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=mybudget&
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_jbudgetsmagic
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=mybudget&
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_facebook
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=student
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_facebook
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=student
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_facebook
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=student
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION.+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_facebook
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=student
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_facebook
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=student
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_sportfusion
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=teamdetail
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_sportfusion
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=teamdetail
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_sportfusion
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=teamdetail
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION.+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_sportfusion
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=teamdetail
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_sportfusion
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=teamdetail
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_gameserver
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=gamepanel
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_gameserver
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=gamepanel
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_gameserver
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=gamepanel
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_gameserver
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=gamepanel
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_gameserver
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=gamepanel
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_cbresumebuilder
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=group_members
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_cbresumebuilder
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=group_members
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_cbresumebuilder
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=group_members
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION.+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_cbresumebuilder
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=group_members
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_cbresumebuilder
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=group_members
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_soundset
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  showcategory
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_soundset
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  showcategory
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_soundset
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  showcategory
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION.+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_soundset
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  showcategory
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_ajaxchat/tests/ajcuser.php
   ## ARGS, :GLOBALS
   # AC GLOBALS 
   ## Rule: ARGS rx :GLOBALS
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  index.php?option=com_photoblog&
   ## ARGS, :&category
   # AC &category 
   ## Rule: ARGS rx :&category
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  index.php?option=com_photoblog&
   ## ARGS, :&category
   # AC &category 
   ## Rule: ARGS rx :&category
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  index.php?option=com_photoblog&
   ## ARGS, :&category
   # AC &category 
   ## Rule: ARGS rx :&category
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  index.php?option=com_photoblog&
   ## ARGS, :&category
   # AC &category 
   ## Rule: ARGS rx :&category
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  index.php?option=com_photoblog&
   ## ARGS, :&category
   # AC &category 
   ## Rule: ARGS rx :&category
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_ezine/class/php/d4m_ajax_pagenav.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :GLOBALS
   # AC GLOBALS 
   ## Rule: ARGS rx :GLOBALS
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  index.php?option=com_jshop&
   ## ARGS, :&pid
   # AC &pid 
   ## Rule: ARGS rx :&pid
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  index.php?option=com_jshop&
   ## ARGS, :&pid
   # AC &pid 
   ## Rule: ARGS rx :&pid
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  index.php?option=com_jshop&
   ## ARGS, :&pid
   # AC &pid 
   ## Rule: ARGS rx :&pid
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  index.php?option=com_jshop&
   ## ARGS, :&pid
   # AC &pid 
   ## Rule: ARGS rx :&pid
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  index.php?option=com_jshop&
   ## ARGS, :&pid
   # AC &pid 
   ## Rule: ARGS rx :&pid
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_joaktree&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &view=joaktree
   ## ARGS, :treeId
   # AC treeId 
   ## Rule: ARGS rx :treeId
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_joaktree&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &view=joaktree
   ## ARGS, :treeId
   # AC treeId 
   ## Rule: ARGS rx :treeId
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_joaktree&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &view=joaktree
   ## ARGS, :treeId
   # AC treeId 
   ## Rule: ARGS rx :treeId
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_joaktree&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &view=joaktree
   ## ARGS, :treeId
   # AC treeId 
   ## Rule: ARGS rx :treeId
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_joaktree&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &view=joaktree
   ## ARGS, :treeId
   # AC treeId 
   ## Rule: ARGS rx :treeId
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /acomponents/com_mamboleto/mamboleto.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path\s*=\s*(https?|ftps?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_jphoto&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=category&
   ## ARGS, :Id
   # AC Id 
   ## Rule: ARGS rx :Id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_jphoto&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=category&
   ## ARGS, :Id
   # AC Id 
   ## Rule: ARGS rx :Id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_jphoto&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=category&
   ## ARGS, :Id
   # AC Id 
   ## Rule: ARGS rx :Id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_jphoto&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=category&
   ## ARGS, :Id
   # AC Id 
   ## Rule: ARGS rx :Id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_jphoto&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=category&
   ## ARGS, :Id
   # AC Id 
   ## Rule: ARGS rx :Id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_mojo/wp-comments-post.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path\s*=\s*(https?|ftps?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_mojo/wp-trackback.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path\s*=\s*(https?|ftps?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_foobla_suggestions&
   ## ARGS, :idea_id
   # AC idea_id 
   ## Rule: ARGS rx :idea_id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_foobla_suggestions&
   ## ARGS, :idea_id
   # AC idea_id 
   ## Rule: ARGS rx :idea_id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_foobla_suggestions&
   ## ARGS, :idea_id
   # AC idea_id 
   ## Rule: ARGS rx :idea_id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_foobla_suggestions&
   ## ARGS, :idea_id
   # AC idea_id 
   ## Rule: ARGS rx :idea_id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_foobla_suggestions&
   ## ARGS, :idea_id
   # AC idea_id 
   ## Rule: ARGS rx :idea_id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_musicgallery&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &task=itempage
   ## ARGS, :Id
   # AC Id 
   ## Rule: ARGS rx :Id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_musicgallery&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &task=itempage
   ## ARGS, :Id
   # AC Id 
   ## Rule: ARGS rx :Id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_musicgallery&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &task=itempage
   ## ARGS, :Id
   # AC Id 
   ## Rule: ARGS rx :Id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_musicgallery&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &task=itempage
   ## ARGS, :Id
   # AC Id 
   ## Rule: ARGS rx :Id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_musicgallery&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &task=itempage
   ## ARGS, :Id
   # AC Id 
   ## Rule: ARGS rx :Id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_mediaslide/viewer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :path
   # AC path 
   ## Rule: ARGS contains :path
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_yelp&
   ## ARGS, :cid
   # AC cid 
   ## Rule: ARGS rx :cid
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_yelp&
   ## ARGS, :cid
   # AC cid 
   ## Rule: ARGS rx :cid
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_yelp&
   ## ARGS, :cid
   # AC cid 
   ## Rule: ARGS rx :cid
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_yelp&
   ## ARGS, :cid
   # AC cid 
   ## Rule: ARGS rx :cid
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_yelp&
   ## ARGS, :cid
   # AC cid 
   ## Rule: ARGS rx :cid
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_intuit/models/intuit.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :approval
   # AC approval 
   ## Rule: ARGS contains :approval
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_avosbillets&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_avosbillets&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_avosbillets&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_avosbillets&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_avosbillets&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_morfeoshow/morfeoshow.html.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :user_id
   # AC user_id 
   ## Rule: ARGS rx :user_id
   if(req.url ~ "(?i:user_id\s*=\s*(https?|ftps?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_job&
   ## ARGS, :id_job
   # AC id_job 
   ## Rule: ARGS rx :id_job
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_job&
   ## ARGS, :id_job
   # AC id_job 
   ## Rule: ARGS rx :id_job
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_job&
   ## ARGS, :id_job
   # AC id_job 
   ## Rule: ARGS rx :id_job
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_job&
   ## ARGS, :id_job
   # AC id_job 
   ## Rule: ARGS rx :id_job
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_job&
   ## ARGS, :id_job
   # AC id_job 
   ## Rule: ARGS rx :id_job
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_perchagallery&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_perchagallery&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_perchagallery&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_perchagallery&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_perchagallery&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_hdflvplayer&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_hdflvplayer&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_hdflvplayer&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_hdflvplayer&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_hdflvplayer&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_jcollection&
   ## ARGS, :controller
   # AC controller 
   ## Rule: ARGS contains :controller
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_ccnewsletter&
   ## ARGS, :controller
   # AC controller 
   ## Rule: ARGS contains :controller
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_sqlreport/ajax/print.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :user_id
   # AC user_id 
   ## Rule: ARGS rx :user_id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_sqlreport/ajax/print.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :user_id
   # AC user_id 
   ## Rule: ARGS rx :user_id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_sqlreport/ajax/print.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :user_id
   # AC user_id 
   ## Rule: ARGS rx :user_id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_sqlreport/ajax/print.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :user_id
   # AC user_id 
   ## Rule: ARGS rx :user_id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_sqlreport/ajax/print.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :user_id
   # AC user_id 
   ## Rule: ARGS rx :user_id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_quicknews&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &task=view_item
   ## ARGS, :newsid
   # AC newsid 
   ## Rule: ARGS rx :newsid
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_quicknews&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &task=view_item
   ## ARGS, :newsid
   # AC newsid 
   ## Rule: ARGS rx :newsid
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_quicknews&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &task=view_item
   ## ARGS, :newsid
   # AC newsid 
   ## Rule: ARGS rx :newsid
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_quicknews&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &task=view_item
   ## ARGS, :newsid
   # AC newsid 
   ## Rule: ARGS rx :newsid
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_quicknews&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &task=view_item
   ## ARGS, :newsid
   # AC newsid 
   ## Rule: ARGS rx :newsid
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_communitypolls&
   ## ARGS, :controller
   # AC controller 
   ## Rule: ARGS contains :controller
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_rsgallery2&
   ## ARGS, :catid
   # AC catid 
   ## Rule: ARGS rx :catid
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_rsgallery2&
   ## ARGS, :catid
   # AC catid 
   ## Rule: ARGS rx :catid
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_rsgallery2&
   ## ARGS, :catid
   # AC catid 
   ## Rule: ARGS rx :catid
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_rsgallery2&
   ## ARGS, :catid
   # AC catid 
   ## Rule: ARGS rx :catid
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_rsgallery2&
   ## ARGS, :catid
   # AC catid 
   ## Rule: ARGS rx :catid
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_blog&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_blog&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_blog&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_blog&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_blog&
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_jcalpro/cal_popup.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path\s*=\s*(https?|ftps?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_wgpicasa&
   ## ARGS, :controller
   # AC controller 
   ## Rule: ARGS contains :controller
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_gbufacebook&
   ## ARGS, :face_id
   # AC face_id 
   ## Rule: ARGS rx :face_id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_gbufacebook&
   ## ARGS, :face_id
   # AC face_id 
   ## Rule: ARGS rx :face_id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_gbufacebook&
   ## ARGS, :face_id
   # AC face_id 
   ## Rule: ARGS rx :face_id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_gbufacebook&
   ## ARGS, :face_id
   # AC face_id 
   ## Rule: ARGS rx :face_id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_gbufacebook&
   ## ARGS, :face_id
   # AC face_id 
   ## Rule: ARGS rx :face_id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_jwmmxtd/admin.jwmmxtd.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path=\s*(ftps?|https?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_universal/includes/config/config.html.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path=\s*(ftps?|https?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /config.dadamail.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :GLOBALS
   # AC GLOBALS 
   ## Rule: ARGS rx :GLOBALS
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /config.dadamail.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :GLOBALS
   # AC GLOBALS 
   ## Rule: ARGS rx :GLOBALS
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /com_ongumatimesheet20/lib/onguma.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path=\s*(https?|ftps?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_zoomportfolio
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=portfolio
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_zoomportfolio
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=portfolio
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_zoomportfolio
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=portfolio
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_zoomportfolio
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=portfolio
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_zoomportfolio
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=portfolio
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_jphone
   ## ARGS, :controller
   # AC controller 
   ## Rule: ARGS contains :controller
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_noticeboard
   ## ARGS, :controller
   # AC controller 
   ## Rule: ARGS contains :controller
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_jgrid
   ## ARGS, :controller
   # AC controller 
   ## Rule: ARGS contains :controller
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /com_rwcards/rwcards.advancedate.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path=\s*(ftps?|https?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /real_estate/index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_jomestate
   ## ARGS, :task
   # AC task 
   ## Rule: ARGS rx :task
   if(req.url ~ "(?i:task=\s*(ftps?|https?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_joomlaxplorer/admin.joomlaxplorer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path=\s*(ftps?|https?|php)\x3a\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_banners/banners.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path=\s*(ftps?|https?|php)\x3a\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_jimtawl
   ## ARGS, :task
   # AC task 
   ## Rule: ARGS contains :task
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_cbe
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=userProfile
   ## ARGS, :tabname
   # AC tabname 
   ## Rule: ARGS contains :tabname
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_billyportfolio
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=billyportfolio
   ## ARGS, :catid
   # AC catid 
   ## Rule: ARGS rx :catid
   if(req.url ~ "(?i:and.*if\()"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_seyret
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=videodirectlink
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /com_xmovie/helpers/img.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :file
   # AC file 
   ## Rule: ARGS contains :file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_frontenduseraccess
   ## ARGS, :controller
   # AC controller 
   ## Rule: ARGS contains :controller
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_xgallery/helpers/img.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :file
   # AC file 
   ## Rule: ARGS contains :file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /com_swmenupro/ImageManager/Classes/ImageManager.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path=\s*(ftps?|https?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_xcloner-backupandrestore/cloner.cron.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :config
   # AC config 
   ## Rule: ARGS contains :config
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_xcloner-backupandrestore/index2.php
   ## ARGS, :mosmsg
   # AC mosmsg 
   ## Rule: ARGS rx :mosmsg
   if(req.url ~ "(?i:mosmsg\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  admin.ponygallery.html.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_doqment
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path=\s*(ftps?|https?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_smartformer/smartformer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path=\s*(ftps?|https?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_mediamall
   ## ARGS, :category
   # AC category 
   ## Rule: ARGS rx :category
   if(req.url ~ "(?i:and.*substring\()"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:page)"){
      # chained rule
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_virtuemart
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  substring
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/mod_virtuemart_latestprod/mod_virtuemart_latestprod.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path=\s*(ftps?|https?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/mod_virtuemart_featureprod/mod_virtuemart_featureprod.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path=\s*(ftps?|https?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_hello
   ## ARGS, :secid
   # AC secid 
   ## Rule: ARGS rx :secid
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_hello
   ## ARGS, :secid
   # AC secid 
   ## Rule: ARGS rx :secid
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_hello
   ## ARGS, :secid
   # AC secid 
   ## Rule: ARGS rx :secid
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_hello
   ## ARGS, :secid
   # AC secid 
   ## Rule: ARGS rx :secid
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_hello
   ## ARGS, :secid
   # AC secid 
   ## Rule: ARGS rx :secid
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_mgm/help.mgm.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mosConfig_absolute_path
   # AC mosConfig_absolute_path 
   ## Rule: ARGS rx :mosConfig_absolute_path
   if(req.url ~ "(?i:mosConfig_absolute_path=\s*(ftps?|https?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_jmsfileseller
   ## ARGS, :view
   # AC view 
   ## Rule: ARGS contains :view
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_people
   ## ARGS, :controller
   # AC controller 
   ## Rule: ARGS contains :controller
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_jfeedback
   ## ARGS, :controller
   # AC controller 
   ## Rule: ARGS rx :controller
   if(req.url ~ "(?i:\\x2e\\x2e\\x2f)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_community
   ## ARGS, :userid
   # AC userid 
   ## Rule: ARGS rx :userid
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_community
   ## ARGS, :userid
   # AC userid 
   ## Rule: ARGS rx :userid
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_community
   ## ARGS, :userid
   # AC userid 
   ## Rule: ARGS rx :userid
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_community
   ## ARGS, :userid
   # AC userid 
   ## Rule: ARGS rx :userid
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_community
   ## ARGS, :userid
   # AC userid 
   ## Rule: ARGS rx :userid
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
}

