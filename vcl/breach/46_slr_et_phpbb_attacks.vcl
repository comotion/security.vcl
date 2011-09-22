sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pmFromFile  modsecurity_46_slr_et_phpbb.data
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /portal_block.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :phpbb_root_path
   # AC phpbb_root_path 
   ## Rule: ARGS rx :phpbb_root_path
   if(req.url ~ "(?i:phpbb_root_path=\s*(ftps?|https?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /acp_lcxbbportal.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :phpbb_root_path
   # AC phpbb_root_path 
   ## Rule: ARGS rx :phpbb_root_path
   if(req.url ~ "(?i:phpbb_root_path=\s*(ftps?|https?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/global.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :pfad
   # AC pfad 
   ## Rule: ARGS rx :pfad
   if(req.url ~ "(?i:(\.\.\/){1,})"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  .php
   ## ARGS, :phpbb_root_path
   # AC phpbb_root_path 
   ## Rule: ARGS rx :phpbb_root_path
   if(req.url ~ "(?i:phpbb_root_path=(ftps?|https?|php))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_acronyms.php
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_acronyms.php
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_acronyms.php
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_acronyms.php
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_acronyms.php
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_acronyms.php
   ## ARGS, :id
   # AC id 
   ## Rule: ARGS rx :id
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin_hacks_list.php
   ## ARGS, :hack_id
   # AC hack_id 
   ## Rule: ARGS rx :hack_id
   if(req.url ~ "(?i:.+SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin_hacks_list.php
   ## ARGS, :hack_id
   # AC hack_id 
   ## Rule: ARGS rx :hack_id
   if(req.url ~ "(?i:.+UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin_hacks_list.php
   ## ARGS, :hack_id
   # AC hack_id 
   ## Rule: ARGS rx :hack_id
   if(req.url ~ "(?i:.+INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin_hacks_list.php
   ## ARGS, :hack_id
   # AC hack_id 
   ## Rule: ARGS rx :hack_id
   if(req.url ~ "(?i:.+DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin_hacks_list.php
   ## ARGS, :hack_id
   # AC hack_id 
   ## Rule: ARGS rx :hack_id
   if(req.url ~ "(?i:.+ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin_hacks_list.php
   ## ARGS, :hack_id
   # AC hack_id 
   ## Rule: ARGS rx :hack_id
   if(req.url ~ "(?i:.+UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :c
   # AC c 
   ## Rule: ARGS rx :c
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :c
   # AC c 
   ## Rule: ARGS rx :c
   if(req.url ~ "(?i:UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :c
   # AC c 
   ## Rule: ARGS rx :c
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :c
   # AC c 
   ## Rule: ARGS rx :c
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :c
   # AC c 
   ## Rule: ARGS rx :c
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## ARGS, :c
   # AC c 
   ## Rule: ARGS rx :c
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_words.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :ModName
   # AC ModName 
   ## Rule: ARGS contains :ModName
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_groups_reapir.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :ModName
   # AC ModName 
   ## Rule: ARGS contains :ModName
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_smilies.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :ModName
   # AC ModName 
   ## Rule: ARGS contains :ModName
   if(req.url ~ "../"){
      call sec_default_handler;
   }
}

