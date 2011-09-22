sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pmFromFile  modsecurity_46_slr_et_lfi.data
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /container.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :theme_directory
   # AC theme_directory 
   ## Rule: ARGS contains :theme_directory
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /header.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :theme_directory
   # AC theme_directory 
   ## Rule: ARGS contains :theme_directory
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /latestposts.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :forumspath
   # AC forumspath 
   ## Rule: ARGS contains :forumspath
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /main.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mj_config
   # AC mj_config 
   ## Rule: ARGS rx :mj_config
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /block_center_down.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :row_mysql_blocks_center_down
   # AC row_mysql_blocks_center_down 
   ## Rule: ARGS rx :row_mysql_blocks_center_down
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /block_center_top.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :row_mysql_blocks_center_top
   # AC row_mysql_blocks_center_top 
   ## Rule: ARGS rx :row_mysql_blocks_center_top
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /block_left.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :row_mysql_blocks_left
   # AC row_mysql_blocks_left 
   ## Rule: ARGS rx :row_mysql_blocks_left
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /block_right.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :row_mysql_blocks_right
   # AC row_mysql_blocks_right 
   ## Rule: ARGS rx :row_mysql_blocks_right
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /window_down.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :row_mysql_bloginfo
   # AC row_mysql_bloginfo 
   ## Rule: ARGS rx :row_mysql_bloginfo
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /window_top.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :row_mysql_bloginfo
   # AC row_mysql_bloginfo 
   ## Rule: ARGS rx :row_mysql_bloginfo
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /spaw_control.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :spaw_root
   # AC spaw_root 
   ## Rule: ARGS contains :spaw_root
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /portfolio/css.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :theme
   # AC theme 
   ## Rule: ARGS contains :theme
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dm-albums/template/album.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :SECURITY_FILE
   # AC SECURITY_FILE 
   ## Rule: ARGS contains :SECURITY_FILE
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /urheber.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :name
   # AC name 
   ## Rule: ARGS contains :name
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /doku.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :config_cascade
   # AC config_cascade 
   ## Rule: ARGS rx :config_cascade
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /show_joined.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /threadstop/threadstop.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :exbb
   # AC exbb 
   ## Rule: ARGS rx :exbb
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /acopia/manager/DiagLogListActionBody.do
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :logFile
   # AC logFile 
   ## Rule: ARGS contains :logFile
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /acopia/manager/DiagCaptureFileListActionBody.do
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :captureFile
   # AC captureFile 
   ## Rule: ARGS contains :captureFile
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /acopia/sat/ViewSatReport.do
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :fileName
   # AC fileName 
   ## Rule: ARGS contains :fileName
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /acopia/manager/DiagCaptureFileListActionBody.do
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :capture
   # AC capture 
   ## Rule: ARGS contains :capture
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /acopia/sat/ViewInventoryErrorReport.do
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :fileName
   # AC fileName 
   ## Rule: ARGS contains :fileName
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /sitemap.xml.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :dir
   # AC dir 
   ## Rule: ARGS rx :dir
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pmscript.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :with
   # AC with 
   ## Rule: ARGS contains :with
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /init.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/startmodules.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :lang_file
   # AC lang_file 
   ## Rule: ARGS contains :lang_file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /library/setup/rpc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/header.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :c_temp_path
   # AC c_temp_path 
   ## Rule: ARGS contains :c_temp_path
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_jeajaxeventcalendar&
   ## ARGS, :view
   # AC view 
   ## Rule: ARGS contains :view
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /windetail.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :adtype
   # AC adtype 
   ## Rule: ARGS contains :adtype
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /detail.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :adtype
   # AC adtype 
   ## Rule: ARGS contains :adtype
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_pro_desk
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
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
   # skipped   REQUEST_LINE contains  option=com_wgpicasa&
   ## ARGS, :controller
   # AC controller 
   ## Rule: ARGS contains :controller
   if(req.url ~ "../"){
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
   # skipped   REQUEST_LINE contains  /include/unverified.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :template
   # AC template 
   ## Rule: ARGS contains :template
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /locms/smarty.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :cwd
   # AC cwd 
   ## Rule: ARGS contains :cwd
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /snippet.reflect.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /viewsource.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :dirn
   # AC dirn 
   ## Rule: ARGS contains :dirn
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /viewsource.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :fname
   # AC fname 
   ## Rule: ARGS contains :fname
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/global.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /centre.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :padmin
   # AC padmin 
   ## Rule: ARGS contains :padmin
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /infusions/last_seen_users_panel/last_seen_users_panel.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :settings
   # AC settings 
   ## Rule: ARGS rx :settings
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forum.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :GLOBALS
   # AC GLOBALS 
   ## Rule: ARGS rx :GLOBALS
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news_show.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :newsoffice_directory
   # AC newsoffice_directory 
   ## Rule: ARGS contains :newsoffice_directory
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /config.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  newlang=kacper
   ## ARGS, :languages
   # AC languages 
   ## Rule: ARGS rx :languages
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /resource_categories_view.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :CLASSES_ROOT
   # AC CLASSES_ROOT 
   ## Rule: ARGS contains :CLASSES_ROOT
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ADM_Pagina.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :Tipo
   # AC Tipo 
   ## Rule: ARGS contains :Tipo
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/core/security/init.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :GLOBALS
   # AC GLOBALS 
   ## Rule: ARGS rx :GLOBALS
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /stage1.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :GLOBALS
   # AC GLOBALS 
   ## Rule: ARGS rx :GLOBALS
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /stage4.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :GLOBALS
   # AC GLOBALS 
   ## Rule: ARGS rx :GLOBALS
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /stage6.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :GLOBALS
   # AC GLOBALS 
   ## Rule: ARGS rx :GLOBALS
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /website.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :page
   # AC page 
   ## Rule: ARGS contains :page
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /_conf/core/common-tpl-vars.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /chat/dac.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :sendChatData
   # AC sendChatData 
   ## Rule: ARGS contains :sendChatData
   if(req.url ~ "../"){
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
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /message_class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :pfadhier
   # AC pfadhier 
   ## Rule: ARGS contains :pfadhier
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /passwiki.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /footer.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :settings
   # AC settings 
   ## Rule: ARGS rx :settings
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /header.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :settings
   # AC settings 
   ## Rule: ARGS rx :settings
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  functions_navlinks.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  profile_send.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  viewtopic_PM-link.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /server_request.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :CONFIG
   # AC CONFIG 
   ## Rule: ARGS rx :CONFIG
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /qlib/smarty.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :CONFIG
   # AC CONFIG 
   ## Rule: ARGS rx :CONFIG
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /qte_web.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :qte_web_path
   # AC qte_web_path 
   ## Rule: ARGS contains :qte_web_path
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /bin/qte_init.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :qte_root
   # AC qte_root 
   ## Rule: ARGS contains :qte_root
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /download.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  main.php?action=download
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /login.tpl.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :TplSuffix
   # AC TplSuffix 
   ## Rule: ARGS contains :TplSuffix
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vars.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :_SESSION
   # AC _SESSION 
   ## Rule: ARGS rx :_SESSION
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pcltar.lib.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :g_pcltar_lib_dir
   # AC g_pcltar_lib_dir 
   ## Rule: ARGS contains :g_pcltar_lib_dir
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /preview.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :synTarget
   # AC synTarget 
   ## Rule: ARGS contains :synTarget
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /body_default.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :shop_this_skin_path
   # AC shop_this_skin_path 
   ## Rule: ARGS contains :shop_this_skin_path
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /export.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :export_to
   # AC export_to 
   ## Rule: ARGS contains :export_to
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /examples/tbs_us_examples_0view.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :script
   # AC script 
   ## Rule: ARGS contains :script
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /config.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :inc_dir
   # AC inc_dir 
   ## Rule: ARGS contains :inc_dir
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cms_detect.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :include
   # AC include 
   ## Rule: ARGS contains :include
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/timesheet.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :config
   # AC config 
   ## Rule: ARGS rx :config
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /debugger/debug_php.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :_GET
   # AC _GET 
   ## Rule: ARGS rx :_GET
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cron.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :include_path
   # AC include_path 
   ## Rule: ARGS contains :include_path
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ST_browsers.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :include_path
   # AC include_path 
   ## Rule: ARGS contains :include_path
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ST_countries.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :include_path
   # AC include_path 
   ## Rule: ARGS contains :include_path
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ST_platforms.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :include_path
   # AC include_path 
   ## Rule: ARGS contains :include_path
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /books/getConfig.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING contains :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY contains  book_id=
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:(\.\.\/){1,})
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/function_core.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :web_root
   # AC web_root 
   ## Rule: ARGS contains :web_root
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /templates/layout_lyrics.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :web_root
   # AC web_root 
   ## Rule: ARGS contains :web_root
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mini.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :help_file
   # AC help_file 
   ## Rule: ARGS contains :help_file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /update_trailer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :context
   # AC context 
   ## Rule: ARGS rx :context
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cuenta/cuerpo.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :base_archivo
   # AC base_archivo 
   ## Rule: ARGS contains :base_archivo
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /locales.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :srclang
   # AC srclang 
   ## Rule: ARGS contains :srclang
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /artmedic_print.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :date
   # AC date 
   ## Rule: ARGS contains :date
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /arch.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :arch
   # AC arch 
   ## Rule: ARGS contains :arch
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /_functions.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :GLOBALS
   # AC GLOBALS 
   ## Rule: ARGS rx :GLOBALS
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /123flashchat.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :e107path
   # AC e107path 
   ## Rule: ARGS contains :e107path
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index_inc.php
   ## ARGS, :inc_ordner
   # AC inc_ordner 
   ## Rule: ARGS contains :inc_ordner
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/3rdparty/adminpart/add3rdparty.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/polling/adminpart/addpolling.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/contact/adminpart/addcontact.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/brandnews/adminpart/addbrandnews.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/newsletter/adminpart/addnewsletter.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/game/adminpart/addgame.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/tour/adminpart/addtour.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/articles/adminpart/addarticles.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/product/adminpart/addproduct.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/plain/adminpart/addplain.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/comments.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :templates_dir
   # AC templates_dir 
   ## Rule: ARGS contains :templates_dir
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/comments.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :template
   # AC template 
   ## Rule: ARGS contains :template
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /addedit-render.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugin/gateway/gnokii/init.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :apps_path
   # AC apps_path 
   ## Rule: ARGS rx :apps_path
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugin/themes/default/init.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :apps_path
   # AC apps_path 
   ## Rule: ARGS rx :apps_path
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/function.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :apps_path
   # AC apps_path 
   ## Rule: ARGS rx :apps_path
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /_footer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :skin_path
   # AC skin_path 
   ## Rule: ARGS contains :skin_path
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /templater.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :config
   # AC config 
   ## Rule: ARGS rx :config
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plog-includes/lib/phpthumb/phpThumb.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :src
   # AC src 
   ## Rule: ARGS contains :src
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plog-includes/lib/phpthumb/phpThumb.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :w
   # AC w 
   ## Rule: ARGS contains :w
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plog-includes/lib/phpthumb/phpThumb.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :h
   # AC h 
   ## Rule: ARGS contains :h
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /content/dynpage_load.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :file
   # AC file 
   ## Rule: ARGS contains :file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /oldnews_reader.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :lang
   # AC lang 
   ## Rule: ARGS contains :lang
   if(req.url ~ "../"){
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
   # skipped   REQUEST_LINE contains  /maincore.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :folder_level
   # AC folder_level 
   ## Rule: ARGS contains :folder_level
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /section.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :Module
   # AC Module 
   ## Rule: ARGS contains :Module
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /classes/flash_mp3_player/extras/external_feeds/getfeed.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :file
   # AC file 
   ## Rule: ARGS contains :file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /classes/flash_mp3_player.23/extras/external_feeds/getfeed.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :file
   # AC file 
   ## Rule: ARGS contains :file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /baconmap/admin/updatelist.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :filepath
   # AC filepath 
   ## Rule: ARGS contains :filepath
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  uniqcode=KPI
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  menu_no_top=performance
   ## ARGS, :uri
   # AC uri 
   ## Rule: ARGS contains :uri
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news/search.php3
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :owa_action
   # AC owa_action 
   ## Rule: ARGS contains :owa_action
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :owa_do
   # AC owa_do 
   ## Rule: ARGS contains :owa_do
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/loadplugin.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :load
   # AC load 
   ## Rule: ARGS contains :load
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /classes/BxDolGzip.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :file
   # AC file 
   ## Rule: ARGS contains :file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/thumbnailformpost.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :adminlangfile
   # AC adminlangfile 
   ## Rule: ARGS contains :adminlangfile
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /module.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  module=osTicket
   ## ARGS, :file
   # AC file 
   ## Rule: ARGS contains :file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/templateie/lib/templateie_install.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :skin_file
   # AC skin_file 
   ## Rule: ARGS contains :skin_file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/initsystem.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :loader_file
   # AC loader_file 
   ## Rule: ARGS contains :loader_file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /api/download_launch.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :filename
   # AC filename 
   ## Rule: ARGS contains :filename
   if(req.url ~ "../"){
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
   # skipped   REQUEST_LINE contains  /download.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  filesec=sitemap
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  filetype=text
   ## ARGS, :file
   # AC file 
   ## Rule: ARGS contains :file
   if(req.url ~ "..//"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/esqueletos/skel_null.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :ABTPV_BLOQUE_CENTRAL
   # AC ABTPV_BLOQUE_CENTRAL 
   ## Rule: ARGS contains :ABTPV_BLOQUE_CENTRAL
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/login.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :default_login_language
   # AC default_login_language 
   ## Rule: ARGS contains :default_login_language
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/upgrade_unattended.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :db_type
   # AC db_type 
   ## Rule: ARGS rx :db_type
   if(req.url ~ "(?i:\.\.\\x2f)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  app=urchin.cgi
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  action=prop
   ## ARGS, :gfid
   # AC gfid 
   ## Rule: ARGS contains :gfid
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/maticmarket/deco/blanc/haut.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :modulename
   # AC modulename 
   ## Rule: ARGS contains :modulename
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/maticmarket/deco/blanc/bas.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :modulename
   # AC modulename 
   ## Rule: ARGS contains :modulename
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/maticmarket/bleu/blanc/haut.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :modulename
   # AC modulename 
   ## Rule: ARGS contains :modulename
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/maticmarket/bleu/blanc/bas.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :modulename
   # AC modulename 
   ## Rule: ARGS contains :modulename
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/maticmarket/bleu/default/haut.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :modulename
   # AC modulename 
   ## Rule: ARGS contains :modulename
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/maticmarket/bleu/default/bas.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :modulename
   # AC modulename 
   ## Rule: ARGS contains :modulename
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/maticmarket/bleu/gold/haut.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :modulename
   # AC modulename 
   ## Rule: ARGS contains :modulename
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/maticmarket/bleu/gold/bas.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :modulename
   # AC modulename 
   ## Rule: ARGS contains :modulename
   if(req.url ~ "../"){
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
   # skipped   REQUEST_LINE contains  /tiki-jsplugin.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :language
   # AC language 
   ## Rule: ARGS contains :language
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/profile/user.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :aXconf
   # AC aXconf 
   ## Rule: ARGS rx :aXconf
   if(req.url ~ "["){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /op/op.Login.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :lang
   # AC lang 
   ## Rule: ARGS contains :lang
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cultbooking.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :lang
   # AC lang 
   ## Rule: ARGS contains :lang
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /active_auctions.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :lan
   # AC lan 
   ## Rule: ARGS contains :lan
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
   # skipped   REQUEST_LINE contains  /gradebook/open_document.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :file
   # AC file 
   ## Rule: ARGS contains :file
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
   # skipped   REQUEST_LINE contains  /util/barcode.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :type
   # AC type 
   ## Rule: ARGS contains :type
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /options-runnow-iframe.php?wpabs=/
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:\\x00\&)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /options-view_log-iframe.php?wpabs=/
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:\\x00\&logfile\=\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/xcloner-backup-and-restore/cloner.cron.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :config
   # AC config 
   ## Rule: ARGS contains :config
   if(req.url ~ "../"){
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
   # skipped   REQUEST_LINE contains  /wp-content/plugins/jquery-mega-menu/skin.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :skin
   # AC skin 
   ## Rule: ARGS rx :skin
   if(req.url ~ "(?i:\.\.\\x2f)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /devtools/qooxdoo-sdk/framework/source/resource/qx/test/part/delay.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :sleep
   # AC sleep 
   ## Rule: ARGS contains :sleep
   if(req.url ~ "file="){
      # chained rule
   }
   ## ARGS, :sleep
   # AC sleep 
   ## Rule: ARGS rx :sleep
   if(req.url ~ "(?i:\.\.\\x2f)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/lcUser.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :LIBDIR
   # AC LIBDIR 
   ## Rule: ARGS contains :LIBDIR
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/wp-publication-archive/includes/openfile.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :file
   # AC file 
   ## Rule: ARGS contains :file
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/filemanager/get_file.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :language
   # AC language 
   ## Rule: ARGS contains :language
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/PluginController.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :path
   # AC path 
   ## Rule: ARGS rx :path
   if(req.url ~ "(?i:\.\.\\x2f)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mods/ckeditor/filemanager/connectors/php/connector.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :CurrentFolder
   # AC CurrentFolder 
   ## Rule: ARGS contains :CurrentFolder
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /authenticate/sessions.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :globalIncludeFilePath
   # AC globalIncludeFilePath 
   ## Rule: ARGS contains :globalIncludeFilePath
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /telecharger.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(DIR_TRAVERSAL)
   # AC re(DIR_TRAVERSAL) 
   ## Rule: TX rx :re(DIR_TRAVERSAL)
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
   # skipped   REQUEST_LINE contains  /scr/soustab.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :dsn
   # AC dsn 
   ## Rule: ARGS rx :dsn
   if(req.url ~ "["){
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
   # skipped   REQUEST_LINE contains  /wp-content/plugins/php_speedy_wp/libs/php_speedy/view/admin_container.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :page
   # AC page 
   ## Rule: ARGS contains :page
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
   # skipped   REQUEST_LINE contains  /wp-content/plugins/ungallery/source_vuln.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :pic
   # AC pic 
   ## Rule: ARGS rx :pic
   if(req.url ~ "(?i:\\x2e\\x2e\\x2f)"){
      call sec_default_handler;
   }
}

