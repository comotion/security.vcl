sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pmFromFile  modsecurity_46_slr_et_rfi.data
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ardeaCore/lib/core/ardeaInit.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /layouts/standard.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/page/pageDescriptionObject.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/layout/layoutHeaderFuncs.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/layout/layoutManager.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/layout/layoutParser.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /common/func.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:CommonAbsDir)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /common/errormsg.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:header)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /public/code/cp_html2xhtmlbasic.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:\x2Ephp\x3F.{0,300}\x3D(http\x3A|ftp\x3A|https\x3A|ftps\x3A))
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /debugger.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /container.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /header.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /rss_importer_functions.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/frontpage_right.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /install/di.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/_bot.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /LSTable.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /main.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /language/1/splash.lang.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:languagePath)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /linkadmin.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /berylium-classes.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:beryliumroot)"){
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
   # skipped   REQUEST_LINE contains  /HTMLSax3.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /safehtml.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /inc/content.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /mtdialogo.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ltdialogo.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /login.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /inc/logingecon.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pcltrace.lib.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /install.clickheat.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /heatmap/_main.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /heatmap/main.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Clickheat/Cache.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Clickheat_Heatmap.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /GlobalVariables.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /overview/main.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /header.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /footer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /dm-albums/template/album.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/dfss/lgsl/lgsl_players.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/dfss/lgsl/lgsl_settings.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /engine/api/api.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /don3_requiem.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /frontpage.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /includes/header.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/libs/internals/core.write_compiled_include.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/libs/internals/core.process_compiled_include.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/libs/plugins/function.config_load.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dp_logs.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /common.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /application/views/public/commentform.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /show_joined.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /show_joined.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /lib/FSphp.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/navigation.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/pathwirte.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /sitemap.xml.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /datumscalc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /monatsblatt.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/admin/include/config.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /modules/formmailer/formmailer.admin.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /init.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /init.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /includes/header.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /www/lib/head_auth.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gallery2/lib/adodb/adodb-error.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /core/includes/gfw_smarty.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  .php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:_CONF\[.*\]=(http|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/common.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:root_path=\s*(ftps?|https?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index_logged.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /functions.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /library/setup/rpc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /includes/footer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:c_temp_path=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/header.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:c_temp_path=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugin_admin.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/hnmain.inc.php3
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /portal_block.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /acp_lcxbbportal.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /embedforum.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /scorm/lib.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin.rssreader.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /components/com_ajaxchat/tests/ajcuser.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_ezine/class/php/d4m_ajax_pagenav.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /acomponents/com_mamboleto/mamboleto.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_mojo/wp-comments-post.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_mojo/wp-trackback.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /components/com_morfeoshow/morfeoshow.html.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /components/com_jcalpro/cal_popup.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /administrator/components/com_jwmmxtd/admin.jwmmxtd.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_universal/includes/config/config.html.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /com_ongumatimesheet20/lib/onguma.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /adm/krgourl.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/engine/content/elements/menu.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /views/print/printbar.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /locms/smarty.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /smallaxe-0.3.1/inc/linkbar.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /snippet.reflect.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /snippet.reflect.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /velid3/getid3.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /velid3/module.archive.gzip.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/Cache/Lite/Output.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/file_manager/special.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/InstantSite/inc.is_root.php?is_projectPath=http|3a|
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /classes/class.Tree.php?GLOBALS[thCMS_root]=http|3a|
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /classes/class.thcsm_user.php?is_path=http|3a|
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modul/mod.users.php?thCMS_root=http|3a|
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /membres/membreManager.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:include_path=\s*(ftps?|https?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /utdb_access.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /utgn_message.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/smarty/SmartyFU.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  system[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /export_batch.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /run_auto_suspend.cron.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /send_email_cache.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /2checkout_return.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /nettools.popup.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /news_show.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ch_readalso.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/common.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/noevents/templates/mfa_theme.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  tpls[
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
   # skipped   REQUEST_LINE contains  /fonctions_racine.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /resource_categories_view.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /skins/header.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ADM_Pagina.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /filepool.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /OpenSiteAdmin/pages/pageHeader.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:\x2Ephp\x3F.{0,300}\x3D(http\x3A|ftp\x3A|https\x3A|ftps\x3A))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /libraries/lib-remotehost.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/core/logger/init.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /newscat.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /includes/converter.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/messages.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/settings.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/language.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /layout_admin_cfg.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /layout_cfg.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /skins/phpchess/layout_t_top.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /controller/
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:(text\.ctrl\.php|common\.function\.php)\?level=\s*(ftps?|https?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /block.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /CoupleDB.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /examples/widget8.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ftp.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /libs/db.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /libs/ftp.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /_conf/core/common-tpl-vars.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /_conf/core/common-tpl-vars.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /inc/articles.inc.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /DB_adodb.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/logout.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /iframe.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user/turbulence.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /send_reminders.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:includedir=\s*(ftps?|https?|php)\:\/)
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
   # skipped   REQUEST_LINE contains  /home.php?page=http\:
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugin/HP_DEV/cms2.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mod/image/index.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mod/liens/index.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mod/liste/index.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mod/special/index.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mod/texte/index.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /blocks/headerfile.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  system[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /files/blocks/latest_files.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  system[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forums/blocks/latest_posts.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  system[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /groups/headerfile.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  system[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /filters/headerfile.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  system[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /links/blocks/links.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  system[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /menu/headerfile.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  system[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news/blocks/latest_news.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  system[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /settings/headerfile.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  system[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/users/headerfile.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  system[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:=\s*(https?|ftps?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /basicfogfactory.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/init.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/action/rss.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /psg.smarty.lib.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /resources/includes/class.Smarty.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /prepend.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING contains :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY contains  _px_config[manager_path]=
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:_px_config\x5bmanager_path\x5d=(https?|ftps?|php)\:)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/classes/pctemplate.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/includes.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:site_path=\s*(ftps?|https?|php)\:\/)
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
   # skipped   REQUEST_LINE contains  /cms/modules/form.lib.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/prodler.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  functions_navlinks.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  profile_send.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  viewtopic_PM-link.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /server_request.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /qte_web.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /display.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/top_graph_header.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /define.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /tmsp/add_tmsp.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /tmsp/edit_tmsp.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /tmsp/subscription.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /tmsp/tmsp.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/competitions/add.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/competitions/competitions.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/settings/settings.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/addons/version/pages/index.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/pages/specials.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /load_lang.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /main_prepend.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /theme/format.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /theme/format.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /theme/format.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/admin/device_admin.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /classes/excel/class.writeexcel_workbook.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /classes/excel/class.writeexcel_worksheet.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /SezHooTabsAndActions.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /slogin_lib.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /main/forum/komentar.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /login.tpl.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vars.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pcltar.lib.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /content/themes/softsaurus_default/pages/subHeader.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /content/themes/softsaurus_stretched/pages/subHeader.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /example_clientside_javascript.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /site_conf.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:ordnertiefe)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /class.csv.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:tt_docroot)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /produkte_nach_serie.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:tt_docroot)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /functionen/ref_kd_rubrik.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:tt_docroot)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /hg_referenz_jobgalerie.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:tt_docroot)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /surfer_anmeldung_NWL.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:tt_docroot)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /produkte_nach_serie_alle.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:tt_docroot)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /surfer_aendern.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:tt_docroot)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ref_kd_rubrik.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:tt_docroot)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /module/referenz.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:tt_docroot)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /standard/1/lay.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:tt_docroot)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /standard/3/lay.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:tt_docroot)"){
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
   # skipped   REQUEST_LINE contains  /templates/default/tpl_message.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /config.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /dosearch.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/payment/payflow_pro.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /global.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /libsecure.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/timesheet.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /watermark.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /get_header.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:vwar_root=\s*(ftps?|https?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /functions_install.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:vwar_root=\s*(ftps?|https?|php)\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /editor/edit_htmlarea.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /includes/ajax_listado.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin.googlebase.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archive.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /base/Archive.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /comments.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /base/Comments.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /base/News.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /base/SendFriend.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/global.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  crea.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /cron.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /ST_browsers.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /ST_countries.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /ST_platforms.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Framework/EmailTemplates.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Customers/PDPEmailReplaceConstants.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Admin/ResellersManager.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /html.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /html2.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/header.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /handlers/page/show.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /js/wptable-button.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wordtube-button.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /js/wptable-tinymce.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/function_core.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /activities/workflow-activities.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /header.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /update_trailer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /last_gallery.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/common.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /class_yapbbcooker.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /view_messages.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /view_blog_comments.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /view_blog_archives.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /add_comments.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /downloads.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /emailsender.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /left_menu.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /handle/proxy.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/header.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/include.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/workspace.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib.module.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:mod_root=\s*(https?|ftps?|php))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_if_nexus&
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /_functions.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /libraries/database.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:\x2Ephp\x3F.{0,300}\x3D(http\x3A|ftp\x3A|https\x3A|ftps\x3A))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index_inc.php
   ## ARGS, :inc_ordner
   # AC inc_ordner 
   ## Rule: ARGS contains :inc_ordner
   if(req.url ~ "../"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index_inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/3rdparty/adminpart/add3rdparty.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/polling/adminpart/addpolling.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/contact/adminpart/addcontact.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/brandnews/adminpart/addbrandnews.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/newsletter/adminpart/addnewsletter.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/game/adminpart/addgame.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/tour/adminpart/addtour.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/articles/adminpart/addarticles.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/product/adminpart/addproduct.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/plain/adminpart/addplain.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /e-pay/src/a_affil.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /toolbar.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /libs/lom.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lom_update.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /scripts/check-lom.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /scripts/weigh_keywords.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /logout.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /help.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /login.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/lom.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /tools/filemanager/skins/mobile/admin1.template.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /test/pages/contact.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /system/pageTemplate.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /system/utilities.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Thumbnail.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /faq.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /checkout.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /libsecure.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gunaysoft.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gunaysoft.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gunaysoft.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /body_comm.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /addedit-render.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /assets/plugins/mp3_id/mp3_id.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /pda_projects.php?offset=http\:
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
   # skipped   REQUEST_LINE contains  /footer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /startup.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /header.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING contains :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY contains  /base_include.inc.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING contains :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY contains  BASE_path=
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:BASE_path=(https?|ftp))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /base_qry_common.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /base_stat_common.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/spamx/BlackList.Examine.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/spamx/DeleteComment.Action.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/spamx/EditHeader.Admin.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/spamx/EditIP.Admin.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/spamx/EditIPofURL.Admin.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/spamx/IPofUrl.Examine.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/spamx/Import.Admin.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/spamx/LogView.Admin.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/spamx/MTBlackList.Examine.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/spamx/MailAdmin.Action.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/spamx/MassDelTrackback.Admin.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/spamx/MassDelete.Admin.class.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/links/functions.inc
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/polls/functions.inc
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  plugins/staticpages/functions.inc
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  create_file.php
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dompdf.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /class.phpmailer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /familynews.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /settings.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /com_del.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/file_manager/special.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /global.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /include/admin.lib.inc.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_a6mambohelpdesk/admin.a6mambohelpdesk.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /com_rwcards/rwcards.advancedate.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /real_estate/index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_jomestate
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news/search.php3
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /bazar/picturelib.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mw_plugin.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /administrator/components/com_joomlaxplorer/admin.joomlaxplorer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /components/com_banners/banners.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /awcm/includes/window_top.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /awcm/control/common.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /awcm/header.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Base/example_1.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/templateie/lib/templateie_install.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /components/com_smf/smf.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /viewver.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /gbookmx/gbook.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /pingsvr.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /blocks/file/controller.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /action.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /nucleus/media.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /nucleus/xmlrpc/server.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /nucleus/libs/PLUGINADMIN.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /customer_ftp.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /lib/addressbook.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /mod/vm/controller/AccessController.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mod/vm/model/dao.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /obj/action.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /obj/architecte.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /obj/avis.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /obj/bible.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /obj/blocnote.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /includes/Cache/Lite/Output.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ardeaCore/lib/core/mvc/ardeaMVC.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ardeaCore/lib/core/ardeaBlog.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ardeaCore/lib/core/mvc/ardeaMVC.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ardeaCore/lib/core/ardeaBlog.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  admin.ponygallery.html.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_doqment
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_smartformer/smartformer.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /modules/mod_virtuemart_latestprod/mod_virtuemart_latestprod.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/mod_virtuemart_featureprod/mod_virtuemart_featureprod.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /include/classes/file.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /extensions/saurus4/captcha_image.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /admin/admin_news_bot.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /components/com_mgm/help.mgm.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /e107_handlers/secure_img_handler.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /e107_handlers/secure_img_handler.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /e107_handlers/secure_img_handler.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /e107_plugins/trackback/trackbackClass.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /e107_plugins/trackback/trackbackClass.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  droit.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /collectivite.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /utilisateur.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /courrier.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /profil.class.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pear.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pear.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   # skipped   REQUEST_LINE contains  /editors/FCKeditor/editor_registry.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /editors/tinymce/editor_registry.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /editors/dhtmltextarea/editor_registry.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/php_speedy_wp/libs/php_speedy/view/admin_container.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
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
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /sublink.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/guestbook/blocks/control.block.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(RFI)
   # AC re(RFI) 
   ## Rule: TX rx :re(RFI)
}

