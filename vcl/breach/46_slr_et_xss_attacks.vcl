sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pmFromFile  modsecurity_46_slr_et_xss.data
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search/list/action_search/index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  form[mods][
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search/list/action_search/index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  form[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/dl/download.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news/list/index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /action_create/index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /action_create/index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /action_create/index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /newsletter/create/index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /shared/code/cp_authorization.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /shared/config/cp_config.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Forms/login
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /picture.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /host-manager/html/add
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Aris/wflogin.jsp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /awstats/awstats.pl
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.5.html
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cand_login.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  _invoice.asp
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  script>
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:(alert|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /scripts/prodList.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /scripts/prodList.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /webline/html/admin/wcs/LoginPage.jhtml
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /config/edituser.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /console.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forcesd.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forcerestart.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /siteminderagent/forms/smpwservices.fcc
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:(script|img|src|alert|onmouse|onkey|onload|ondragdrop|onblur|onfocus|onclick))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /verify/asp/n6plugindestructor.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /footer.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /loan.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /listmovies.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /room/info_book.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /room/week.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /main/inc/lib/fckeditor/editor/plugins/ImageManager/editor.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /listmembers.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /stats.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /WorkArea/reterror.aspx
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /workarea/medialist.aspx
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/firestats/php/window-add-excluded-ip.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/firestats/php/window-add-excluded-url.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/firestats/php/window-new-edit-site.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /showown.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gnatsweb.pl
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /hlstats.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /hlstats.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /hlstats.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /hlstats.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /smhui/getuiinfo
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  JS
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /patch/single_winner1.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:bid_id)"){
      # chained rule
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  <script>
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  </script>
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ReqWebHelp/advanced/workingSet.jsp
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  operation=add
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:(script|img|src|onmouse|onkey|onload|ondragdrop|onblur|onfocus|onclick))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ReqWebHelp/basic/searchView.jsp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ReqWebHelp/basic/searchView.jsp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ReqWebHelp/basic/searchView.jsp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ReqWebHelp/basic/searchView.jsp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /help/readme.nsf/Header
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /WebEditor/Authentication/LoginPage.aspx
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /private/cindefn.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /private/power_management_policy_options.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /private/pm_temp.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /private/power_module.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /private/blade_leds.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /private/ipmi_bladestatus.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /module_bbcodeloader.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /module_div.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /module_email.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /module_image.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /module_link.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /jscripts/folder_rte_files/module_table.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /calendar.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /profiles/html/simpleSearch.do
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /sendmail.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /order_form.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /configure_plugin.tpl.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/phpinfo.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  1[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/phpinfo.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  a[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/queuedMessage.do
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  method=getQueueMessages&
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/queuedMessage.do
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  method=getQueueMessages&
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /de/pda/dev_logon.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /usrmgr/registerAccount.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /de/create_account.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dhost/modules
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /skins/header.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /faces/jsf/tips.jsp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /settings.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cat.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Default.aspx
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user/User_ChkLogin.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /rating/rate.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:id)"){
      # chained rule
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  <script>
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  </script>
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /rating/postcomments.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:id)"){
      # chained rule
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  <script>
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  </script>
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /awards.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /login.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /register.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /weapons.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  cp/ps/Main/login/Login
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/themes/redoable/searchloop.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/themes/redoable/header.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /contact/index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /html/studentmain.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /sendcard.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cgi/surgeftpmgr.cgi
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  cmd=class&
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /implicit-objects.jsp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /appdev/sample/web/hello.jsp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /reportItem.do
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /browseCat.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /browseSubCat.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /openTutorial.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /topFrame.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/editListing.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /shopcontent.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/viewHeaders.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/viewHeaders.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/viewHeaders.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/viewHeaders.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/actions/msgAnalyse.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/actions/msgAnalyse.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/actions/msgAnalyse.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/actions/msgAnalyse.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/actions/msgAnalyse.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/actions/msgAnalyse.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/actions/msgForwardToRiskFilter.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/actions/msgForwardToRiskFilter.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/actions/msgForwardToRiskFilter.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/msgList/viewmsg/actions/msgForwardToRiskFilter.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /usersettings.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include/sessionRegister.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /sidebar.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/nextgen-gallery/xml/media-rss.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/wp-cumulus/tagcloud.swf
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  mode=tags
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ReadMsg.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3C |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SCRIPT
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  | 3E |
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /frontend/x3/files/fileop.html
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /all_photos.html
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /users/payment.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:order_id)"){
      # chained rule
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  <script>
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  </script>
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /sqledit.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /tiki-featured_link.php
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:type)"){
      # chained rule
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /iframe>
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /printcal.pl
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /catalogo.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /addressbook.cgi
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  show=search
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/csstidy/css_optimiser.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cacti/utilities.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dailyview.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /html/11-login.asp
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news/search.php3
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/vodpod-video-gallery/vodpod_gallery_thumbs.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/feedlist/handler_image.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /fetchmailprefs.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  actionID=fetchmail_prefs_save
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  fm_driver=imap
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Forms/home_1
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /en/front_content.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/upgrade_unattended.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/wp-safe-search/wp-safe-search-jx.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/accept-signups/accept-signups_submit.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /bizdir/bizdir.cgi
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /English_manual_version_2.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /zimplit.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  action=load
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /tagcloud.swf
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  mode=tags
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /tagcloud-ru.swf
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  mode=tags
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cultbooking.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /SearchCenter/Pages/AllResults.aspx
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/audio/getid3/demos/demo.browse.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/spikephpcoverage/src/phpcoverage.remote.top.inc.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:PHPCOVERAGE_HOME\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /js/modalbox/tests/functional/_ajax_method_get.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /explanation.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:explain\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/boonex/custom_rss/post_mod_crss.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:relocate\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /core/themes.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  stconf.nsf/WebMessage
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  OpenView
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  stconf.nsf
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:stconf.nsf.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D).+unescape)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/iwant-one-ihave-one/updateAJAX.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /shipping/methods/fedex_v7/label_mgr/js_include.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /shipping/pages/popup_shipping/js_include.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/xcloner-backup-and-restore/index2.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=dologin
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/xcloner-backup-and-restore/index2.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_xcloner-backupandrestore/index2.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/zotpress/zotpress.image.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/rp-menu.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /header.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/1-flash-gallery/folder.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /_wk/Xinha/plugins/SpellChecker/spell-check-savedicts.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /_wk/Xinha/plugins/SpellChecker/spell-check-savedicts.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /header.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/rp-menu.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/lazyest-gallery/lazyest-popup.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /basicstats.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/lazyest-gallery/lazyest-popup.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /basicstats.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /openBrowser.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /we/include/we_modules/shop/edit_shop_editorFrameset.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /we/include/we_modules/messaging/messaging_show_folder_content.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /we/include/weTracking/econda/weEcondaImplement.inc.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /devtools/qooxdoo-sdk/framework/source/resource/qx/test/jsonp_primitive.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /templates/recruitment/jobVacancy.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mods/ckeditor/filemanager/connectors/php/upload.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/photosmash-galleries/index.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vtigerservice.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/socialgrid/static/js/inline-admin.js.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/jscalendar/test.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/inline-gallery/browser/browser.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /addons/kcfinder/browse.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /templates/admin_default/confirm.tpl.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /xperience.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/security/useredit.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/security/roleedit.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/security/userlist!show.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/deleteArtifact!doDelete.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/admin/addLegacyArtifactPath!commit.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/admin/deleteNetworkProxy!confirm.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/admin/addRepository.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/admin/confirmDeleteRepository.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/admin/editAppearance.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/admin/addLegacyArtifactPath.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/admin/addNetworkProxy.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/admin/networkProxies.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/admin/legacyArtifactPath.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archiva/admin/configureAppearance.action
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /sessions
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /sessions
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:path)"){
      # chained rule
   }
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING contains :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY contains  orderby=
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:orderby\x3D.+(alert|script|onmouse|onkey|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vBTube.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vBTube.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /annonce.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/php_speedy_wp/libs/php_speedy/view/admin_container.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  page=eshop-templates.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  page=eshop-orders.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  page=eshop-orders.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /snarf_ajax.php
   ## &TX, :re(XSS)
   # AC re(XSS) 
   ## Rule: TX rx :re(XSS)
}

