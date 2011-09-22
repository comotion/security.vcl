sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pmFromFile  modsecurity_46_slr_et_sqli.data
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/campsiteattachment/attachments.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vehiclelistings.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vehiclelistings.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vehiclelistings.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vehiclelistings.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vehiclelistings.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vehiclelistings.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vehiclelistings.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vehiclelistings.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vehiclelistings.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/rating.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/rating.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/edit.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /templates/modif.html
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /shared/code/cp_authorization.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /public/code/cp_downloads.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /subcat.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /view_profile.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /postingdetails.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /topic_title.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forum2.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /kullanicilistesi.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /aramayap.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /giris.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mesajkutum.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /kullanicilistesi.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forum.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /artreplydelete.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news_detail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /detail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /listpics.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gallery.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /product.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?i:userid)"){
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleInfo = "SLR: ET WEB_SPECIFIC_APPS Possible Achievo userid= Variable UPDATE SET SQL Injection Attempt";
      set req.http.X-Sec-RuleName = "web-application-attack";
      set req.http.X-Sec-RuleId = "2010135-2";
      # chained rule
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dispatch.php?atknodetype=reports.weekreport
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING contains :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY contains  UPDATE
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING contains :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY contains  SET
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /activenews_view.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /activeNews_categories.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /activeNews_comments.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /activenews_search.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /HaberDetay.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /rss.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /section/default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /email.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /voirannonce.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_membre/fiche_membre.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_annonce/okvalannonce.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_annonce/changeannonce.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /giris.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /giris.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /system/index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /publications_list.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /publication_view.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /edit.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /bt-trackback.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/config.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /account_change.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /account_change.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /torrents.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /torrents.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /bry.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /HABERLER.ASP
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /HABERLER.ASP
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ASPKAT.ASP
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ASPKAT.ASP
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /down.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /stylesheet.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  graph_view.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  tree.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /calendar_detail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_mail_adressee.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /openPolicy.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /prodList.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /displayCalendar.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /view_gallery.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /view_gallery.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /download_image.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gallery.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gallery.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /view_recent.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /inc_listnews.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /comersus_optReviewReadExec.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /haber.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /thumbnails.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /albmgr.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /usermgr.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /db_ecard.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /error.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cats.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cart.inc.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plus/feedback_js.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /set_preferences.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /send_password_preferences.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /SecureLoginManager/list.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /login.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /content.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /members.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /applications/SecureLoginManager/inc_secureloginmanager.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /page.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /visu_user.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /info_book.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /docebo/docebo
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  UPDATE
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /docebo/docebo
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  UPDATE
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  SET
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /tracking/courseLog.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /main/auth/my_progress.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /bus_details.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /goster.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /detail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /detail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /detail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /detail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /home.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /listmembers.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/memberlist.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/memberlist.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /add_comment.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /add_comment.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /list_comments.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /sptrees/default.aspx
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mod_banners.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /newsdetail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Types.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /actualpic.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ad.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ad.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ad.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dircat.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dirSub.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dircat.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dirSub.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /types.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /homeDetail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /result.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /compareHomes.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /compareHomes.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /compareHomes.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /result.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /result.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /result.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /show_owned.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /show_joined.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administration/administre2.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /productdetail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /style.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /products.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /faq.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /articles.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vdateUsr.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /boxx/ShowAppendix.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /question.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /detail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /filelist.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /filelist.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /showfile.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /game.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /info_user.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /listmain.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /windows.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /down_indir.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.cfm
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forum/include/error/autherror.cfm
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.cfm
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.cfm
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.cfm
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /low.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /down_indir.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /kategori.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /inc/common.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /glossaire-p-f.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /userdetail.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /jump.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /detail.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /jump.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/comments/json.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=comment
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /print.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /addrating.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /addrating.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /giris_yap.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /haberoku.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /oku.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dispimage.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /rating.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /meal_rest.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /res_details.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /classes/class_session.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forum/modules/gallery/post.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lib/entry_reply_entry.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ixm_ixpnews.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /auth.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /auth.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /auth.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /G_Display.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /Search/DisplayResults.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /login.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admincp/attachment.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admincp/attachment.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /inlinemod.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /main_page.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /open_tree.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /outputs.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/cms/opentree.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  id[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /openlink.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /viewlinks.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /models/category.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /letterman.class.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
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
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
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
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/mod_mainmenu/menu.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/content.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/weblinks.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/contacts.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/categories.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/search/sections.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /database/table/user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
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
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
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
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_gameserver
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=gamepanel
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_cbresumebuilder
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=group_members
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  index.php?option=com_photoblog&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  index.php?option=com_jshop&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_joaktree&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &view=joaktree
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_jphoto&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=category&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_foobla_suggestions&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_musicgallery&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &task=itempage
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_yelp&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_avosbillets&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_job&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php?option=com_perchagallery&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_hdflvplayer&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /administrator/components/com_sqlreport/ajax/print.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_quicknews&
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  &task=view_item
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_rsgallery2&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_blog&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_gbufacebook&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search_listing.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search_listing.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /detail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forum.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /down.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /i-search.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /journal.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /polls.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /guestbook.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /inout/status.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /inout/update.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forgotpass.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forgotpass.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /inout/update.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /inout/status.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /details.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /navigacija.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /prikazInformacije.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /linkslist.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /categoria.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /main.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ProductDetails.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /comments.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /register.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /email.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /detail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /listings.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /listings.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /listings.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /moscomment.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /com_comment.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/mambo.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /WorkOrder.do
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news_page.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /product_review.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  x[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /product_review.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /product_review.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /product_review.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /product_review.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /product_review.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /order-track.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lire-avis.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /uye_giris_islem.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /uye_giris_islem.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /duyuru.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /item_show.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /item_list.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /item_list.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forum.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin_check_user.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mystats.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /diary.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /result.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /users.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/ipsearch/ipsearch.admin.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pfs/pfs.edit.inc.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /system/core/users/users.register.inc.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /polls.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /users.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ViewCat.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /News/page.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pages/addcomment2.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pages/addcomment2.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pages/addcomment2.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pages/addcomment2.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /shared/code/cp_functions_downloads.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /view.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dagent/downloadreport.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dagent/downloadreport.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /nukesentinel.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /nukesentinel.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/nsbypass.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /viewthread.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ossim/repository/repository_attachment.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /etkinlikbak.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /OmegaMw7.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user_pages/page.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /jtfwcpnt.jsp
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /login/register.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /includes/a_register.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /php-stats.recphp.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/admin_acronyms.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin_hacks_list.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/admin/modules/gallery.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /include.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /comment.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mainfile.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/modules/modules.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/Advertising/admin/index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/Advertising/admin/index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/Advertising/admin/index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/Advertising/admin/index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/Advertising/admin/index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /blocks/block-Old_Articles.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/News/index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /links.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  op=viewslink&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /friend.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  op=FriendSend&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /code/guestadd.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /code/guestadd.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /code/guestadd.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /code/guestadd.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /item.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /post.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /archives.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /viewimage.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /philboard_forum.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pollmentorres.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /simplog/archive.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /simplog/archive.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /simplog/index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /lire-avis.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /qte_result.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /viewad.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /login.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /login.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user_confirm.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user_confirm.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /recipe.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /list.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /edit_day.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /inc/class_users.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /listfull.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /printmain.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /listmain.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /searchoption.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /searchmain.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /searchkey.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /searchmain.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /searchoption.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /searchkey.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /searchoption.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /searchoption.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /searchoption.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /searchoption.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /roleManager.jsp
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  type=query&
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /class/debug/debug_show.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /devami.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cgi-bin/reorder2.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /add2.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /add2.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /add2.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /add2.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /add2.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /html/studentmain.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /utilities/usermessages.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  serendipity[multiCat][
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /orange.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /print.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /logon_user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /update_profile.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /page.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dl.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dl.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dl.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dl.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pop_profile.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /list.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /game_listing.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:.+UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /rss/show_webfeed.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /directory.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /sendarticle.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:.+UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /printarticle.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:.+UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /preferences.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  board[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /save.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /h_goster.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ViewReport.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ViewBugs.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /banner.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /slideshow.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /thumbnails.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /badword.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /shopgiftregsearch.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vf_memberdetail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /repass.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /repass.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /verify.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /verify.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /virtuemart_parser.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /virtuemart_parser.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /virtuemart_parser.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /haberdetay.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cat.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /urunbak.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mailer.w2b
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /DocPay.w2b
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /coupon_detail.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /viewcat.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /comments.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /content.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /phonemessage.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /faqDsp.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /process.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /process.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dlwallpaper.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wallpaper.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /item.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /filecheck.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  id[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /directions.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /connexion.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /functions/functions_filters.asp
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forum/pop_up_member_search.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /News/page.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /eWebQuiz.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /check_vote.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /usergroups.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /pms.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  pmid[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  boardids[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /search.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  board[
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /thread.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-ajax.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-functions.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /xmlrpc.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-trackback.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-trackback.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/cpl/cplphoto.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /devami.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /classes/class.news.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /classes/class.news.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /classes/class.news.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /view.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /kernel/group.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /class/table_broken.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /print.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /show_news.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /displaypic.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /functions.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mezungiris.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mezungiris.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ogretmenkontrol.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /ogretmenkontrol.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/mp3playlist/mp3playlist.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /faqDsp.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /bb-includes/formatting-functions.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /newsletters/edition.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /SelGruFra.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /SelGruFra.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /category.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /manufacturer.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dettaglio.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dettaglio.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mod.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mod.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index1.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /default2.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.asp
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /getnewsitem.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /display_review.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /display_review.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /compare_product.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /user.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /install.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /read/index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/bms/invoices_discount_ajax.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /nickpage.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gallery.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gallery.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /print.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /news.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forums.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forums.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /forums.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /users.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wbsearch.aspx
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vBSupport.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /vBSupport.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /printview.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gallery.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gallery.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /gallery.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /xNews.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_zoomportfolio
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=portfolio
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /refund_request.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /classified_img.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admincp.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  section=smilies
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  action=edit
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /infusions/mg_user_fotoalbum_panel/mg_user_fotoalbum.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /site_info.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /filemgmt/singlefile.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cart.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  m=features
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  view=catalog
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  item_type=M
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /takefreestart.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /mod.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  mod=publisher
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  op=printarticle
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /informacion_general.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /program/moduler_banner_aabn.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /infusions/teams_structure/team.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  lvl=coll_see
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /notaevento.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /bexfront.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /hilfsmittel.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  action=read
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/iwant-one-ihave-one/updateAJAX.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /dsp_page.cfm
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/forum-server/feed.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /public/code/cp_menu_data_file.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/1-flash-gallery/massedit_album.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /products.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /imprimir.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /content/rubric/index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/classes/autocomplete.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /web/classes/autocomplete.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/pdfClasses/pdfgen.php
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules/Surveys/modules.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  name=Surveys
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /cchatbox.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /samples/with_db/loaddetails.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /country_escorts.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /model-kits.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /interna.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_hello
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /admin/code/tce_xml_user_results.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /tde_busca/processaPesquisa.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /showcats.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /minbrowse.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/flash-album-gallery/lib/hitcounter.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /annonce_detail.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /modules.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  name=Tutorials
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  t_op=showtutorial
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /index.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  option=com_community
   ## &TX, :re(SQL_INJECTION)
   # AC re(SQL_INJECTION) 
   ## Rule: TX rx :re(SQL_INJECTION)
}

