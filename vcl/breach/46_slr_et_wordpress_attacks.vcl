sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pmFromFile  modsecurity_46_slr_et_wordpress.data
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/firestats/php/window-add-excluded-ip.php
   ## ARGS, :edit
   # AC edit 
   ## Rule: ARGS rx :edit
   if(req.url ~ "(?i:edit\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/firestats/php/window-add-excluded-url.php
   ## ARGS, :edit
   # AC edit 
   ## Rule: ARGS rx :edit
   if(req.url ~ "(?i:edit\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/firestats/php/window-new-edit-site.php
   ## ARGS, :site_id
   # AC site_id 
   ## Rule: ARGS rx :site_id
   if(req.url ~ "(?i:site_id\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /rss/show_webfeed.php
   ## ARGS, :wcHeadlines
   # AC wcHeadlines 
   ## Rule: ARGS rx :wcHeadlines
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /rss/show_webfeed.php
   ## ARGS, :wcHeadlines
   # AC wcHeadlines 
   ## Rule: ARGS rx :wcHeadlines
   if(req.url ~ "(?i:UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /rss/show_webfeed.php
   ## ARGS, :wcHeadlines
   # AC wcHeadlines 
   ## Rule: ARGS rx :wcHeadlines
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /rss/show_webfeed.php
   ## ARGS, :wcHeadlines
   # AC wcHeadlines 
   ## Rule: ARGS rx :wcHeadlines
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /rss/show_webfeed.php
   ## ARGS, :wcHeadlines
   # AC wcHeadlines 
   ## Rule: ARGS rx :wcHeadlines
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /rss/show_webfeed.php
   ## ARGS, :wcHeadlines
   # AC wcHeadlines 
   ## Rule: ARGS rx :wcHeadlines
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-login.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:redirect_to=(ht|f)tps?\:\/)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /js/wptable-button.php
   ## ARGS, :wpPATH
   # AC wpPATH 
   ## Rule: ARGS rx :wpPATH
   if(req.url ~ "(?i:=\s*(https?|ftps?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wordtube-button.php
   ## ARGS, :wpPATH
   # AC wpPATH 
   ## Rule: ARGS rx :wpPATH
   if(req.url ~ "(?i:=\s*(https?|ftps?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /sidebar.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:<?(java|vb)?script>?.*<.+\/script>?)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-ajax.php
   ## ARGS, :cookie
   # AC cookie 
   ## Rule: ARGS rx :cookie
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-ajax.php
   ## ARGS, :cookie
   # AC cookie 
   ## Rule: ARGS rx :cookie
   if(req.url ~ "(?i:UNION\s+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-ajax.php
   ## ARGS, :cookie
   # AC cookie 
   ## Rule: ARGS rx :cookie
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-ajax.php
   ## ARGS, :cookie
   # AC cookie 
   ## Rule: ARGS rx :cookie
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-ajax.php
   ## ARGS, :cookie
   # AC cookie 
   ## Rule: ARGS rx :cookie
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-ajax.php
   ## ARGS, :cookie
   # AC cookie 
   ## Rule: ARGS rx :cookie
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-functions.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-functions.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION\s+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-functions.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-functions.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin-functions.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:ASCII\(.+SELECT)
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
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /xmlrpc.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION\s+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /xmlrpc.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /xmlrpc.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /xmlrpc.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:ASCII\(.+SELECT)
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
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-trackback.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION\s+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-trackback.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-trackback.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-trackback.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:ASCII\(.+SELECT)
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
   # skipped   REQUEST_BODY rx  (?i:SELECT.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-trackback.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UNION\s+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-trackback.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:INSERT.+INTO)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-trackback.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:DELETE.+FROM)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-trackback.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:ASCII\(.+SELECT)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-trackback.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:UPDATE.+SET)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :newsletter
   # AC newsletter 
   ## Rule: ARGS rx :newsletter
   if(req.url ~ "(?i:UNION\s+SELECT)"){
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
   # skipped   REQUEST_LINE contains  /js/wptable-tinymce.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :ABSPATH
   # AC ABSPATH 
   ## Rule: ARGS rx :ABSPATH
   if(req.url ~ "(?i:ABSPATH\s*=\s*(https?|ftps?|php)\:\/)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-admin/admin.php
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING contains :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY contains  page=
   ## QUERY_STRING, 
   ## Rule: QUERY_STRING rx :
   ## REQUEST_BODY, 
   # skipped   REQUEST_BODY rx  (?i:\x2Fwp\x2Dadmin\x2Fadmin\x2Ephp.+page\x3D(\x2Fcollapsing\x2Darchives\x2Foptions\x2Etxt|akismet\x2Freadme\x2Etxt|related\x2Dways\x2Dto\x2Dtake\x2Daction\x2Foptions\x2Ephp|wp\x2Dsecurity\x2Dscan\x2Fsecurityscan\x2Ephp))
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/nextgen-gallery/xml/media-rss.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :mode
   # AC mode 
   ## Rule: ARGS rx :mode
   if(req.url ~ "(?i:(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/cpl/cplphoto.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :postid
   # AC postid 
   ## Rule: ARGS rx :postid
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/cpl/cplphoto.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :postid
   # AC postid 
   ## Rule: ARGS rx :postid
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/cpl/cplphoto.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :postid
   # AC postid 
   ## Rule: ARGS rx :postid
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/cpl/cplphoto.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :postid
   # AC postid 
   ## Rule: ARGS rx :postid
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/cpl/cplphoto.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :postid
   # AC postid 
   ## Rule: ARGS rx :postid
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/wp-cumulus/tagcloud.swf
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  mode=tags
   ## ARGS, :tagcloud
   # AC tagcloud 
   ## Rule: ARGS rx :tagcloud
   if(req.url ~ "(?i:tagcloud\x3D.+(script|alert|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/vodpod-video-gallery/vodpod_gallery_thumbs.php
   ## ARGS, :gid
   # AC gid 
   ## Rule: ARGS rx :gid
   if(req.url ~ "(?i:gid\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/feedlist/handler_image.php
   ## ARGS, :i
   # AC i 
   ## Rule: ARGS rx :i
   if(req.url ~ "(?i:i\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/wp-safe-search/wp-safe-search-jx.php
   ## ARGS, :v1
   # AC v1 
   ## Rule: ARGS rx :v1
   if(req.url ~ "(?i:v1\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/accept-signups/accept-signups_submit.php
   ## ARGS, :email
   # AC email 
   ## Rule: ARGS rx :email
   if(req.url ~ "(?i:email\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/audio/getid3/demos/demo.browse.php
   ## ARGS, :showfile
   # AC showfile 
   ## Rule: ARGS rx :showfile
   if(req.url ~ "(?i:showfile\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /js/modalbox/tests/functional/_ajax_method_get.php
   ## ARGS, :param
   # AC param 
   ## Rule: ARGS rx :param
   if(req.url ~ "(?i:param\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
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
   # skipped   REQUEST_LINE contains  /wp-content/plugins/iwant-one-ihave-one/updateAJAX.php
   ## ARGS, :post_id
   # AC post_id 
   ## Rule: ARGS rx :post_id
   if(req.url ~ "(?i:post_id\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/iwant-one-ihave-one/updateAJAX.php
   ## ARGS, :post_id
   # AC post_id 
   ## Rule: ARGS rx :post_id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/iwant-one-ihave-one/updateAJAX.php
   ## ARGS, :post_id
   # AC post_id 
   ## Rule: ARGS rx :post_id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/iwant-one-ihave-one/updateAJAX.php
   ## ARGS, :post_id
   # AC post_id 
   ## Rule: ARGS rx :post_id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/iwant-one-ihave-one/updateAJAX.php
   ## ARGS, :post_id
   # AC post_id 
   ## Rule: ARGS rx :post_id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/iwant-one-ihave-one/updateAJAX.php
   ## ARGS, :post_id
   # AC post_id 
   ## Rule: ARGS rx :post_id
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/iwant-one-ihave-one/updateAJAX.php
   ## ARGS, :post_id
   # AC post_id 
   ## Rule: ARGS rx :post_id
   if(req.url ~ "(?i:UPDATE.+SET)"){
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
   # skipped   REQUEST_LINE contains  /wp-content/plugins/xcloner-backup-and-restore/index2.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  task=dologin
   ## ARGS, :option
   # AC option 
   ## Rule: ARGS rx :option
   if(req.url ~ "(?i:option\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/xcloner-backup-and-restore/index2.php
   ## ARGS, :mosmsg
   # AC mosmsg 
   ## Rule: ARGS rx :mosmsg
   if(req.url ~ "(?i:mosmsg\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/forum-server/feed.php
   ## ARGS, :topic
   # AC topic 
   ## Rule: ARGS rx :topic
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/forum-server/feed.php
   ## ARGS, :topic
   # AC topic 
   ## Rule: ARGS rx :topic
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/forum-server/feed.php
   ## ARGS, :topic
   # AC topic 
   ## Rule: ARGS rx :topic
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/forum-server/feed.php
   ## ARGS, :topic
   # AC topic 
   ## Rule: ARGS rx :topic
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/forum-server/feed.php
   ## ARGS, :topic
   # AC topic 
   ## Rule: ARGS rx :topic
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/forum-server/feed.php
   ## ARGS, :topic
   # AC topic 
   ## Rule: ARGS rx :topic
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/zotpress/zotpress.image.php
   ## ARGS, :citation
   # AC citation 
   ## Rule: ARGS rx :citation
   if(req.url ~ "(?i:citation\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/1-flash-gallery/folder.php
   ## ARGS, :type
   # AC type 
   ## Rule: ARGS rx :type
   if(req.url ~ "(?i:type\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/1-flash-gallery/massedit_album.php
   ## ARGS, :gall_id
   # AC gall_id 
   ## Rule: ARGS rx :gall_id
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/1-flash-gallery/massedit_album.php
   ## ARGS, :gall_id
   # AC gall_id 
   ## Rule: ARGS rx :gall_id
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/1-flash-gallery/massedit_album.php
   ## ARGS, :gall_id
   # AC gall_id 
   ## Rule: ARGS rx :gall_id
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/1-flash-gallery/massedit_album.php
   ## ARGS, :gall_id
   # AC gall_id 
   ## Rule: ARGS rx :gall_id
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/1-flash-gallery/massedit_album.php
   ## ARGS, :gall_id
   # AC gall_id 
   ## Rule: ARGS rx :gall_id
   if(req.url ~ "(?i:ASCII\(.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/1-flash-gallery/massedit_album.php
   ## ARGS, :gall_id
   # AC gall_id 
   ## Rule: ARGS rx :gall_id
   if(req.url ~ "(?i:UPDATE.+SET)"){
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
   # skipped   REQUEST_LINE contains  /wp-content/plugins/lazyest-gallery/lazyest-popup.php
   ## ARGS, :image
   # AC image 
   ## Rule: ARGS rx :image
   if(req.url ~ "(?i:image\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/lazyest-gallery/lazyest-popup.php
   ## ARGS, :image
   # AC image 
   ## Rule: ARGS rx :image
   if(req.url ~ "(?i:image\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
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
   # skipped   REQUEST_LINE contains  /plugins/socialgrid/static/js/inline-admin.js.php
   ## ARGS, :default_services
   # AC default_services 
   ## Rule: ARGS rx :default_services
   if(req.url ~ "(?i:default_services\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /plugins/inline-gallery/browser/browser.php
   ## ARGS, :do
   # AC do 
   ## Rule: ARGS rx :do
   if(req.url ~ "(?i:do\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/flash-album-gallery/lib/hitcounter.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :pid
   # AC pid 
   ## Rule: ARGS rx :pid
   if(req.url ~ "(?i:SELECT.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/flash-album-gallery/lib/hitcounter.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :pid
   # AC pid 
   ## Rule: ARGS rx :pid
   if(req.url ~ "(?i:DELETE.+FROM)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/flash-album-gallery/lib/hitcounter.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :pid
   # AC pid 
   ## Rule: ARGS rx :pid
   if(req.url ~ "(?i:UNION.+SELECT)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/flash-album-gallery/lib/hitcounter.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :pid
   # AC pid 
   ## Rule: ARGS rx :pid
   if(req.url ~ "(?i:INSERT.+INTO)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/flash-album-gallery/lib/hitcounter.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :pid
   # AC pid 
   ## Rule: ARGS rx :pid
   if(req.url ~ "(?i:UPDATE.+SET)"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  /wp-content/plugins/php_speedy_wp/libs/php_speedy/view/admin_container.php
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  GET 
   ## ARGS, :page
   # AC page 
   ## Rule: ARGS rx :page
   if(req.url ~ "(?i:page=\s*(ftps?|https?|php)\:\/)"){
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
   # skipped   REQUEST_LINE contains  /wp-content/plugins/php_speedy_wp/libs/php_speedy/view/admin_container.php
   ## ARGS, :title
   # AC title 
   ## Rule: ARGS rx :title
   if(req.url ~ "(?i:title\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  page=eshop-templates.php
   ## ARGS, :eshoptemplate
   # AC eshoptemplate 
   ## Rule: ARGS rx :eshoptemplate
   if(req.url ~ "(?i:eshoptemplate\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  page=eshop-orders.php
   ## ARGS, :action
   # AC action 
   ## Rule: ARGS rx :action
   if(req.url ~ "(?i:action\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
      call sec_default_handler;
   }
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE contains  page=eshop-orders.php
   ## ARGS, :viewemail
   # AC viewemail 
   ## Rule: ARGS rx :viewemail
   if(req.url ~ "(?i:viewemail\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D))"){
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

