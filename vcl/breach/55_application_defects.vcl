sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## &GLOBAL, :MISSING_CHARSET
   # AC MISSING_CHARSET 
   # skipped  & GLOBAL eq MISSING_CHARSET 0
   ## GLOBAL, :MISSING_CHARSET
   # AC MISSING_CHARSET 
   # skipped   GLOBAL le MISSING_CHARSET 10
   ## RESPONSE_STATUS, 
   # skipped   RESPONSE_STATUS rx  ^2
   ## RESPONSE_HEADERS, :Content-Length
   # AC Content-Length 
   # skipped   RESPONSE_HEADERS streq Content-Length 0
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <meta.*?content=\"text/html; charset=
   ## RESPONSE_CONTENT_TYPE, 
   # skipped   RESPONSE_CONTENT_TYPE rx  (?i:^text/html;?$)
   ## &GLOBAL, :CHARSET_NOT_UTF8
   # AC CHARSET_NOT_UTF8 
   # skipped  & GLOBAL eq CHARSET_NOT_UTF8 0
   ## GLOBAL, :CHARSET_NOT_UTF8
   # AC CHARSET_NOT_UTF8 
   # skipped   GLOBAL le CHARSET_NOT_UTF8 10
   ## RESPONSE_STATUS, 
   # skipped   RESPONSE_STATUS rx  ^2
   ## RESPONSE_CONTENT_TYPE, 
   # skipped   RESPONSE_CONTENT_TYPE rx  (?i:^text/html)
   ## RESPONSE_CONTENT_TYPE, 
   # skipped   RESPONSE_CONTENT_TYPE contains  charset=utf-8
   ## RESPONSE_HEADERS, :Content-Length
   # AC Content-Length 
   # skipped   RESPONSE_HEADERS streq Content-Length 0
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <meta.*?content=\"text/html; charset=utf-8
   ## &GLOBAL, :CHARSET_MISMATCH
   # AC CHARSET_MISMATCH 
   # skipped  & GLOBAL eq CHARSET_MISMATCH 0
   ## GLOBAL, :CHARSET_MISMATCH
   # AC CHARSET_MISMATCH 
   # skipped   GLOBAL le CHARSET_MISMATCH 10
   ## RESPONSE_STATUS, 
   # skipped   RESPONSE_STATUS rx  ^2
   ## RESPONSE_CONTENT_TYPE, 
   # skipped   RESPONSE_CONTENT_TYPE rx  (?i:^text/html;\s?charset=(.*))
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  (?i:<meta.*?content=\"text/html; charset=(.*?)\")
   ## RESPONSE_HEADERS, :Content-Length
   # AC Content-Length 
   # skipped   RESPONSE_HEADERS streq Content-Length 0
   ## TX, :CHARSET_HEADER
   # AC CHARSET_HEADER 
   # skipped   TX streq CHARSET_HEADER %{tx.charset_body}
   ## &ARGS, 
   # skipped  & ARGS gt  0
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "([\'\"\(\)\;<>#])"){
      # chained rule
   }
   ## MATCHED_VAR, 
   ## Rule: MATCHED_VAR rx :
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY contains  %{tx.inbound_meta-characters}
   ## GLOBAL, :re(XSS_LIST_)
   # AC re(XSS_LIST_) 
   ## Rule: GLOBAL rx :re(XSS_LIST_)
   ## TX, :INBOUND_META-CHARACTERS
   # AC INBOUND_META-CHARACTERS 
   ## Rule: TX rx :INBOUND_META-CHARACTERS
   ## GLOBAL, :re(XSS_LIST_)
   # AC re(XSS_LIST_) 
   ## Rule: GLOBAL rx :re(XSS_LIST_)
   ## RESPONSE_HEADERS, :/Set-Cookie2
   # AC /Set-Cookie2 
   # skipped   RESPONSE_HEADERS rx /Set-Cookie2 ?
   ## TX, :SESSIONID
   # AC SESSIONID 
   ## Rule: TX rx :SESSIONID
   ## SERVER_PORT, 
   # skipped   SERVER_PORT streq  443
   ## TX, :SESSIONID
   # AC SESSIONID 
   ## Rule: TX rx :SESSIONID
   ## TX, :SESSIONID
   # AC SESSIONID 
   ## Rule: TX rx :SESSIONID
   ## SERVER_PORT, 
   # skipped   SERVER_PORT streq  443
   ## TX, :SESSIONID
   # AC SESSIONID 
   ## Rule: TX rx :SESSIONID
}

