sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \%[Bb][3456][0-9]{3,3}[\x20\-]{0,3}[0-9]{4,6}[\x20\-]{0,3}[0-9]{2,5}[\x20\-]{0,3}[0-9]{0,4}\^[^\^]+\^[0-9]+\?
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \;[3456][0-9]{3,3}[\x20\-]{0,3}[0-9]{4,6}[\x20\-]{0,3}[0-9]{2,5}[\x20\-]{0,3}[0-9]{0,4}[=Dd][0-9]+\?
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  [^0-9][3456][0-9]{3,3}[\x20\-]{0,3}[0-9]{4,6}[\x20\-]{0,3}[0-9]{2,5}[\x20\-]{0,3}[0-9]{0,4}[^0-9]
}

