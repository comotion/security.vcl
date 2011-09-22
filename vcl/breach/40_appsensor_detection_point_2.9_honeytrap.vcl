sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## ARGS, :DEBUG
   # AC DEBUG 
   # skipped   ARGS streq DEBUG false
   ## STREAM_OUTPUT_BODY, 
   ## Rule: STREAM_OUTPUT_BODY rsub :
}

