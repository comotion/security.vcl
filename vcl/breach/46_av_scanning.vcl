sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## FILES_TMPNAMES, 
   # skipped   FILES_TMPNAMES inspectFile  /bin/runAV
}

