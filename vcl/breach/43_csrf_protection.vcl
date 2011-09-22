sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## &ARGS, 
   # skipped  & ARGS ge  1
   ## &ARGS, :CSRF_TOKEN
   # AC CSRF_TOKEN 
   # skipped  & ARGS eq CSRF_TOKEN 1
   ## &ARGS, 
   # skipped  & ARGS ge  1
   ## ARGS, :CSRF_TOKEN
   # AC CSRF_TOKEN 
   # skipped   ARGS streq CSRF_TOKEN %{SESSION.CSRF_TOKEN}
   ## &SESSION, :CSRF_TOKEN
   # AC CSRF_TOKEN 
   # skipped  & SESSION eq CSRF_TOKEN 1
}

