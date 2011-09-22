sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## &RESOURCE, :OSVDB_CHECK
   # AC OSVDB_CHECK 
   # skipped  & RESOURCE eq OSVDB_CHECK 0
   ## RESPONSE_STATUS, 
   # skipped   RESPONSE_STATUS streq  200
   ## TX, :OSVDB_MSG
   # AC OSVDB_MSG 
   ## Rule: TX rx :OSVDB_MSG
}

