sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE rx  ^GET /$
   ## REMOTE_ADDR, 
   # skipped   REMOTE_ADDR rx  ^(127\.0\.0\.|\:\:)1$
   ## TX, :re(PROTOCOL_VIOLATION)
   # AC re(PROTOCOL_VIOLATION) 
   ## Rule: TX rx :re(PROTOCOL_VIOLATION)
   ## TX, :re(MISSING_HEADER_)
   # AC re(MISSING_HEADER_) 
   ## Rule: TX rx :re(MISSING_HEADER_)
   ## REQUEST_LINE, 
   # skipped   REQUEST_LINE rx  ^(GET /|OPTIONS \*) HTTP/1.0$
   ## REMOTE_ADDR, 
   # skipped   REMOTE_ADDR rx  ^(127\.0\.0\.|\:\:)1$
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS rx :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "^Apache.*\(internal dummy connection\)$"){
      # chained rule
   }
   ## TX, :re(PROTOCOL_VIOLATION)
   # AC re(PROTOCOL_VIOLATION) 
   ## Rule: TX rx :re(PROTOCOL_VIOLATION)
   ## TX, :re(MISSING_HEADER_)
   # AC re(MISSING_HEADER_) 
   ## Rule: TX rx :re(MISSING_HEADER_)
   ## REQUEST_METHOD, 
   # skipped   REQUEST_METHOD streq  POST
   ## REQUEST_HEADERS, :User-Agent
   # AC User-Agent 
   ## Rule: REQUEST_HEADERS contains :User-Agent
   # AAA User-Agent
   if(req.http.User-Agent ~ "Adobe Flash Player"){
      # chained rule
   }
   ## REQUEST_HEADERS, :X-Flash-Version
   # AC X-Flash-Version 
   ## Rule: REQUEST_HEADERS rx :X-Flash-Version
   # AAA X-Flash-Version
   if(req.http.X-Flash-Version ~ ".*"){
      # chained rule
   }
   ## REQUEST_HEADERS, :Content-Type
   # AC Content-Type 
   ## Rule: REQUEST_HEADERS contains :Content-Type
   # AAA Content-Type
   if(req.http.Content-Type ~ "application/x-amf"){
      # chained rule
   }
   ## TX, :re(PROTOCOL_VIOLATION)
   # AC re(PROTOCOL_VIOLATION) 
   ## Rule: TX rx :re(PROTOCOL_VIOLATION)
   ## TX, :re(MISSING_HEADER_)
   # AC re(MISSING_HEADER_) 
   ## Rule: TX rx :re(MISSING_HEADER_)
}

