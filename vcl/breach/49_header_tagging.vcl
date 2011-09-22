sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## TX, :ANOMALY_SCORE
   # AC ANOMALY_SCORE 
   # skipped   TX eq ANOMALY_SCORE 0
   ## TX, :re(^)
   # AC re(^) 
   ## Rule: TX rx :re(^)
}

