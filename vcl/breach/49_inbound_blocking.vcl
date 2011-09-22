sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## TX, :ANOMALY_SCORE
   # AC ANOMALY_SCORE 
   # skipped   TX gt ANOMALY_SCORE 0
   ## RESOURCE, :OSVDB_VULNERABLE
   # AC OSVDB_VULNERABLE 
   # skipped   RESOURCE eq OSVDB_VULNERABLE 1
   ## TX, :ANOMALY_SCORE_BLOCKING
   # AC ANOMALY_SCORE_BLOCKING 
   # skipped   TX streq ANOMALY_SCORE_BLOCKING on
   ## TX, :ANOMALY_SCORE
   # AC ANOMALY_SCORE 
   # skipped   TX gt ANOMALY_SCORE 0
   ## TX, :ANOMALY_SCORE
   # AC ANOMALY_SCORE 
   # skipped   TX ge ANOMALY_SCORE %{tx.inbound_anomaly_score_level}
   ## TX, :ANOMALY_SCORE_BLOCKING
   # AC ANOMALY_SCORE_BLOCKING 
   # skipped   TX streq ANOMALY_SCORE_BLOCKING on
   ## TX, :re(^)
   # AC re(^) 
   ## Rule: TX rx :re(^)
}

