sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## TX, :OUTBOUND_ANOMALY_SCORE
   # AC OUTBOUND_ANOMALY_SCORE 
   # skipped   TX ge OUTBOUND_ANOMALY_SCORE %{tx.outbound_anomaly_score_level}
   ## TX, :ANOMALY_SCORE_BLOCKING
   # AC ANOMALY_SCORE_BLOCKING 
   # skipped   TX streq ANOMALY_SCORE_BLOCKING on
   ## TX, :re(^)
   # AC re(^) 
   ## Rule: TX rx :re(^)
}

