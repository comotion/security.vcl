sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## &RESOURCE, :ENFORCE_RE_PROFILE
   # AC ENFORCE_RE_PROFILE 
   # skipped  & RESOURCE eq ENFORCE_RE_PROFILE 0
   ## &RESOURCE, :ENFORCE_RE_PROFILE
   # AC ENFORCE_RE_PROFILE 
   # skipped  & RESOURCE eq ENFORCE_RE_PROFILE 1
   ## REQUEST_METHOD, 
   ## Rule: REQUEST_METHOD within :
   if((HEAD|GET|POST|PUT|DELETE|TRACE|OPTIONS|CONNECT) ~ "req.request"){
      set req.http.X-Sec-RuleInfo = "Attempt to Invoke Unsupported HTTP Method.";
      set req.http.X-Sec-RuleName = "POLICY/METHOD_NOT_ALLOWED";
      set req.http.X-Sec-RuleName = "OWASP_AppSensor/RE2";
      set req.http.X-Sec-RuleName = "https://www.owasp.org/index.php/AppSensor_DetectionPoints#RE2:_Attempt_to_Invoke_Unsupported_HTTP_Method";
      set req.http.X-Sec-RuleId = "981087";
      call sec_default_handler;
   }
   ## TX, :REQUEST_METHOD_VIOLATION
   # AC REQUEST_METHOD_VIOLATION 
   # skipped   TX eq REQUEST_METHOD_VIOLATION 1
   ## TX, :MIN_NUM_ARGS_VIOLATION
   # AC MIN_NUM_ARGS_VIOLATION 
   # skipped   TX eq MIN_NUM_ARGS_VIOLATION 1
   ## TX, :MAX_NUM_ARGS_VIOLATION
   # AC MAX_NUM_ARGS_VIOLATION 
   # skipped   TX eq MAX_NUM_ARGS_VIOLATION 1
   ## TX, :ARGS_NAMES_VIOLATION
   # AC ARGS_NAMES_VIOLATION 
   ## Rule: TX rx :ARGS_NAMES_VIOLATION
   ## TX, :re(^ARGS)
   # AC re(^ARGS) 
   ## Rule: TX rx :re(^ARGS)
   ## TX, :re(^ARGS)
   # AC re(^ARGS) 
   ## Rule: TX rx :re(^ARGS)
   ## TX, :re(^ARGS)
   # AC re(^ARGS) 
   ## Rule: TX rx :re(^ARGS)
   ## TX, :re(^ARGS)
   # AC re(^ARGS) 
   ## Rule: TX rx :re(^ARGS)
   ## TX, :re(^ARGS)
   # AC re(^ARGS) 
   ## Rule: TX rx :re(^ARGS)
   ## TX, :re(^ARGS)
   # AC re(^ARGS) 
   ## Rule: TX rx :re(^ARGS)
   ## TX, :re(^ARGS)
   # AC re(^ARGS) 
   ## Rule: TX rx :re(^ARGS)
   ## TX, :re(^ARGS)
   # AC re(^ARGS) 
   ## Rule: TX rx :re(^ARGS)
   ## TX, :re(^ARGS)
   # AC re(^ARGS) 
   ## Rule: TX rx :re(^ARGS)
   ## TX, :re(^ARGS)
   # AC re(^ARGS) 
   ## Rule: TX rx :re(^ARGS)
   ## RESPONSE_STATUS, 
   # skipped   RESPONSE_STATUS rx  ^404$
   ## RESPONSE_STATUS, 
   # skipped   RESPONSE_STATUS rx  ^(5|4)
   ## TX, :ANOMALY_SCORE
   # AC ANOMALY_SCORE 
   # skipped   TX eq ANOMALY_SCORE 0
   ## &RESOURCE, :ENFORCE_RE_PROFILE
   # AC ENFORCE_RE_PROFILE 
   # skipped  & RESOURCE eq ENFORCE_RE_PROFILE 1
   ## Script, 
   ## Rule: Script rx :
}

