sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "^"){
      set req.http.X-Sec-RuleId = "960022-2";
      # chained rule
   }
   ## TX, :re(^ARGS
   # AC re(^ARGS 
   # skipped   TX gt re(^ARGS 1
   ## MATCHED_VAR_NAME, 
   ## Rule: MATCHED_VAR_NAME rx :
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ ".*"){
      # chained rule
   }
   ## TX, :re(HPPNAMEDATA_)
   # AC re(HPPNAMEDATA_) 
   ## Rule: TX contains :re(HPPNAMEDATA_)
   ## TX, :re(HPP_COUNTER_)
   # AC re(HPP_COUNTER_) 
   ## Rule: TX rx :re(HPP_COUNTER_)
}

