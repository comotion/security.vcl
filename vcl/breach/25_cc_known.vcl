sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## ARGS, 
   ## Rule: ARGS verifyCC :
   if(req.url verifyCC "(?:^|[^\d])(\d{4}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{1,4})(?:[^\d]|$)"){
      set req.http.X-Sec-RuleId = "981078";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS verifyCC :
   if(req.url verifyCC "(?:^|[^\d])((?:5568|4(?:486|716))\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{4}|8699\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{3})(?:[^\d]|$)"){
      set req.http.X-Sec-RuleInfo = "GSA SmartPay Credit Card Number detected in user input";
      set req.http.X-Sec-RuleName = "PCI/10.2";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "920019";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS verifyCC :
   if(req.url verifyCC "(?:^|[^\d])(5[1-5]\d{2}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{4})(?:[^\d]|$)"){
      set req.http.X-Sec-RuleInfo = "MasterCard Credit Card Number detected in user input";
      set req.http.X-Sec-RuleName = "PCI/10.2";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "920005";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS verifyCC :
   if(req.url verifyCC "(?:^|[^\d])(4\d{3}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d(?:\d{3})??)(?:[^\d]|$)"){
      set req.http.X-Sec-RuleInfo = "Visa Credit Card Number detected in user input";
      set req.http.X-Sec-RuleName = "PCI/10.2";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "920007";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS verifyCC :
   if(req.url verifyCC "(?:^|[^\d])(3[47]\d{2}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{3})(?:[^\d]|$)"){
      set req.http.X-Sec-RuleInfo = "American Express Credit Card Number detected in user input";
      set req.http.X-Sec-RuleName = "PCI/10.2";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "920009";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS verifyCC :
   if(req.url verifyCC "(?:^|[^\d])((?:30[0-5]|3[68]\d)\d\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{2})(?:[^\d]|$)"){
      set req.http.X-Sec-RuleInfo = "Diners Club Credit Card Number detected in user input";
      set req.http.X-Sec-RuleName = "PCI/10.2";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "920011";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS verifyCC :
   if(req.url verifyCC "(?:^|[^\d])(6(?:011|5\d{2})\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{4})(?:[^\d]|$)"){
      set req.http.X-Sec-RuleInfo = "Discover Credit Card Number detected in user input";
      set req.http.X-Sec-RuleName = "PCI/10.2";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "920015";
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS verifyCC :
   if(req.url verifyCC "(?:^|[^\d])(3\d{3}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{4}|(?:1800|21(?:31|00))\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{3})(?:[^\d]|$)"){
      set req.http.X-Sec-RuleInfo = "JCB Credit Card Number detected in user input";
      set req.http.X-Sec-RuleName = "PCI/10.2";
      set req.http.X-Sec-Severity = "5";
      set req.http.X-Sec-RuleId = "920017";
      call sec_default_handler;
   }
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY verifyCC  (?:^|[^\d])(?<!google_ad_client = \"pub-)(\d{4}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{1,4})(?:[^\d]|$)
   ## RESPONSE_HEADERS, :Location
   # AC Location 
   # skipped   RESPONSE_HEADERS verifyCC Location (?:^|[^\d])(?<!google_ad_client = \"pub-)(\d{4}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{1,4})(?:[^\d]|$)
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY verifyCC  (?:^|[^\d])(?<!google_ad_client = \"pub-)((?:5568|4(?:486|716))\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{4}|8699\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{3})(?:[^\d]|$)
   ## RESPONSE_HEADERS, :Location
   # AC Location 
   # skipped   RESPONSE_HEADERS verifyCC Location (?:^|[^\d])(?<!google_ad_client = \"pub-)((?:5568|4(?:486|716))\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{4}|8699\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{3})(?:[^\d]|$)
   ## TX, :1
   # AC 1 
   ## Rule: TX rx :1
   ## TX, :CCDATA
   # AC CCDATA 
   ## Rule: TX rx :CCDATA
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY verifyCC  (?:^|[^\d])(?<!google_ad_client = \"pub-)(5[1-5]\d{2}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{4})(?:[^\d]|$)
   ## RESPONSE_HEADERS, :Location
   # AC Location 
   # skipped   RESPONSE_HEADERS verifyCC Location (?:^|[^\d])(?<!google_ad_client = \"pub-)(5[1-5]\d{2}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{4})(?:[^\d]|$)
   ## TX, :1
   # AC 1 
   ## Rule: TX rx :1
   ## TX, :CCDATA
   # AC CCDATA 
   ## Rule: TX rx :CCDATA
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY verifyCC  (?:^|[^\d])(?<!google_ad_client = \"pub-)(4\d{3}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d(?:\d{3})??)(?:[^\d]|$)
   ## RESPONSE_HEADERS, :Location
   # AC Location 
   # skipped   RESPONSE_HEADERS verifyCC Location (?:^|[^\d])(?<!google_ad_client = \"pub-)(4\d{3}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d(?:\d{3})??)(?:[^\d]|$)
   ## TX, :1
   # AC 1 
   ## Rule: TX rx :1
   ## TX, :CCDATA
   # AC CCDATA 
   ## Rule: TX rx :CCDATA
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY verifyCC  (?:^|[^\d])(?<!google_ad_client = \"pub-)(3[47]\d{2}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{3})(?:[^\d]|$)
   ## RESPONSE_HEADERS, :Location
   # AC Location 
   # skipped   RESPONSE_HEADERS verifyCC Location (?:^|[^\d])(?<!google_ad_client = \"pub-)(3[47]\d{2}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{3})(?:[^\d]|$)
   ## TX, :1
   # AC 1 
   ## Rule: TX rx :1
   ## TX, :CCDATA
   # AC CCDATA 
   ## Rule: TX rx :CCDATA
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY verifyCC  (?:^|[^\d])(?<!google_ad_client = \"pub-)((?:30[0-5]|3[68]\d)\d\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{2})(?:[^\d]|$)
   ## RESPONSE_HEADERS, :Location
   # AC Location 
   # skipped   RESPONSE_HEADERS verifyCC Location (?:^|[^\d])(?<!google_ad_client = \"pub-)((?:30[0-5]|3[68]\d)\d\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{2})(?:[^\d]|$)
   ## TX, :1
   # AC 1 
   ## Rule: TX rx :1
   ## TX, :CCDATA
   # AC CCDATA 
   ## Rule: TX rx :CCDATA
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY verifyCC  (?:^|[^\d])(?<!google_ad_client = \"pub-)(6(?:011|5\d{2})\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{4})(?:[^\d]|$)
   ## RESPONSE_HEADERS, :Location
   # AC Location 
   # skipped   RESPONSE_HEADERS verifyCC Location (?:^|[^\d])(?<!google_ad_client = \"pub-)(6(?:011|5\d{2})\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{4})(?:[^\d]|$)
   ## TX, :1
   # AC 1 
   ## Rule: TX rx :1
   ## TX, :CCDATA
   # AC CCDATA 
   ## Rule: TX rx :CCDATA
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY verifyCC  (?:^|[^\d])(?<!google_ad_client = \"pub-)(3\d{3}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{4}|(?:1800|21(?:31|00))\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{3})(?:[^\d]|$)
   ## RESPONSE_HEADERS, :Location
   # AC Location 
   # skipped   RESPONSE_HEADERS verifyCC Location (?:^|[^\d])(?<!google_ad_client = \"pub-)(3\d{3}\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{4}|(?:1800|21(?:31|00))\-?\d{4}\-?\d{2}\-?\d{2}\-?\d{3})(?:[^\d]|$)
   ## TX, :1
   # AC 1 
   ## Rule: TX rx :1
   ## TX, :CCDATA
   # AC CCDATA 
   ## Rule: TX rx :CCDATA
}

