sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## TX, :PARANOID_MODE
   # AC PARANOID_MODE 
   # skipped   TX eq PARANOID_MODE 1
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(?:\x5c|(?:%(?:c(?:0%(?:9v|af)|1%1c)|2(?:5(?:2f|5c)|f)|u221[56]|1u|5c)|\/))(?:%(?:u2024|2e)|\.){2}(?:\x5c|(?:%(?:c(?:0%(?:9v|af)|1%1c)|2(?:5(?:2f|5c)|f)|u221[56]|1u|5c)|\/))"){
      call sec_default_handler;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(?:\x5c|(?:%(?:c(?:0%(?:9v|af)|1%1c)|2(?:5(?:2f|5c)|f)|u221[56]|1u|5c)|\/))(?:%(?:u2024|2e)|\.){2}(?:\x5c|(?:%(?:c(?:0%(?:9v|af)|1%1c)|2(?:5(?:2f|5c)|f)|u221[56]|1u|5c)|\/))"){
      call sec_default_handler;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(?:\x5c|(?:%(?:c(?:0%(?:9v|af)|1%1c)|2(?:5(?:2f|5c)|f)|u221[56]|1u|5c)|\/))(?:%(?:u2024|2e)|\.){2}(?:\x5c|(?:%(?:c(?:0%(?:9v|af)|1%1c)|2(?:5(?:2f|5c)|f)|u221[56]|1u|5c)|\/))"){
      call sec_default_handler;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(?:\x5c|(?:%(?:c(?:0%(?:9v|af)|1%1c)|2(?:5(?:2f|5c)|f)|u221[56]|1u|5c)|\/))(?:%(?:u2024|2e)|\.){2}(?:\x5c|(?:%(?:c(?:0%(?:9v|af)|1%1c)|2(?:5(?:2f|5c)|f)|u221[56]|1u|5c)|\/))"){
      call sec_default_handler;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(?:\x5c|(?:%(?:c(?:0%(?:9v|af)|1%1c)|2(?:5(?:2f|5c)|f)|u221[56]|1u|5c)|\/))(?:%(?:u2024|2e)|\.){2}(?:\x5c|(?:%(?:c(?:0%(?:9v|af)|1%1c)|2(?:5(?:2f|5c)|f)|u221[56]|1u|5c)|\/))"){
      call sec_default_handler;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (?:\x5c|(?:%(?:c(?:0%(?:9v|af)|1%1c)|2(?:5(?:2f|5c)|f)|u221[56]|1u|5c)|\/))(?:%(?:u2024|2e)|\.){2}(?:\x5c|(?:%(?:c(?:0%(?:9v|af)|1%1c)|2(?:5(?:2f|5c)|f)|u221[56]|1u|5c)|\/))
}

