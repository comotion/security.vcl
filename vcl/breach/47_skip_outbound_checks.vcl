sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## TX, :text_file_extension
   # AC text_file_extension 
   # skipped   TX eq text_file_extension 1
   ## TX, :no_parameters
   # AC no_parameters 
   # skipped   TX eq no_parameters 1
}

