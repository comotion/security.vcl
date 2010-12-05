# comotion@krutt.org
# hide headers that would otherwise reveal varnish
# note: there are other cleverer ways of discovering varnish
sub vcl_deliver {
   # cloak
   remove resp.http.Via;
   remove resp.http.X-Varnish;
   remove resp.http.Retry-after;
   remove resp.http.Server;

   # cant get rid these, they get added after deliver.
   # so much for proper cloaking
   remove resp.http.Client-Date;
   remove resp.http.Client-Peer;
   remove resp.http.Client-Response-Num;
   remove resp.http.Connection;
}

sub vcl_recv {
   set req.http.X-SEC-Module = "cloak";
   
   # I'm sure there are other urls you can try Erik
   if (req.version ~
   if (req.url ~ "^/%250?$"){
      set req.http.X-SEC-RuleName = "Bogous request";
      set req.http.X-SEC-RuleId = "1";
      set req.http.X-SEC-RuleInfo = "Htrosbif specific";
      # htrosbif attacks! lets try to confuse it
      error 100 "continue";
      call sec_handler;
   }
}


# Try to obscure the client-to-backend comms as well
sub vcl_miss {
   # remove bereq.http.User-agent;
   remove bereq.http.X-Forwarded-For;
   remove bereq.http.X-Varnish;
}
