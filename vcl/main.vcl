
/* Security.vcl main VCL file
 * Copyright (C) 2009 Redpill Linpro AS
 * Copyright (C) 2009 Kristian Lyngstøl
 * Copyright (C) 2009 Kacper Wysocki
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Author: Kristian Lyngstøl <kristian@redpill-linpro.com>
 * Author: Kacper Wysocki <kwy@redpill-linpro.com>
 * 
 * FIXME: We might need a Makefile for the paths here, but for now, they are
 * hardcoded. Blah.
 */

import std;

# clear all internal variables
include "/etc/varnish/security/build/variables.vcl";

sub vcl_recv {
   # gather info about client
   # this is one of the vars guaranteed to be present
   # if and only if your request is inside security.vcl
   set req.http.X-SEC-Client = "[" +  client.ip + "] "
                               + req.http.host + req.url 
                               + " (" + req.http.user-agent + ")";
}

# which modules to use, what to log, how to handle events and honeypot backend definition
include "/etc/varnish/security/config.vcl";

# fallthrough: clear all internal variables on security.vcl_recv exit
include "/etc/varnish/security/build/variables.vcl";

# define all the event handlers
include "/etc/varnish/security/handlers.vcl";

/* The value of '800' and up is used because it is not actual HTTP error
 * codes. They should not be exposed. 
 *
 * The list thus far: 
 *  800 - Debug
 *  801 - Plain error (403-forbidden might be a bad rewrite here)
 *  802 - Redirect
 *  803 - Restart, forward to backend honey
 *  804 - Synthetic response
 *  805 - Attempt to drop or reset the request (not implemented yet)
 *  808 - Raw synthetic deliver
 */
sub vcl_error {
   # are we insecure?
   if(req.restarts == 0 && req.http.X-SEC-Client ){
      # XXX: for some reason one log prints twice... bug?
      call sec_log;
      if (obj.status == 800) {
         set obj.http.X-SEC-Rule = req.http.X-SEC-Rule;
         set obj.status = 200;
      } elsif (obj.status == 801) {
         set obj.status = 403;
         if(req.http.X-SEC-Response ){
            set obj.response = req.http.X-SEC-Response;
         }else{
            set obj.response = "Forbidden";
         }
      } elsif (obj.status == 802) {
         set obj.status = 302;
         #set obj.response = "Redirected for fun and profit";
         if(obj.http.X-SEC-Response ){
            set obj.http.Location = obj.http.X-SEC-Response;
         }else{
            set obj.http.Location = "http://images.google.com/images?q=llama";
         }
         return (deliver);
      } elsif (obj.status == 803) {
         # restart on 2nd backend
         set req.http.X-SEC-Response = "honeypot me";
         set req.backend = sec_honey;
         return (restart);
      } elsif (obj.status == 804){
         set obj.status = 200;
         set obj.response = "OK";
         set obj.http.content-type = "text/html";
         if(! obj.http.X-SEC-Response ){
            set obj.http.X-SEC-Response = "Synthetic";
         }
         synthetic {"<html><body>
"} + obj.http.X-SEC-Response + {"
</body></html>
"};
         return (deliver);
      } elsif (obj.status == 805) {
         set obj.status = 501;
         set obj.response = "Get outta here";
      } elsif (obj.status == 808) {
         set obj.status = 200;
         set obj.response = "OK";
         synthetic req.http.X-SEC-Response;
      }
      # fallthrough to other vcl_error's
   }
}

/* Call this one to just log rule hits and pass to backend
 * without calling error.
 * This effectively *DISABLES* security.vcl protectionism */
sub sec_passthru {
   call sec_log;
}


/* Call this one for a catch-all */
sub sec_general {
	error 800 "Naugty, not nice!";
}

/* 403 rejected */
sub sec_reject {
   error 801 "Rejected";
}

/* call this one for a redirect */
sub sec_redirect {
   error 802 "Redirect";
}

sub sec_honeypot {
   error 803 "Sexy Honey";
}

/* call this one for synthetic html */
sub sec_synthtml {
   error 804 "Synthetic";
}

/* TODO: drop the request..
 *   the plan is to implement VMOD that either
 *   - sends an RST and kills the client connection OR
 *   - kills the client connection silently
 */
sub sec_drop {
   error 805 "quit it";
}

sub sec_magichandler {

   if(!req.http.X-SEC-Response ) { 
      ## The default attack response message, can be overridden by rules.
      set req.http.X-SEC-Response = "Naughty, not nice!";
   }
   if(req.http.X-SEC-Response ~ "^honeypot me$"){
      # we have restarted and our request is on the honeypot backend
      # pass the request;
      return (pass);
   }
}
/* You can define how to handle the different severity levels. */
sub sec_handler {
   ## retrieve the rule info
   set req.http.X-SEC-Rule = req.http.X-SEC-Module + "-" + req.http.X-SEC-RuleId;
   if(req.http.X-SEC-Rule ~ "^(fooobs)$") {
      # squelch this rule
   }else{
      ## magichandler handles restarts should always be called!
      call sec_magichandler;

      if(req.http.X-SEC-Severity == "1"){
         /* we have only one severity for now: this is the default rule */
         call sec_default_handler;
      }else{
         # fallback attack response when severity is off the charts
         call sec_default_handler;
      }

      if(!req.http.X-SEC-Client ){ # this variable always present, so rule always false
         # all functions must be used in vcl, fool compiler by putting them here

         std.log("security.vcl WONTREACH: available sec handlers");
         #  the handlers are defined in main.vcl along with the error codes
         #     handler name  # code # purpose
         call sec_general;   # 800  # debug handler - delivers X-SEC-Rule to client
         call sec_reject;    # 801  # 403 reject with message
         call sec_redirect;  # 802  # 302 redirect
         call sec_honeypot;  # 803  # restart request with honeypot backend
         call sec_synthtml;  # 804  # synthesize a response
         call sec_drop;      # 805  # drop the request (not implemented) 
         call sec_myhandler; # any  # do your own thing
         call sec_default_handler;  # fallback handler
         ## note! the passthru handler really does pass thru
         # - you must make sure it is the last thing called
         call sec_passthru;  # n/a  # log client and pass thru to default error logic
      }
   }
}


/* vim: set syntax=c tw=76: */
