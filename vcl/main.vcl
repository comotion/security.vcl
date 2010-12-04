
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

include "/etc/varnish/security/build/variables.vcl";
include "/etc/varnish/security/modules/demo.vcl";
include "/etc/varnish/security/modules/php.vcl";
include "/etc/varnish/security/modules/sql.vcl";
include "/etc/varnish/security/modules/xss.vcl";
include "/etc/varnish/security/modules/cmd.vcl";
include "/etc/varnish/security/modules/restricted-file-extensions.vcl";
include "/etc/varnish/security/modules/content-encoding.vcl";
include "/etc/varnish/security/modules/content-type.vcl";
include "/etc/varnish/security/modules/localfiles.vcl";
include "/etc/varnish/security/modules/request.vcl";

#include "/etc/varnish/security/modules/user-agent.vcl";

#include "/etc/varnish/security/breach/20_protocol_violations.vcl";
#include "/etc/varnish/security/breach/21_protocol_anomalies.vcl";
#include "/etc/varnish/security/breach/23_request_limits.vcl";
#include "/etc/varnish/security/breach/30_http_policy.vcl";
#include "/etc/varnish/security/breach/35_bad_robots.vcl";
#include "/etc/varnish/security/breach/40_generic_attacks.vcl";
#include "/etc/varnish/security/breach/45_trojans.vcl";
#include "/etc/varnish/security/breach/50_outbound.vcl";

/* The value of '800' and up is used because it is not actual HTTP error
 * codes. They should not be exposed. 
 *
 * The list thus far: 
 *  800 - Debug
 *  801 - Plain error (401-unauthorized might be a bad rewrite here)
 *  802 - Redirect
 */
sub vcl_error {
	if (obj.status == 800) {
		set obj.http.X-SEC-Rule = req.http.X-SEC-Module "-" req.http.X-SEC-RuleId;

		set obj.status = 200;
	} elsif (obj.status == 801) {
		set obj.status = 401;
		set obj.response = "Here be dragons! YARR! Wait, that's pirates.";
	} elsif (obj.status == 802) {
		set obj.status = 302;
		set obj.response = "Redirected for fun and profit";
		set obj.http.Location = "http://images.google.com/images?q=llama";
		return (deliver);
	}
}

/* Catch-all handler */
sub sec_general {
	error 800 "BOOOYA!";
}

sub sec_sev1 {
	call sec_general;
}

/* vim: set syntax=c tw=76: */
