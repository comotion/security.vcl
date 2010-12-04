
/* Security.VCL demonstration rules
 * Copyright (C) 2009 Redpill Linpro AS
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
 *
 * This file demonstrates the intended use of Security VCL for
 * rule-matching and how to handle the fallout.
 */

sub sec_demo_sev1 {
	set req.http.X-SEC-Severity = "1";
	call sec_handler;
}

sub vcl_recv {
	set req.http.X-SEC-Module =  "demo";

	if (req.url ~ "/exploit/") {
		//TEST:demo-1:GET:/exploit/foo/bar:bla
		//TESTN:demo-1:GET:/notexploit/foo/bar
		set req.http.X-SEC-RuleName = "Awsome demo for Security.VCL";
		set req.http.X-SEC-RuleId = "1";
		set req.http.X-SEC-RuleInfo = "This rule triggers when an 31337 h4x0r accesses a dir with name /exploit/";
		call sec_demo_sev1;
	}
}

/* vim: set syntax=c tw=76: */
