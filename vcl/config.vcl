/* Security.vcl config VCL file
 * Copyright (C) 2009 Redpill Linpro AS
 * Copyright (C) 2009 Kristian Lyngstøl
 * Copyright (C) 2009 Kacper Wysocki
 * Copyright (C) 2009 Edward Bjarte Fjellskål
 *
 * In this file you specify which rulesets to configure,
 * what to log and which handlers to employ.
 *
 */

# Comment out any include line to disable the security module.
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

## User agent checks may be a little too restrictive for your tastes.
#include "/etc/varnish/security/modules/user-agent.vcl";

## The breach2vcl tool is not perfect...
# include "/etc/varnish/security/breach.vcl";


