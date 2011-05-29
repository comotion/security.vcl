/* Security.vcl config VCL file
 * Copyright (C) 2009 Redpill Linpro AS
 * Copyright (C) 2009 Kristian Lyngstøl
 * Copyright (C) 2009 Kacper Wysocki
 * Copyright (C) 2009 Edward Bjarte Fjellskål
 *
 * In this file you specify which rulesets to configure.
 *
 */

# Comment out any include line to disable the security module.
include "/etc/varnish/security/modules/demo.vcl";
include "/etc/varnish/security/modules/php.vcl";
include "/etc/varnish/security/modules/sql.vcl";
include "/etc/varnish/security/modules/xss.vcl";
#include "/etc/varnish/security/modules/cmd.vcl"; # wget rule kinda sucks for repo
include "/etc/varnish/security/modules/restricted-file-extensions.vcl";
include "/etc/varnish/security/modules/content-encoding.vcl";
include "/etc/varnish/security/modules/content-type.vcl";
include "/etc/varnish/security/modules/localfiles.vcl";

# check this module, it is rather harsh
include "/etc/varnish/security/modules/request.vcl";

# you may or may not want these
include "/etc/varnish/security/modules/robots.vcl";
include "/etc/varnish/security/modules/cloak.vcl";

## User agent checks may be a little too restrictive for your tastes.
#include "/etc/varnish/security/modules/user-agent.vcl";

## The breach2vcl tool is not perfect...
# include "/etc/varnish/security/breach.vcl";

