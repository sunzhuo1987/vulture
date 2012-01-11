#file:Plugin/Plugin_SAML.pm
#-------------------------
#!/usr/bin/perl
package Plugin::Plugin_SAML;

use strict;
use warnings;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub plugin {
	my ($package_name, $r, $log, $dbh, $intf, $app, $options) = @_;
	
	$log->debug("########## Plugin_SAML ##########");
	
}

1;