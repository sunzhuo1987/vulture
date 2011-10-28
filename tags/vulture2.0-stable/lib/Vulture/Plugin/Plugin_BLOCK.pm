#file:Plugin/Plugin_BLOCK.pm
#-------------------------
package Plugin::Plugin_BLOCK;

use Apache2::Log;
use Apache2::Reload;

use Apache2::Const -compile => qw(FORBIDDEN);

sub plugin{
	my ($package_name, $r, $log, $dbh, $app, $options) = @_;
	
	$log->debug("########## Plugin_BLOCK ##########");

	$r->set_handlers(PerlResponseHandler => Apache2::Const::FORBIDDEN);

	return Apache2::Const::FORBIDDEN;
}

1;
