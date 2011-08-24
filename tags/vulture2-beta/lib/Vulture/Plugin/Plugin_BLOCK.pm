#file:Plugin/Plugin_BLOCK.pm
#-------------------------
package Plugin::Plugin_BLOCK;

use Apache2::Log;
use Apache2::Reload;

use Apache2::Request;

use Apache2::Const -compile => qw(DECLINED);

sub plugin{
	my ($package_name, $r, $log, $dbh, $options) = @_;
	
	$log->debug("########## Plugin_BLOCK ##########");

	#Destroy useless handlers
	$r->set_handlers(PerlAccessHandler => undef);
	$r->set_handlers(PerlAuthenHandler => undef);
	$r->set_handlers(PerlAuthzHandler => undef);
	$r->set_handlers(PerlFixupHandler => undef);
	$r->set_handlers(PerlResponseHandler => undef);

	return Apache2::Const::DECLINED;
}

1;
