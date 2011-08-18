#file:Plugin/Plugin_STATIC.pm
#-------------------------
package Plugin::Plugin_STATIC;

use Apache2::Log;
use Apache2::Reload;

use Apache2::Request;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub plugin{
	my ($package_name, $r, $log, $dbh, $options) = @_;

	my @captured = @{$options};
	
	$log->debug("########## Plugin_STATIC ##########");

	#Destroy useless handlers
	$r->set_handlers(PerlAccessHandler => undef);
	$r->set_handlers(PerlAuthenHandler => undef);
	$r->set_handlers(PerlAuthzHandler => undef);

	$log->debug("Serving ".$captured[0]);
	$r->filename($r->dir_config('VultureStaticPath').$1) or $r->status(404);
	return Apache2::Const::OK;
}

1;
