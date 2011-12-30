#file:Plugin/Plugin_STATIC.pm
#-------------------------
package Plugin::Plugin_STATIC;

use Apache2::Log;
use Apache2::Reload;


use Apache2::Const -compile => qw(OK FORBIDDEN);

sub plugin{
	my ($package_name, $r, $log, $dbh, $intf, $app, $options) = @_;

	my @captured = @{$options};
	
	$log->debug("########## Plugin_STATIC ##########");
    if($r->hostname =~ $intf->{'sso_portal'}){
        #Destroy useless handlers
        $r->set_handlers(PerlAccessHandler => undef);
        $r->set_handlers(PerlAuthenHandler => undef);
        $r->set_handlers(PerlAuthzHandler => undef);
        $r->set_handlers(PerlFixupHandler => undef);
        #$r->set_handlers(PerlResponseHandler => sub { return });

        $log->debug("Serving ".$captured[0]);
        $log->debug($r->dir_config('VultureStaticPath').$captured[0]);
        $r->filename($r->dir_config('VultureStaticPath').$captured[0]);
        # or $r->status(404);
        $r->content_type('image/jpeg');
        $r->pnotes('static' => 1);
        return Apache2::Const::OK;
    } else {
        $log->debug("Serving static file belongs to proxyfied app");
        return undef;
    }
}

1;
