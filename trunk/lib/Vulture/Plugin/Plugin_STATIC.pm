#file:Plugin/Plugin_STATIC.pm
#-------------------------
#!/usr/bin/perl
package Plugin::Plugin_STATIC;

use strict;
use warnings;
use Cwd;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&plugin);
}

use Apache2::Log;
use Apache2::Reload;

use Core::VultureUtils qw(&get_app &session &get_cookie);
use Apache2::Const -compile => qw(OK FORBIDDEN);

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;

    my @captured = @{$options};
    my $mc_conf  = $r->pnotes('mc_conf');
    $log->debug("########## Plugin_STATIC ##########");
    my $cookie_app_name = $r->dir_config('VultureProxyCookieName');
    #check if we are serving static content from sso_portal
    my ($id_app) = Core::VultureUtils::get_cookie( $r->headers_in->{Cookie},
        $cookie_app_name . '=([^;]*)' );
    my (%session_app);
    Core::VultureUtils::session( \%session_app, $app->{timeout}, $id_app, $log,
        $mc_conf, $app->{update_access_time} );

    if (
           $r->hostname =~ $intf->{'sso_portal'}
        or $r->hostname =~ $intf->{'cas_portal'}
        or ( $r->headers_in->{'Referer'} =~ /$cookie_app_name=([^;]*)/ )
        or ( exists $session_app{SSO_Forwarding}
            and defined $session_app{SSO_Forwarding} )
      )
    {

        #Destroy useless handlers
        $r->set_handlers( PerlAccessHandler => undef );
        $r->set_handlers( PerlAuthenHandler => undef );
        $r->set_handlers( PerlAuthzHandler  => undef );
        $r->set_handlers( PerlFixupHandler  => undef );

        #$r->set_handlers(PerlResponseHandler => sub { return });

        my $fpath =
          Cwd::abs_path( $r->dir_config('VultureStaticPath') . $captured[0] );
        $log->debug("Serving $fpath");
        my $regexp = $r->dir_config('VultureStaticPath');
        if ( $fpath !~ /^$regexp/ ) {
            $log->debug( "blocking bad request : " . $captured[0] );
            return undef;
        }
        $r->filename($fpath);

        # or $r->status(404);
        $r->content_type('image/jpeg');
        $r->pnotes( 'static' => 1 );
        return Apache2::Const::OK;
    }
    else {
        $log->debug("Serving static file belongs to proxyfied app");
        return undef;
    }
}

1;
