#file:Plugin/Plugin_REDIRECT_NO_REFERER.pm
#-------------------------
package Plugin::Plugin_REDIRECT_NO_REFERER;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&plugin);
}

use Apache2::Log;
use Apache2::Reload;

use Apache2::Const -compile => qw(OK FORBIDDEN);
use Core::VultureUtils qw(&get_cookie &session);

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;

    $log->debug("########## Plugin_GS_REFERER ##########");
    my $mc_conf         = $r->pnotes('mc_conf');
    my $SSO_cookie_name = get_cookie( $r->headers_in->{Cookie},
        $r->dir_config('VultureProxyCookieName') . '=([^;]*)' )|| '';
    my (%session_SSO);
    session( \%session_SSO, $intf->{sso_timeout}, $SSO_cookie_name, $log,
        $mc_conf, $intf->{sso_update_access_time} );
    my $SSO_cookie_app_name = get_cookie( $r->headers_in->{Cookie},
        $r->dir_config('VultureAppCookieName') . '=([^;]*)' )|| '';

    $log->debug($SSO_cookie_app_name);
    if (   ( $r->hostname eq $intf->{'cas_portal'} )
        or length( $r->headers_in->{'Referer'} )
        or $session_SSO{is_auth}
        or defined($SSO_cookie_app_name) )
    {
        $log->debug( $r->headers_in->{'Referer'} );
        return undef;
    }

    $options ||= '/';
    $log->debug("Bad referer. Redirecting to $options");

    #Display result in ResponseHandler
    $r->pnotes( 'response_content' =>
            "<html><head><meta http-equiv=\"Refresh\" content=\"0; url='" 
          . $options
          . "'\"/></head></html>");
    $r->pnotes( 'response_content_type' => 'text/html' );

    #Destroy useless handlers
    $r->set_handlers( PerlAuthenHandler => undef );
    $r->set_handlers( PerlAuthzHandler  => undef );
    $r->set_handlers( PerlFixupHandler  => undef );

    #Bypass TransHandler
    return Apache2::Const::OK;
}

1;
