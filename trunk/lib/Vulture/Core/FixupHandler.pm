#file:Core/FixupHandler.pm
#---------------------------------
#!/usr/bin/perl
package Core::FixupHandler;

use strict;
use warnings;

use Apache2::Access ();
use Apache2::Reload;
use Apache2::RequestUtil ();
use Apache2::Log;

use Apache2::Const -compile => qw(OK);

use Core::VultureUtils qw(&session &get_app_cookies);

sub handler {
    my $r   = shift;
    my $log = $r->pnotes('log');

    $log->debug("########## FixupHandler ##########");

    #Bypass ResponseHandler and use mod_proxy
    if ( $r->pnotes('url_to_mod_proxy') ) {
        $r->set_handlers( PerlResponseHandler => undef );
        return proxy_redirect( $r, $log, $r->pnotes('url_to_mod_proxy') );
    }
}

sub proxy_redirect {
    my ( $r, $log, $url ) = @_;

    my $app = $r->pnotes('app');
    my $mc_conf = $r->pnotes('mc_conf');
    my (%session_app);
    Core::VultureUtils::session( \%session_app, $app->{timeout},
        $r->pnotes('id_session_app'),
        $log, $mc_conf, $app->{update_access_time} );

    $log->debug( "Mod_proxy is working. Redirecting to " . $url );

    #Cleaning up cookies
    #Don't send VultureApp && VultureProxy cookies
    my $cleaned_cookies = Core::VultureUtils::get_app_cookies($r);
    $r->headers_in->unset( "Cookie");
    $r->headers_in->set( "Cookie" => $cleaned_cookies ) if ($cleaned_cookies);
    $session_app{cookie} = $cleaned_cookies;
    #Not canonicalising url (i.e : not escaping chars)
    if ( not $app->{'canonicalise_url'} ) {
        $log->debug("Skipping url canonicalising");
        my $n = $r->notes();
        $n->add( "proxy-nocanon" => "1" );
    }
    if ($app->{'is_jk'}) {
        $r->proxyreq(0);
        $r->handler('jakarta-servlet');
    } else {
        $r->filename( "proxy:" . $url );
        $r->proxyreq(2);
        $r->handler('proxy-server');
    }
    return Apache2::Const::OK;
}
1;
