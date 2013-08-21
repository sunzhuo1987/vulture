#file:Plugin/Plugin_LOGOUT_ALL.pm
#-------------------------
#!/usr/bin/perl

package Plugin::Plugin_LOGOUT_ALL;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&plugin);

}

use Apache2::Log;
use Apache2::Reload;
use Core::VultureUtils
  qw(&get_cookie &session &get_memcached &set_memcached &notify &get_translations &get_style &parse_set_cookie &get_ua_object &get_http_request);
use Apache2::Const -compile => qw(OK FORBIDDEN REDIRECT);

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;
    my $mc_conf = $r->pnotes('mc_conf');
    $log->debug("########## Plugin_LOGOUT_ALL ##########");

    #Taking user identity
    my ($id_app,$id_sso);
    my (%session_app,%session_SSO);
    
    $id_app = get_cookie( $r->headers_in->{Cookie},
        $r->dir_config('VultureAppCookieName') . '=([^;]*)' );
    if (defined $id_app){
        session( \%session_app, undef, $id_app, undef, $mc_conf );
        $id_sso = $session_app{SSO};
    }
    else{
        $id_sso = get_cookie($r->headers_in->{Cookie},
           $r->dir_config('VultureProxyCookieName').'=([^;]*)'); 
    }
        
    session( \%session_SSO, undef, $id_sso, undef, $mc_conf );

    #Logout from Memcached vulture_users_in
    my (%users);

    %users = %{ get_memcached( 'vulture_users_in', $mc_conf ) || {} };

    delete $users{ $session_SSO{username} };
    set_memcached( 'vulture_users_in', \%users, undef, $mc_conf );

    notify( $dbh, undef, $session_SSO{username}, 'deconnection',
        scalar( keys %users ) );

    #Foreach app where user is currently logged in
    foreach my $key ( keys %session_SSO ) {
        #Reject bad app key
        my @wrong_keys =
          qw/is_auth username url_to_redirect password SSO last_access_time _session_id random_token/;
        unless ( grep $_ eq $key, @wrong_keys ) {
            my $id_app = $session_SSO{$key};

            my (%current_app) = ();
            session( \%current_app, undef, $id_app, undef, $mc_conf );

            #Logout user
            $current_app{'is_auth'} = undef;

            #Getting url to logout
            my $query =
"SELECT app.name, app.id, url, remote_proxy, logout_url FROM app, intf WHERE app.name = ? AND intf.id = ?";
            $log->debug($query);
            my $sth = $dbh->prepare($query);
            $log->debug( $intf->{id} );
            $sth->execute( $current_app{'app_name'}, $intf->{id} );
            my ( $host, $app_id, $url, $remote_proxy, $logout_url ) =
              $sth->fetchrow_array;

            notify( $dbh, $app_id, $session_SSO{username}, 'deconnection',
                scalar( keys %users ) );

            if ( $url and $logout_url ) {
                #Setting fake user agent
                my $ua = Core::VultureUtils::get_ua_object($r, $remote_proxy);
                my $request = Core::VultureUtils::get_http_request($r, $dbh, $app_id, 'GET', $url . $logout_url);
                #Getting response
                my $response = $ua->request($request);
                #Render cookie
                my %cookies_app;
                if ( $response->headers->header('Set-Cookie') ) {
                    # Adding new couples (name, value) thanks to POST response
                    foreach my $c ( $response->headers->header('Set-Cookie') ) {
                        my $tc = parse_set_cookie($c);
                        $cookies_app{$tc->{"name"}} = $tc;
                        $log->debug("ADD/REPLACE" . $tc->{"name"} . "=" . $tc->{"value"});
                    }
                }
                my $path = "/";
                if ( $current_app{app_name} =~ /(.*)\/(.*)/ ) {
                    $path = $path . $2;
                }
                foreach my $k ( keys %cookies_app ) {
                    $r->err_headers_out->add( 'Set-Cookie' => $k . "="
                          . $cookies_app{$k}->{value}
                          . "; domain="
                          . $r->hostname()
                          . "; path="
                          . $path
                          . (( exists $cookies_app{$k}->{"expires"}) ? "; expires=". $cookies_app{$k}->{"expires"}:"")
                         );    # Send cookies to browser's client
                    $log->debug( "PROPAG " . $k . "=" . $cookies_app{$k} );
                }
                if ( $response->code =~ /^30[0-9]/ )
                {                    #On gère les redirections de type 30x
                    $r->err_headers_out->set(
                        'Location' => $response->headers->header('Location') );
                }
            }
            #Delete current session
            tied(%current_app)->delete();
        }
    }
    #Logout from SSO
    tied(%session_SSO)->delete();
    #Destroy useless handlers
    $r->set_handlers( PerlAccessHandler => undef );
    $r->set_handlers( PerlAuthenHandler => undef );
    $r->set_handlers( PerlAuthzHandler  => undef );
    $r->set_handlers( PerlFixupHandler  => undef );
#    my $translations = get_translations( $r, $log, $dbh, "DISCONNECTED" );
#If no html, send form
#    my $html = get_style($r, $log, $dbh, $app, 'LOGOUT', 'Logout from Vulture', {FORM => ''}, $translations);
    $options ||= "/";
    $r->pnotes( 'response_content' =>
            "<html><head><meta http-equiv=\"Refresh\" content=\"0; url='" 
          . $options
          . "'\"/></head></html>");
    $r->pnotes( 'response_content_type' => 'text/html' );
    return Apache2::Const::OK;
}
1;
