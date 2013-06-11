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
  qw(&get_cookie &session &get_memcached &set_memcached &notify &get_translations &get_style);

use Apache2::Const -compile => qw(OK FORBIDDEN REDIRECT);

use DBI;

use Apache::SSLLookup;
use LWP::UserAgent;

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;
    $r = Apache::SSLLookup->new($r);
    my $mc_conf = $r->pnotes('mc_conf');
    my %headers_vars = (
        2  => 'SSL_CLIENT_I_DN',
        3  => 'SSL_CLIENT_M_SERIAL',
        4  => 'SSL_CLIENT_S_DN',
        5  => 'SSL_CLIENT_V_START',
        6  => 'SSL_CLIENT_V_END',
        7  => 'SSL_CLIENT_S_DN_C',
        8  => 'SSL_CLIENT_S_DN_ST',
        9  => 'SSL_CLIENT_S_DN_Email',
        10 => 'SSL_CLIENT_S_DN_L',
        11 => 'SSL_CLIENT_S_DN_O',
        12 => 'SSL_CLIENT_S_DN_OU',
        13 => 'SSL_CLIENT_S_DN_CN',
        14 => 'SSL_CLIENT_S_DN_T',
        15 => 'SSL_CLIENT_S_DN_I',
        16 => 'SSL_CLIENT_S_DN_G',
        17 => 'SSL_CLIENT_S_DN_S',
        18 => 'SSL_CLIENT_S_DN_D',
        19 => 'SSL_CLIENT_S_DN_UID',
    );

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

            notify( $dbh, $id_app, $session_SSO{username}, 'deconnection',
                scalar( keys %users ) );

            #Getting url to logout
            my $query =
"SELECT app.name, app.id, url, remote_proxy, logout_url FROM app, intf WHERE app.name = ? AND intf.id = ?";
            $log->debug($query);
            my $sth = $dbh->prepare($query);
            $log->debug( $intf->{id} );
            $sth->execute( $current_app{'app_name'}, $intf->{id} );
            my ( $host, $app_id, $url, $remote_proxy, $logout_url ) =
              $sth->fetchrow_array;
            if ( $url and $logout_url ) {

                #Setting fake user agent
                my ( $ua, $response, $request );
                $ua = LWP::UserAgent->new;

                #Setting proxy if needed
                if ( $remote_proxy ne '' ) {
                    $ua->proxy( [ 'http', 'https' ], $remote_proxy );
                }

                #Setting request
                $request = HTTP::Request->new( 'GET', $url . $logout_url );

                #Setting headers
                $request->remove_header('User-Agent');
                $request->push_header(
                    'User-Agent' => $r->headers_in->{'User-Agent'} );
                #Pushing cookies
                $request->remove_header( 'Cookie');
                $request->push_header( 'Cookie' => $r->headers_in->{'Cookie'});

                my $sth =
                  $dbh->prepare("SELECT name, type, value FROM header WHERE app_id= ?");
                $sth->execute( $app_id );

                #Push specific headers to get the right form
                while ( my ( $h_name, $h_type, $h_value ) = $sth->fetchrow ) {
                    if ( $h_type eq "REMOTE_ADDR" ) {
                        $h_value = $r->connection->remote_ip;

                        #Nothing to do
                    }
                    elsif ( $h_type eq "CUSTOM" ) {

                        #Types related to SSL
                    }
                    else {
                        $h_value = $r->ssl_lookup( $headers_vars{$h_type} )
                          if ( exists $headers_vars{$h_type} );
                    }

                    #Try to push custom headers
                    eval {
                        $log->debug("Pushing custom header $h_name => $h_value");
                        $request->remove_header($h_name);
                        $request->push_header($h_name => $h_value);
                    };
                }
                $sth->finish();

                #Getting response
                $response = $ua->request($request);

                #Render cookie
                my %cookies_app;
                if ( $response->headers->header('Set-Cookie') ) {

                    # Adding new couples (name, value) thanks to POST response
                    foreach my $c ( $response->headers->header('Set-Cookie') ) {
                        my $tc = Core::VultureUtils::parse_set_cookie($c);
                        $cookies_app{$tc->{"name"}} = $tc;
                        $log->debug("ADD/REPLACE" . $tc->{"name"} . "=" . $tc->{"value"});
                    }

                    #Fill session with cookies returned by app (for logout)
                    $session_app{cookie} =
                      $response->headers->header('Set-Cookie');
                }
                my $path = "/";
                if ( $current_app{app_name} =~ /(.*)\/(.*)/ ) {
                    $path = $path . $2;
                }
                foreach my $k ( keys %cookies_app ) {
                    $r->err_headers_out->add( 'Set-Cookie' => $k . "="
                          . $cookies_app{$k}
                          . "; domain="
                          . $r->hostname()
                          . "; path="
                          . $path
                          . "; expires="
                          . $cookies_app{$k}->{"expires"}
                          . "" );    # Send cookies to browser's client
                    $log->debug( "PROPAG " . $k . "=" . $cookies_app{$k} );
                }

                if ( $response->code =~ /^30[0-9]/ )
                {                    #On gère les redirections de type 30x
                    $r->err_headers_out->set(
                        'Location' => $response->headers->header('Location') );
                }
            }

            #End query
            $sth->finish();

            #Delete current session
            tied(%current_app)->delete();
        }
    }

    #Logout from SSO
    tied(%session_SSO)->delete();

    #};

    #Debug for eval
    $log->debug($@) if $@;

    #Destroy useless handlers
    $r->set_handlers( PerlAccessHandler => undef );
    $r->set_handlers( PerlAuthenHandler => undef );
    $r->set_handlers( PerlAuthzHandler  => undef );
    $r->set_handlers( PerlFixupHandler  => undef );

    my $translations = get_translations( $r, $log, $dbh, "DISCONNECTED" );

#If no html, send form
#    my $html = get_style($r, $log, $dbh, $app, 'LOGOUT', 'Logout from Vulture', {FORM => ''}, $translations);
    $options ||= "/";
    $r->pnotes( 'response_content' =>
            "<html><head><meta http-equiv=\"Refresh\" content=\"0; url='" 
          . $options
          . "'\"/></head></html>");

    #    $r->pnotes('response_content' => $html);
    $r->pnotes( 'response_content_type' => 'text/html' );
    return Apache2::Const::OK;
}

1;
