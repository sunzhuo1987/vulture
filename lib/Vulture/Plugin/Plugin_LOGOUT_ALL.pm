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

use LWP::UserAgent;

use Apache::SSLLookup;

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;
    $r = Apache::SSLLookup->new($r);
    my $mc_conf = $r->pnotes('mc_conf');

    $log->debug("########## Plugin_LOGOUT_ALL ##########");

    #Taking user identity
    my ($id_app) = get_cookie( $r->headers_in->{Cookie},
        $r->dir_config('VultureAppCookieName') . '=([^;]*)' )
      || return Apache2::Const::FORBIDDEN;

    #eval{
    my (%session_app);
    session( \%session_app, undef, $id_app, undef, $mc_conf );

    my (%session_SSO);
    session( \%session_SSO, undef, $session_app{SSO}, undef, $mc_conf );

    #Logout from Memcached vulture_users_in
    my (%users);

    %users = %{ get_memcached( 'vulture_users_in', $mc_conf ) || {} };
    return Apache2::Const::FORBIDDEN unless ($session_SSO{is_auth});

    delete $users{ $session_SSO{username} };
    set_memcached( 'vulture_users_in', \%users, undef, $mc_conf );

    notify( $dbh, undef, $session_SSO{username}, 'deconnection',
        scalar( keys %users ) );
    $session_app{'is_auth'} = undef;

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
"SELECT app.name, url, remote_proxy, logout_url FROM app, intf WHERE app.name = ? AND intf.id = ?";
            $log->debug($query);
            my $sth = $dbh->prepare($query);
            $log->debug( $intf->{id} );
            $sth->execute( $current_app{'app_name'}, $intf->{id} );
            my ( $host, $url, $remote_proxy, $logout_url ) =
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
                $request->push_header(
                    'User-Agent' => $r->headers_in->{'User-Agent'} );

                #Setting headers
                #Pushing cookies
                $log->debug( $current_app{cookie} );
                $request->push_header( 'Cookie' => $current_app{cookie} );
                $request->push_header( 'Cookie' => $r->headers_in->{'Cookie'});
                $request->push_header(
                    'User-Agent' => $r->headers_in->{'User-Agent'} );
                $request->push_header( 'Host' => $host );

                #Getting response
                $response = $ua->request($request);

                #Render cookie
                my %cookies_app;
                if ( $response->headers->header('Set-Cookie') ) {

                    # Adding new couples (name, value) thanks to POST response
                    foreach ( $response->headers->header('Set-Cookie') ) {
                        if (/([^,; ]+)=([^,; ]+)/) {
                            $cookies_app{$1} = $2;    # adding/replace
                            $log->debug( "ADD/REPLACE " . $1 . "=" . $2 );

                        }
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
                          . "" );    # Send cookies to browser's client
                    $log->debug( "PROPAG " . $k . "=" . $cookies_app{$k} );
                }

                if ( $response->code =~ /^30(.*)/ )
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
