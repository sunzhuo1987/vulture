#file:Plugin/Plugin_LOGOUT_CAS.pm
#-------------------------
#!/usr/bin/perl
package Plugin::Plugin_LOGOUT_CAS;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&plugin);
}

use Apache2::Log;
use Apache2::Reload;
use Apache2::Request;
use APR::URI;
use XML::LibXML;
use Try::Tiny;
use POSIX;
use Core::VultureUtils
  qw(&session &get_memcached &set_memcached &get_cookie &get_app &get_LDAP_field &get_SQL_field &get_ua_object &get_http_request);

sub trim {
    my $arg = shift;
    $arg =~ s/^\s+//;
    $arg =~ s/\s+$//;
    return $arg;
}
sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;
    
    # Get ticket from CAS request
    $log->debug("################### Plugin_LOGOUT_CAS ############");
    my $req      = Apache2::Request->new($r);
    my $posted = $req->param('logoutRequest');

    my $parser   = XML::LibXML->new;
    my $badquery = 0;
    my $status   = "Success";
    my $ticket	 = '';
    my $mc_conf  = $r->pnotes('mc_conf');
    #Logout from Memcached vulture_users_in
    my (%users);

    %users = %{ get_memcached( 'vulture_users_in', $mc_conf ) || {} };

    try {
        my $xmlreq = $parser->load_xml( string => $posted );
        my $xpc = XML::LibXML::XPathContext->new($xmlreq);
        $xpc->registerNs( "samlp",
            "urn:oasis:names:tc:SAML:2.0:protocol" );

        $ticket =
          trim( $xpc->findvalue("//samlp:SessionIndex") );
        $log->debug("Found valid request and ticket : $ticket");
        if ($ticket eq '') {
            $status = "No valid request. no valid ticket";
            $badquery = 1;
        }
    }

    catch {
        $status   = "No valid request. Catch an error";
        $badquery = 1;
    };
    if ($badquery == 0) {
        #Disconnect all
        my $session_id =  Core::VultureUtils::get_memcached($ticket,$mc_conf);
        $log->debug("Found session id : $session_id corresponding to CAS ticket $ticket ");
        my (%session_SSO);
        Core::VultureUtils::session( \%session_SSO, undef, $session_id,
                 $log, $mc_conf );

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
    "SELECT app.id, app.name, url, remote_proxy, logout_url FROM app, intf WHERE app.name = ? AND intf.id = ?";
                $log->debug($query);
                my $sth = $dbh->prepare($query);
                $log->debug( $intf->{id} );
                $sth->execute( $current_app{'app_name'}, $intf->{id} );
                my ( $app_id, $host, $url, $remote_proxy, $logout_url ) =
                  $sth->fetchrow_array;

                Core::VultureUtils::log_auth_event($log, $app_id, $session_SSO{username}, 'deconnection', 'LOGOUT_CAS');
                if ( $url and $logout_url ) {

                    #Setting fake user agent
                    my ( $ua, $response, $request );
                    $ua = get_ua_object($r, $remote_proxy);
                    $request = get_http_request($r, $dbh, $app_id, 'GET', $url . $logout_url);
                    #Pushing cookies
                    if (exists $current_app{cookie} and $current_app{cookie}){
                        $request->remove_header('cookie');
                        $request->push_header( 'Cookie' => $current_app{cookie} );
                    }
                    #Getting response
                    $response = $ua->request($request);
                    #Render cookie
                    my %cookies_app;
                    my $cookie;
                    if ( $response->headers->header('Set-Cookie') ) {
                    # Adding new couples (name, value) thanks to POST response
                        foreach ( $response->headers->header('Set-Cookie') ) {
                            if (/([^,; ]+)=([^,; ]+)/) {
                                $cookies_app{$1} = $2;    # adding/replace
                                $log->debug( "ADD/REPLACE " . $1 . "=" . $2 );
                            }
                        }
                        #Fill session with cookies returned by app (for logout)
                        $cookie =
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
    } else {
        #do nothing. No session to destroy
        $log->debug("Nothing to do because $status");
    }
}
1;

