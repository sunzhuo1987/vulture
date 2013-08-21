#file:Plugin/Plugin_LOGOUT_BROWSER.pm
#-------------------------
#!/usr/bin/perl

package Plugin::Plugin_LOGOUT_BROWSER;

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
  qw(&get_cookie &session &get_memcached &set_memcached &notify &get_translations &get_style &parse_cookies);
use Apache2::Const -compile => qw(OK FORBIDDEN REDIRECT);
use Apache::SSLLookup;
use LWP::UserAgent;

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;
    $r = Apache::SSLLookup->new($r);
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
    my $mc_conf = $r->pnotes('mc_conf');

    $log->debug("########## Plugin_LOGOUT_BROWSER ".$app->{name}."##########");

    my $cookies = $r->headers_in->{Cookie};

    # Getting server side logout informations
    my $query = ( "SELECT name, url, remote_proxy, logout_url FROM app WHERE app.name = ?");
    my $sth = $dbh->prepare($query);
    $sth->execute( $app->{'name'} );
    my ( $host, $url, $remote_proxy, $logout_url ) = $sth->fetchrow_array;
    $sth->finish();

    # Server side logout
    if ( $url and $logout_url ) {
        my $ua = LWP::UserAgent->new;
        if ( $remote_proxy ne '' ) {
            $ua->proxy( [ 'http', 'https' ], $remote_proxy );
        }
        #Create logout request
        my $request = HTTP::Request->new( 'GET', $url . $logout_url );

        #Setting headers
        $request->remove_header('User-Agent');
        $request->push_header('User-Agent' => $r->headers_in->{'User-Agent'});
        #Pushing cookies
        $request->remove_header( 'Cookie');
        $request->push_header( 'Cookie' => $r->headers_in->{'Cookie'});

        my $sth =
          $dbh->prepare("SELECT name, type, value FROM header WHERE app_id= ?");
        $sth->execute( $app->{id} );

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
        #Send logout request
        $ua->request($request);
    }

    my $id_app = get_cookie( $cookies, $r->dir_config('VultureAppCookieName') . '=([^;]*)' );
    my %session_app;
    session( \%session_app, undef, $id_app, undef, $mc_conf );

    notify( $dbh, $app->{id}, $session_app{username}, 'deconnection', 0);
    $session_app{is_auth} = 0;

    my $path = "/";
    if ( $app->{name} =~ /(.*)\/(.*)/ ) {
        $path = "/$2";
    }
    # Retreive current cookies
    my $pc = parse_cookies($cookies);
    $r->err_headers_out->unset('Set-Cookie');
    foreach my $ck (keys(%$pc)){
        # Set cookie expiration in past 
        $r->err_headers_out->add('Set-Cookie' => 
            "$ck=none; path=$path; expires=Thu, 01 Jan 1970 00:00:00 GMT; domain=." . $app->{name});
    }
    tied(%session_app)->delete();

    #Destroy useless handlers
    $r->set_handlers( PerlAccessHandler => undef );
    $r->set_handlers( PerlAuthenHandler => undef );
    $r->set_handlers( PerlAuthzHandler  => undef );
    $r->set_handlers( PerlFixupHandler  => undef );

    # Return empty content or redirect if option
	my $redir = "";
	if ($options){
		$redir = "<meta http-equiv=\"Refresh\" content=\"0; url='$options'\">";
	}
    $r->pnotes( 'response_content' => "<html><head>$redir</head><body></body></html>");
    $r->pnotes( 'response_content_type' => 'text/html' );
    return Apache2::Const::OK;
}
1;
