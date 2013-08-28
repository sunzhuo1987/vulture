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
  qw(&get_cookie &session &notify &parse_cookies &get_ua_object &get_http_request);
use Apache2::Const -compile => qw(OK FORBIDDEN REDIRECT);

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;
    my $mc_conf = $r->pnotes('mc_conf');

    $log->debug("########## Plugin_LOGOUT_BROWSER ".$app->{name}."##########");

    my $cookies = $r->headers_in->{Cookie};

    my $id_app = get_cookie( $cookies, $r->dir_config('VultureAppCookieName') . '=([^;]*)' );
    my %session_app;
    session( \%session_app, undef, $id_app, undef, $mc_conf );

    # Getting server side logout informations
    my $query = ( "SELECT url, remote_proxy, logout_url FROM app WHERE app.name = ?");
    my $sth = $dbh->prepare($query);
    $sth->execute( $app->{'name'} );
    my ( $url, $remote_proxy, $logout_url ) = $sth->fetchrow_array;

    # Server side logout
    if ( $url and $logout_url ) {
        #Create logout request
        my $ua = Core::VultureUtils::get_ua_object($r, $remote_proxy);
        my $request = Core::VultureUtils::get_http_request($r, $dbh, $app->{id}, 'GET', $url . $logout_url);
        if (exists $session_app{cookie} and $session_app{cookie}){
            $request->remove_header('cookie');
            $request->push_header( 'Cookie' => $session_app{cookie} );
        }
        #Send logout request
        $ua->request($request);
    }

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
