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
  qw(&get_cookie &session &get_memcached &set_memcached &notify &get_translations &get_style);
use Apache2::Const -compile => qw(OK FORBIDDEN REDIRECT);
use LWP::UserAgent;

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;
    $r = Apache::SSLLookup->new($r);
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
        $request->push_header('User-Agent' => $r->headers_in->{'User-Agent'} );
        $request->push_header('Cookie' => $cookies );
#        $request->push_header('Host' => $host );

        #Send logout request
        $ua->request($request);
    }

    my $id_app = get_cookie( $cookies, $r->dir_config('VultureAppCookieName') . '=([^;]*)' );
    my %session_app;
    session( \%session_app, undef, $id_app, undef, $mc_conf );
    $session_app{is_auth} = 0;

    my $path = "/";
    if ( $app->{name} =~ /(.*)\/(.*)/ ) {
        $path = "/$2";
    }
    # Retreive current cookies
    my $pc = parse_set_cookie($cookies);
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

    # Return empty iframe content
    $r->pnotes( 'response_content' => '<html><head></head><body></body></html>');
    $r->pnotes( 'response_content_type' => 'text/html' );
    return Apache2::Const::OK;
}
sub parse_set_cookie{
        my $sc = shift;
        my $tab = {};
        foreach my $v (split (';',$sc)) {
            my ($t,$u) = split ('=',$v);
            $tab->{trim($t)} = $u;
        }
        return $tab;
}
sub trim{
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    return $string;
}
1;
