#file:Plugin/Plugin_REDIRECT_IF_REFERER.pm
#-------------------------
package Plugin::Plugin_REDIRECT_IF_REFERER;

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

    $log->debug("########## Plugin_REDIRECT_IF_REFERER ##########");
    my $mc_conf         = $r->pnotes('mc_conf');
    my $SSO_cookie_name = get_cookie( $r->headers_in->{Cookie},
        $r->dir_config('VultureProxyCookieName') . '=([^;]*)' )|| '';
    my (%session_SSO);
    session( \%session_SSO, $intf->{sso_timeout}, $SSO_cookie_name, $log,
        $mc_conf, $intf->{sso_update_access_time} );
    my $SSO_cookie_app_name = get_cookie( $r->headers_in->{Cookie},
        $r->dir_config('VultureAppCookieName') . '=([^;]*)' )|| '';


    $log->debug("Referer: ".$r->headers_in->{'Referer'});

    #Nothing to do if no REFERER
    if (!length($r->headers_in->{'Referer'}))
    {
        $log->debug("Empty Referer, nothing to do");
        return undef;
    }
    elsif($options =~ /([^\s]+)\s+=>\s+([^\s]+)/){
        my $motif 	= $1;
	my $rewrite 	= $2;

	unless ($r->headers_in->{'Referer'} =~ /$motif/) {
    		$log->debug("Referer do not match REGEX: " . $motif );
		return undef;
	}

        my (@replace) = $r->headers_in->{'Referer'} =~ /$motif/;
        my $i = 1;
        foreach (@replace) {
            $rewrite =~ s/\$$i/$_/ig;
            $i++;
        }

	if ($rewrite eq $r->headers_in->{'Referer'}) {
		$log->debug("Referer not matching");
		return undef;
	}

        #Redirect
    	$log->debug("Found a matching Referer: Redirecting to $rewrite");

    	#Display result in ResponseHandler
	    $r->pnotes( 'response_content' =>
            "<html><head><meta http-equiv=\"Refresh\" content=\"0; url='" 
          . $rewrite
          . "'\"/></head></html>");
	    $r->pnotes( 'response_content_type' => 'text/html' );

	    #Destroy useless handlers
	    $r->set_handlers( PerlAuthenHandler => undef );
	    $r->set_handlers( PerlAuthzHandler  => undef );
	    $r->set_handlers( PerlFixupHandler  => undef );

	    #Bypass TransHandler
	    return Apache2::Const::OK;

    }

    $log->debug("PLUGIN_IF_REFERER:: Error !!");
    return undef;    
   

}

1;
