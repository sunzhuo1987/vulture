#file:Plugin/Plugin_REDIRECT_NO_LOG.pm
#-------------------------
#!/usr/bin/perl
package Plugin::Plugin_REDIRECT_NO_LOG;

use strict;
use warnings;

use Core::VultureUtils qw(&session);
use Apache2::Const -compile => qw(OK);


BEGIN {
    use Exporter ();
    our @ISA = qw(Exporter);
    our @EXPORT_OK = qw(&plugin);
}

sub plugin{
	my ($package_name, $r, $log, $dbh, $intf, $app, $options) = @_;
	$log->debug("########## Plugin_REDIRECT_NO_LOG ##########");
	
	#Getting SSO session if exists.
	my $SSO_cookie_name = Core::VultureUtils::get_cookie($r->headers_in->{Cookie}, $r->dir_config('VultureProxyCookieName').'=([^;]*)');
	my (%session_SSO);

	Core::VultureUtils::session(\%session_SSO, $intf->{sso_timeout}, $SSO_cookie_name, $log, $intf->{sso_update_access_time});
	unless ($session_SSO{'is_auth'} and $r->hostname =~ $intf->{'sso_portal'} ) {
		$log->debug("Redirect");
		if($r->unparsed_uri =~ /vulture_app=([^;]*)/){
			my $app_cookie_name = $1;
			my (%session_app);
			#Get app
			Core::VultureUtils::session(\%session_app, $app->{timeout}, $app_cookie_name, $log, $app->{update_access_time});
			my $app = Core::VultureUtils::get_app($log, $session_app{app_name}, $dbh, $intf->{id});
			$log->debug("app is ".$session_app{app_name});
			
			#my @list_options = $options;
			my %hash_options = split /,|=>/, $options;
			my ($k, $v);
			while(($k, $v) = each(%hash_options)){
				#Redirect
				if(trim($session_app{app_name}) eq trim($k)){
	                $r->pnotes('response_content' => '<html><head><meta http-equiv="Refresh" content="0; url='.$v.'"/></head></html>');
					$r->pnotes('response_content_type' => 'text/html');
					
					$r->set_handlers(PerlAuthenHandler => undef);
					$r->set_handlers(PerlAuthzHandler => undef);
					$r->set_handlers(PerlFixupHandler => undef);
					return Apache2::Const::OK;
				}
			}
		}
	}
	
	return undef;
}

sub trim($)
{
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

1;
