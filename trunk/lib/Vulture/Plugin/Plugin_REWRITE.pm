#file:Plugin/Plugin_REWRITE.pm
#-------------------------
#!/usr/bin/perl
package Plugin::Plugin_REWRITE;

use strict;
use warnings;

use Apache2::Log;
use Apache2::Reload;

use Apache2::Const -compile => qw(DECLINED REDIRECT);

sub plugin{
	my ($package_name, $r, $log, $dbh, $intf, $app, $options) = @_;
	
	$log->debug("########## Plugin_REWRITE ##########");

	#Parse options
	#Mod proxy
	if($options =~ /(.+)\[P\]/){

		#Mod_proxy with apache : user will not see anything
		$log->debug("Getting url to mod_proxy");
		$r->pnotes('url_to_mod_proxy' => $app->{'url'}.$1);
		return undef;

	#Redirect
	} elsif($options =~ /(.+)\[R\]/){
	    $log->debug("Redirecting to ".$1);
		$r->err_headers_out->set('Location' => $1);
		return Apache2::Const::REDIRECT;
	}
}

1;
