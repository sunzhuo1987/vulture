#file:Plugin/Plugin_REWRITE.pm
#-------------------------
#!/usr/bin/perl
package Plugin::Plugin_REWRITE;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA = qw(Exporter);
    our @EXPORT_OK = qw(&plugin);
}

use Apache2::Log;
use Apache2::Reload;

use Apache2::Const -compile => qw(REDIRECT);

sub plugin{
	my ($package_name, $r, $log, $dbh, $intf, $app, $options) = @_;
	
	$log->debug("########## Plugin_REWRITE ##########");

	#Parse options
	#Mod proxy
	if(@$options[2] =~ /(.+)\s\[P\]/){
		my $rewrite = $1;
		my(@replace) = $r->uri =~ /@$options[0]/;
		my $i = 1;
		foreach (@replace) {
			$rewrite =~ s/\$$i/$_/ig;
			$i++;
		}
		if ($rewrite =~ /^(http|https):\/\//) {
			$r->pnotes('url_to_mod_proxy' => $rewrite);
		}
		else {
			$r->pnotes('url_to_mod_proxy' => $app->{'url'}.$rewrite);
		}
		$log->debug("Getting url to mod_proxy");
		return undef;

	#Redirect
	} elsif(@$options[2] =~ /(.+)\[R\]/){
		my $rewrite = $1;
		my(@replace) = $r->uri =~ /@$options[0]/;
		my $i = 1;
		foreach (@replace) {
			$rewrite =~ s/\$$i/$_/ig;
			$i++;
		}
	    $log->debug("Redirecting to ".$rewrite);
		$r->err_headers_out->set('Location' => $rewrite);
		return Apache2::Const::REDIRECT;
	}
}

1;
