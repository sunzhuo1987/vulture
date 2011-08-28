#file:Plugin/Plugin_REWRITE.pm
#-------------------------
package Plugin::Plugin_REWRITE;

use Apache2::Log;
use Apache2::Reload;

use Apache2::Const -compile => qw(DECLINED);

sub plugin{
	my ($package_name, $r, $log, $dbh, $options) = @_;
	
	$log->debug("########## Plugin_REWRITE ##########");

	#Parse options
	#Mod proxy
	if($options =~ /(.+)\[P\]/){

		#Mod_proxy with apache : user will not see anything
		$log->debug("Getting url to mod_proxy");
		$r->pnotes('url_to_mod_proxy' => 'http://'.$r->hostname.':'.$r->get_server_port.$1);
		return Apache2::Const::OK;

	#Redirect
	} elsif($options =~ /(.+)\[R\]/){
		$r->err_headers_out->set('Location' => 'http://'.$r->hostname.':'.$r->get_server_port.$1);
		return Apache2::Const::REDIRECT;
	}
}

1;
