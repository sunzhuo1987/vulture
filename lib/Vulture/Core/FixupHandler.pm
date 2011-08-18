#file:Core/FixupHandler.pm
#---------------------------------
package Core::FixupHandler;
  
use Apache2::Access ();
use Apache2::Reload;
use Apache2::RequestUtil ();
use Apache2::Log;

use Apache2::Const -compile => qw(OK);
use Apache::SSLLookup;

sub handler {
	my $r = Apache::SSLLookup->new(shift);
	my $log = $r->pnotes('log');

	$log->debug("########## FixupHandler ##########");
	
	#Bypass ResponseHandler and use mod_proxy
	if($r->pnotes('url_to_mod_proxy')){
		$r->set_handlers(PerlResponseHandler => undef);
		return proxy_redirect($r, $log, $r->pnotes('url_to_mod_proxy'));
	}
}

sub proxy_redirect {
	my ($r, $log, $url) = @_;

	my $app = $r->pnotes('app');

	$log->debug("Mod_proxy is working. Redirecting to ".$url);

	$r->err_headers_out->set('Host' => $app->{'url'});
	
	$r->proxyreq(2);
	#$r->uri($url);
	$r->filename("proxy:".$url);
	$r->handler('proxy-server');
	return Apache2::Const::OK;
}

1;
