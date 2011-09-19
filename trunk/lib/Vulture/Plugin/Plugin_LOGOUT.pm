#file:Plugin/Plugin_LOGOUT.pm
#-------------------------
package Plugin::Plugin_LOGOUT;

use Apache2::Log;
use Apache2::Reload;

use Core::VultureUtils qw(&get_cookie &session);

use Apache2::Const -compile => qw(OK FORBIDDEN REDIRECT);

use DBI;

use LWP::UserAgent;

use Apache::SSLLookup;

sub plugin{
	my ($package_name, $r, $log, $dbh, $app, $options) = @_;

	my $r = Apache::SSLLookup->new($r);
	
	$log->debug("########## Plugin_LOGOUT ##########");

	#Taking user identity
	my ($id_app) = get_cookie($r->headers_in->{Cookie}, 'vulture_app=([^;]*)') || return Apache2::Const::FORBIDDEN;
	

	eval{
		my (%session_app);
		session(\%session_app, undef, $id_app);

		my (%session_SSO);
		session(\%session_SSO, undef, $session_app{SSO});

		foreach my $key (keys %session_SSO){
			if($key ne 'is_auth' and $key ne 'username'){ 
				my $id_app = $session_SSO{$key};
				my (%current_app);
				session(\%current_app, undef, $id_app);

				
				
				#Getting url to logout
				my $query = "SELECT url, intf.remote_proxy, logout_url FROM app, intf WHERE app.name = '".$current_app{app_name}."' AND intf.id = app.intf_id";
				$sth = $dbh->prepare($query);
				$sth->execute;
				if(my ($url, $remote_proxy, $logout_url) = $sth->fetchrow_array){
					#Setting fake user agent
					my ($ua, $response, $request);
					$ua = LWP::UserAgent->new;

					#Setting proxy if needed
					if ($app->{remote_proxy} ne ''){
						$ua->proxy(['http', 'https'], $remote_proxy);
					}

					#Setting request
					$request = HTTP::Request->new('GET', $url.$logout_url);

					#Setting headers
					$request->push_header('Cookie' => $current_app{cookie});
					$request->push_header('User-Agent' => $r->headers_in->{'User-Agent'});
					$request->push_header('Host' => $host);

					$log->debug($request->as_string);	

					#Getting response
					$response = $ua->request($request);

					if ($response->code =~ /^30(.*)/ ) { #On gère les redirections de type 30x
						$r->err_headers_out->set('Location' => $response->headers->header('Location'));
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
	};

	#Debug for eval
	$log->debug ($@) if $@;

	#Destroy useless handlers
	$r->set_handlers(PerlAccessHandler => undef);
	$r->set_handlers(PerlAuthenHandler => undef);
	$r->set_handlers(PerlAuthzHandler => undef);
	$r->set_handlers(PerlFixupHandler => undef);
	$r->set_handlers(PerlResponseHandler => undef);

	return Apache2::Const::REDIRECT;
}

1;
