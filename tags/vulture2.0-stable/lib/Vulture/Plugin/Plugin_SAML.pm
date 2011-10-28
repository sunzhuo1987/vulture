#file:Plugin/Plugin_SAML.pm
#-------------------------
package Plugin::Plugin_SAML;

use Apache2::Log;
use Apache2::Reload;

use Core::VultureUtils qw(&session &get_memcached &set_memcached);

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub plugin{
	my ($package_name, $r, $log, $dbh, $app, $options) = @_;
	
	$log->debug("########## Plugin_SAML ##########");

	my ($action, $app_name, $intf_id, $login, $password);
	my $req = Apache2::Request->new($r);	
	
	#Get parameters	
	$action = $req->param('action');
	$app_name = $req->param('app_name');
	$login = $req->param('login');

	#Get memcached data
	my (%users);
	%users = %{get_memcached('vulture_users_in')};

	if(not($action) or not($login)){
		return Apache2::Const::FORBIDDEN;
	}

	#Check if user is logged in SSO portal
	if($action eq 'is_logged'){
		$log->debug("Check if user $login is logged in SSO portal");
		my $xml = "<xml><is_logged>";
		if(exists $users{$login}){
			$xml .= "true";
		} else {
			$xml .= "false";		
		}
		$xml .= "</is_logged></xml>";
		$r->pnotes('response_content' => $xml);
        $r->pnotes('response_content_type' => 'text/xml');
		
	#Check if user is logged in application
	} elsif($action eq 'is_logged_app'){
		$log->debug("Check if user $login is logged in application $app_name");
		my $xml = "<xml><is_logged>";
		if(not($app_name)){
			return Apache2::Const::FORBIDDEN;		
		}
		if(defined $users{$login}){

			#Taking user identity			
			my (%user_session_SSO);
			session(\%user_session_SSO, undef, $users{$login});
			if(defined $user_session_SSO{$app_name}){
				$xml .= "true";			
			} else {
				$xml .= "false";			
			}
		} else {
			$xml .= "false";		
		}
		$xml .= "</is_logged></xml>";
		$r->pnotes('response_content' => $xml);
        $r->pnotes('response_content_type' => 'text/xml');

	#Logout user
	} elsif($action eq 'logout'){
		$log->debug("Logout user $login from SSO portal");
		#If user is currently logged		
		if(defined $users{$login}){
			
			#Logout taking user identity			
			my (%user_session_SSO);
			session(\%user_session_SSO, undef, $users{$login});
			$user_session_SSO{is_auth} = 0;

			#Deleting session from Memcached
			delete $users{$login};
		}
	
	#Logout user from application
	} elsif($action eq 'logout_app'){
		$log->debug("Logout user $login from application $app_name");
		if(not($app_name)){
			return Apache2::Const::FORBIDDEN;		
		}
		if(defined $users{$login}){

			#Taking user identity			
			my (%user_session_SSO);
			session(\%user_session_SSO, undef, $users{$login});
			if(defined $user_session_SSO{$app_name}){
				my (%user_session_app);
				session(\%user_session_app, undef, $user_session_SSO{$app_name});
				$user_session_app{is_auth} = 0;	
			}
		}

	#Nothing
	} else {
		return Apache2::Const::FORBIDDEN;
	}

	#Commit changes
	set_memcached('vulture_users_in', \%users);
    
    #Destroy useless handlers
    $r->set_handlers(PerlAuthenHandler => undef);
    $r->set_handlers(PerlAuthzHandler => undef);
    $r->set_handlers(PerlFixupHandler => undef);
	return Apache2::Const::OK;
}

1;
