#file:Core/AuthzHandler.pm
#---------------------------------
package Core::AuthzHandler;
  
use Apache2::Access ();
use Apache2::Reload;
use Apache2::RequestUtil ();
use Apache2::Log;

use DBI;

use Module::Load;

use Apache2::Const -compile => qw(OK HTTP_UNAUTHORIZED);

use Core::VultureUtils qw(&session);

sub handler {
	my $r = shift;

	my $log = $r->pnotes('log');

	$log->debug("########## AuthzHandler ##########");

	#If an user was set and if he is authorized, then give him a cookie for this app
	my $user = $r->pnotes('username') || $r->user ;
	my $password = $r->pnotes('password');
	my $dbh = $r->pnotes('dbh');
	my $app = $r->pnotes('app');

	#Session data
	my (%session_app);
	session(\%session_app, $app->{timeout}, $r->pnotes('id_session_app'), $log, $app->{update_access_time});
	my (%session_SSO);
	session(\%session_SSO, $app->{timeout}, $r->pnotes('id_session_SSO'), $log, $app->{update_access_time});

	#Bypass for Vulture Auth
	if(not $session_SSO{is_auth} and not $r->user){
		$log->debug("Bypass AuthzHandler because SSO session is not valid");
		return Apache2::Const::OK;	
	}

	#If user has valid app cookie
	if($session_app{is_auth}){
		$log->debug("User is already authorized to access this app");
		return Apache2::Const::OK;	
	}

	#Get app info coming from TransHandlerv2
	if($app and $app->{'id'}){ 
		
		#Check if ACL is on. If not, let user go.
        		
		if($app->{'acl'}){
			
			#If user was set by AuthenHandler, then check his credentials			
			if ($user){			
				my $module_name = "ACL::ACL_".uc($app->{'acl'}->{'acl_type'});
			
				load $module_name;
				
				#Get return
				$ret = $module_name->checkACL($r, $log, $dbh, $app, $user, $app->{'acl'}->{'id_method'});
	
				#Debug for eval				
				$log->debug($@) if $@;
				
				if (defined $ret and $ret == scalar Apache2::Const::OK){
					$log->debug("User $user has credentials for this app regarding ACL. Validate app session");

					#Setting app session
					$session_app{is_auth} = 1;
					$session_app{username} = $user;
					$session_app{password} = $password;
			
					#Backward logout
					$session_app{SSO} = $r->pnotes('id_session_SSO');

					#SSO must be warned that user is logged in this app (ex : SAML)
					$session_SSO{$app->{'name'}} = $r->pnotes('id_session_app');

					$log->debug("Validate app session");
					return Apache2::Const::OK;
				} else {
					$log->debug("Regarding to ACL, user is not authorized to access to this app.");
					
					$session_app{is_auth} = 0;
					$r->pnotes('username' => undef);
					$r->pnotes('password' => undef);
					return Apache2::Const::HTTP_UNAUTHORIZED;
				}
			}
			return Apache2::Const::HTTP_UNAUTHORIZED;
		} else {
			$log->debug("No ACL in this app. Validate app session for user $user");
			
			#Setting app session
			$session_app{is_auth} = 1;
			$session_app{username} = $user;
			$session_app{password} = $password;

			#Backward logout
			$session_app{SSO} = $r->pnotes('id_session_SSO');

			#SSO must be warned that user is logged in this app (ex : SAML)
			$session_SSO{$app->{'name'}} = $r->pnotes('id_session_app');
			
			return Apache2::Const::OK;
		}
	} else {
		$log->debug("App is undef in AuthzHandler");
		$r->pnotes('username' => undef);
		$r->pnotes('password' => undef);
		return Apache2::Const::HTTP_UNAUTHORIZED;	
	}
	return Apache2::Const::HTTP_UNAUTHORIZED;
}

1;
