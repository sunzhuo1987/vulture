#file:Core/AuthenHandler.pm
#---------------------------------
package Core::AuthenHandler;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Connection ();
use Apache2::Log;
use Apache2::Reload;
use Apache2::Access;

use Module::Load;

use Apache2::Const -compile => qw(OK HTTP_UNAUTHORIZED);

use Core::VultureUtils qw(&session &get_memcached &set_memcached);

sub handler {
	my $r = shift;

	my $log = $r->pnotes('log');
	my $dbh = $r->pnotes('dbh');
	my $app = $r->pnotes('app');

	my (%session_SSO);
	session(\%session_SSO, $app->{timeout}, $r->pnotes('id_session_SSO'));

	my ($status, $password);
	my $user;

	$log->debug("########## AuthenHandler ##########");


	#Basic authentification
    if($app and $app->{'auth_basic'}){
           $log->debug('Basic mode');
           ($status, $password) = $r->get_basic_auth_pw;
           $user = $r->user;
	}
	#Get user/password from URL or POST method
	elsif($r->method eq "POST"){
		($user, $password) = getPOSTdata($r);
	} elsif($r->method eq "GET"){
		($user, $password) = getGETdata($r);
	} else {
	}

	#Check if credentials are good. If they are, give a vulture_proxy cookie and go to AuthzHandler for a vulture_app cookie		
	if($session_SSO{is_auth}){
		$log->debug("User is already authorized to access this SSO");

		$r->pnotes('username' => $session_SSO{username});
		$r->pnotes('password' => $session_SSO{password});

		#Authentified, cookie is valid, let user go and check ACL (next step)
		return Apache2::Const::OK;
	
	#Not authentified
	} else {
		my $auths = $app->{'auth'};
		if ($app and defined @$auths and @$auths){
			
			#Check type and use good auth module
			my $ret = Apache2::Const::HTTP_UNAUTHORIZED;

			$ret = multipleAuth($r, $log, $dbh, $app, $user, $password, $app->{auth_id_method}) if ($user);

			if(defined $ret and $ret == scalar Apache2::Const::OK){
				$log->debug("Good user/password");
				
				#Setting user for AuthzHandler
				$r->pnotes('username' => $user);
				$r->pnotes('password' => $password);

				$r->err_headers_out->add('Set-Cookie' => "vulture_proxy=".$r->pnotes('id_session_SSO')."; path=/; domain=".$r->hostname);
				$log->debug('Set-Cookie' => "vulture_proxy=".$r->pnotes('id_session_SSO')."; path=/; domain=".$r->hostname);
		
				$log->debug('Validate SSO session');
				$session_SSO{is_auth} = 1;
				$session_SSO{username} = $user;
				$session_SSO{password} = $password;

				#Setting Memcached table (ex: SAML)
				#my (%users);
				#%users = %{get_memcached('vulture_users_in')};
				#$users{$user} = $r->pnotes('id_session_SSO');
				#set_memcached('vulture_users_in', \%users);
			
				return Apache2::Const::OK;	
			} else {
				$r->user(undef);
				$log->debug("Wrong user/password") if ($password and $user);
				$r->pnotes('auth_message' => 'L\'authentification a échouée') if ($password and $user);
				
				#Unfinite loop for basic auth
				if($app and $app->{'auth_basic'}){
					$r->note_basic_auth_failure;
					return Apache2::Const::HTTP_UNAUTHORIZED; 
				} else {
					$log->debug("No user / password... ask response handler to display the logon form");
					return Apache2::Const::OK;
				}
			}
		}	
	}
	return Apache2::Const::HTTP_UNAUTHORIZED;
}

sub getGETdata {
	my ($r) = @_;
	my $req = Apache2::Request->new($r);
	my $login = $req->param('vulture_login');
	my $password = $req->param('vulture_password');

	return ($login, $password);
}

sub getPOSTdata {
	my ($r) = @_;
	my $req = Apache2::Request->new($r);
	my $login = $req->param('vulture_login');
	my $password = $req->param('vulture_password');

	return ($login, $password);
}

sub multipleAuth {
    my ($r, $log, $dbh, $app, $user, $password, $id_method) = @_;
    
    my $ret = Apache2::Const::FORBIDDEN;
	my $auths = $app->{'auth'};
	foreach my $row (@$auths) {
		my $module_name = "Auth::Auth_".uc(@$row[1]);

        $log->debug($module_name);

		load $module_name;
				
		#Get return
		$ret = $module_name->checkAuth($r, $log, $dbh, $app, $user, $password, @$row[2]);

		return Apache2::Const::OK if $ret == Apache2::Const::OK;
	}
	#No auth found
	return Apache2::Const::FORBIDDEN;
}

1;
