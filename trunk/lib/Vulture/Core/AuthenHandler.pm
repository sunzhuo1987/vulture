#file:Core/AuthenHandler.pm
#---------------------------------
#!/usr/bin/perl
package Core::AuthenHandler;

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Connection ();
use Apache2::Log;
use Apache2::Reload;
use Apache2::Request;
use Apache2::Access;

use Authen::Smb;

use Module::Load;

use Apache2::Const -compile => qw(OK HTTP_UNAUTHORIZED);

use Core::VultureUtils qw(&session &get_memcached &set_memcached &generate_random_string &notify);
use Core::ActionManager qw(&handle_action);

#USED FOR NTLM
sub get_nonce
{
    my ($self,$r,$log,$pdc,$bdc,$domain) = @_ ;

    if ($self -> {nonce})
    {
        $log->debug("Auth_NTLM: get_nonce -> Reuse " . $self -> {nonce});
        return $self -> {nonce};
    }

    my $nonce = '12345678' ;
    $log->debug("Auth_NTLM: Connect to pdc = $pdc bdc = $bdc domain = $domain");
    my $smbhandle = Authen::Smb::Valid_User_Connect ($pdc, $bdc, $domain, $nonce) ;
    if (!$smbhandle)
    {
        $log->debug("Auth_NTLM: Connect to SMB Server failed (pdc = $pdc bdc = $bdc domain = $domain error = "
        . Authen::Smb::SMBlib_errno . '/' . Authen::Smb::SMBlib_SMB_Error . ") for " . $r -> uri) ;
        return undef;
    }
    $log->debug("Auth_NTLM: get_nonce() -> $nonce");
    $self -> {smbhandle} = $smbhandle;
    return $self -> {nonce} = $nonce ;
}


sub handler:method
{
	my ($class, $r) = @_ ;
    my $req = Apache2::Request->new($r);

	my $log = $r->pnotes('log');
	my $dbh = $r->pnotes('dbh');
	my $app = $r->pnotes('app');
    $log->error("App is missing in AuthenHandler") unless $app;
    my $intf = $r->pnotes('intf');

	my (%session_SSO);
	Core::VultureUtils::session(\%session_SSO, $intf->{sso_timeout}, $r->pnotes('id_session_SSO'), $log, $intf->{sso_update_access_time});

	my ($status, $password);
	my $user;
    my $token;

	$log->debug("########## AuthenHandler ##########");

	#Basic authentification
	if(($app and $app->{'auth_basic'}) or ($intf and $intf->{'auth_basic'})){
       $log->debug('Basic mode');
       ($status, $password) = $r->get_basic_auth_pw;
       $user = $r->user;
	}
	#Get user/password from URL or POST method
	elsif($r->method eq "POST" or $r->method eq "GET"){
		($user, $password, $token) = getRequestData($r);
	} else {
	    return Apache2::Const::HTTP_UNAUTHORIZED;
	}

    $log->debug(Dumper(\%session_SSO));
    
    
    #If user is not logged in SSO, skip this code
    #Check if credentials are good. If they are, give a vulture_proxy cookie and go to AuthzHandler for a vulture_app cookie
    if($session_SSO{is_auth}){
        my $diff_count = 0;
        $log->debug("User is logged in SSO. Check if auths are the same");
        #Foreach app where user is currently logged in
        foreach my $key (keys %session_SSO){
            $log->debug($key);

            #Reject bad app key
            my @wrong_keys = qw/is_auth username password last_access_time last_access_time _session_id random_token/;
            unless(grep $_ eq $key, @wrong_keys){ 
                my $id_app = $session_SSO{$key};
                my (%current_app);
                Core::VultureUtils::session(\%current_app, undef, $id_app);

                $log->debug(Dumper(\%current_app));

                #Getting all auths methods used previously to compare with current app auths
                my $query = "SELECT auth.name, auth.auth_type, auth.id_method FROM app, intf, auth, auth_multiple WHERE app.name = ? AND intf.id = ? AND auth_multiple.app_id = app.id AND auth_multiple.auth_id = auth.id";
                $log->debug($query);
                my @auths = @{$dbh->selectall_arrayref($query, undef, $current_app{app_name}, $intf->{id})};
                my @current_auths = @{defined ($app->{'auth'}) ? $app->{'auth'} : $intf->{'auth'}};

                use Data::Dumper;
                $log->debug(Dumper(\@auths));
                $log->debug(Dumper(\@current_auths));
                
                my @difference = ();
                my %count = ();
				my $element;
                foreach $element (@auths, @current_auths) { $count{@$element[0]}++ }
                foreach $element (keys %count) {
                    if (int( $count{$element}) <= 1) {
		   	 push (@{ \@difference }, $element);
		    }
                }
                $log->debug(Dumper(\@difference));

                $log->debug("Before $diff_count");
                $diff_count += scalar @difference;
                $log->debug("Auth not in common $diff_count");
            }
        }
        
        #Same auths
        if($diff_count == 0){
            $log->debug("User is already authorized to access this SSO");

            $r->pnotes('username' => $session_SSO{username});
            $r->pnotes('password' => $session_SSO{password});

            #Setting Memcached table
            my (%users);
            %users = %{Core::VultureUtils::get_memcached('vulture_users_in')};
            $users{$session_SSO{username}} = {'SSO' => $r->pnotes('id_session_SSO')};

            #Generate new service ticket
            my $st = 'ST-'.Core::VultureUtils::generate_random_string(29);
            my $service = $req->param('service');
            if(defined $service){
                $log->debug("Creating new service ticket");
                $users{$session_SSO{username}}->{'ticket'} = $st;
                $users{$session_SSO{username}}->{'ticket_service'} = $service;
                $users{$session_SSO{username}}->{'ticket_created'} = time();
            }
            $r->pnotes('url_to_redirect' => $service.'/?ticket='.$st) if defined $service;
            Core::VultureUtils::set_memcached('vulture_users_in', \%users);

            #Authentified, cookie is valid, let user go and check ACL (next step)
            return Apache2::Const::OK;
        }
    }

	#Not authentified
    
    $log->debug("Try to authenticate user");
    
    #Check type and use good auth module
    my $ret = Apache2::Const::HTTP_UNAUTHORIZED;
    my $ret ||= '';

    my $auths = defined ($app->{'auth'}) ? $app->{'auth'} : $intf->{'auth'};

    my $ntlm = undef;
    my $cas = undef;
    foreach my $row (@$auths) {
        if (uc(@$row[1]) eq "NTLM" ) {
            $ret = multipleAuth($r, $log, $dbh, $auths, $app, $user, $password, $class, 1);
            $ntlm = 1;
            last;
        } elsif (uc(@$row[1]) eq "CAS" ) {
            $log->debug("CAS mode");
            $ret = multipleAuth($r, $log, $dbh, $auths, $app, $user, $password, $class, 1);
            $cas = 1;
            last;
        }
    }

    $ret = multipleAuth($r, $log, $dbh, $auths, $app, $user, $password, 0, 0) if (defined $user and ($token eq $session_SSO{random_token} or $app->{'auth_basic'} or not defined $cas));

    $log->debug("Return from auth => ".$r->pnotes('auth_message')) if defined $r->pnotes('auth_message');

    #Trigger action when change pass is needed / auth failed
    Core::ActionManager::handle_action($r, $log, $dbh, $intf, $app, 'NEED_CHANGE_PASS', 'You need to change your password') if(uc($r->pnotes('auth_message')) eq 'NEED_CHANGE_PASS');
    Core::ActionManager::handle_action($r, $log, $dbh, $intf, $app, 'ACCOUNT_LOCKED', 'You need to unlock your password') if(uc($r->pnotes('auth_message')) eq 'ACCOUNT_LOCKED');
    Core::ActionManager::handle_action($r, $log, $dbh, $intf, $app, 'AUTH_SERVER_FAILURE', 'Vulture can\'t contact authentication server') if(uc($r->pnotes('auth_message')) eq 'AUTH_SERVER_FAILURE');
    Core::ActionManager::handle_action($r, $log, $dbh, $intf, $app, 'LOGIN_FAILED', 'Login failed') if (!$r->pnotes('auth_message') and $ret != scalar Apache2::Const::OK and ($user or $password));


    
    if(defined $ret and $ret == scalar Apache2::Const::OK){
        $log->debug("Good user/password");

        #Get new username and password ... ex : CAS
        $user = $r->pnotes('username') || $r->user() || $user;
        $password = $r->pnotes('password') || $password;

        #Setting user for AuthzHandler
        $r->pnotes('username' => $user);
        $r->pnotes('password' => $password);

        $log->debug('Validate SSO session');
        $session_SSO{is_auth} = 1;
        $session_SSO{username} = $user;
        $session_SSO{password} = $password;

        #Setting Memcached table
        my (%users);
        %users = %{Core::VultureUtils::get_memcached('vulture_users_in') or {}};
        $users{$user} = {'SSO' => $r->pnotes('id_session_SSO')};

        Core::VultureUtils::notify($dbh, undef, $user, 'connection', scalar(keys %users));

        #Generate new service ticket
        my $st = 'ST-'.Core::VultureUtils::generate_random_string(29);
        my $service = $req->param('service');
        if(defined $service){
            $log->debug("Creating new ticket");
            $users{$session_SSO{username}}->{'ticket'} = $st;
            $users{$session_SSO{username}}->{'ticket_service'} = $service;
            $users{$session_SSO{username}}->{'ticket_created'} = time();
        }
        $r->pnotes('url_to_redirect' => $service.'/?ticket='.$st) if defined $service;
        Core::VultureUtils::set_memcached('vulture_users_in', \%users);

        return Apache2::Const::OK;
    #Authentication failed for some reasons
    } else {
        unless ($ntlm) {
            my (%users);
            %users = %{Core::VultureUtils::get_memcached('vulture_users_in') or {}};

            Core::VultureUtils::notify($dbh, undef, $user, 'connection_failed', scalar(keys %users));

            $r->user('');
            $log->warn("Login failed in AuthenHandler for user $user") if ($password and $user);

            #Create error message if no auth_message
            unless($r->pnotes('auth_message')){
                $r->pnotes('auth_message' => "MISSING_USER") if $password;
                $r->pnotes('auth_message' => "MISSING_PASSWORD") if $user;
                $r->pnotes('auth_message' => "LOGIN_FAILED") if ($password and $user);
            }
        }

        #Unfinite loop for basic auth
        if(($app and $app->{'auth_basic'}) or ($intf and $intf->{'auth_basic'})){
            $log->warn("Login failed (basic mode) in AuthenHandler for user $user") if ($password and $user);
            $r->note_basic_auth_failure;
            return Apache2::Const::HTTP_UNAUTHORIZED;
        } else {

            #IF NTLM is used, we immediatly return the results of MultipleAuth();
            return $ret if ($ntlm);

            $log->debug("No user / password... ask response handler to display the logon form");
            return Apache2::Const::OK;
        }
    }
}

#get the Data from Vulture login page
sub getRequestData {
	my ($r) = @_;
    my $req = Apache2::Request->new($r);
	my $login = $req->param('vulture_login');
	my $password = $req->param('vulture_password');
    my $token = $req->param('vulture_token');

	return ($login, $password, $token);
}

sub multipleAuth {
    my ($r, $log, $dbh, $auths, $app, $user, $password, $class, $is_transparent) = @_;

    my $ret = Apache2::Const::FORBIDDEN;

	foreach my $row (@$auths) {
		my $module_name = "Auth::Auth_".uc(@$row[1]);

        $log->debug("Load $module_name");
		load $module_name;

		#Get return
		#for NTML and other authentification method without login or password
		if ($is_transparent==0) {
			$log-> debug ("multipleAuth: Classic Authentication");
			$ret = $module_name->checkAuth($r, $log, $dbh, $app, $user, $password, @$row[2]);
		}
		else {
			$log-> debug ("multipleAuth: Transparent Authentication");
			$ret = $module_name->checkAuth($r, $class, $log, $dbh, $app, $user, $password, @$row[2]);
		}

		#Auth module said "The authentication is successful" -- User has been authentified
		return Apache2::Const::OK 			if $ret == Apache2::Const::OK;

		#Auth module said "The authentication is not authorized for the moment" -- It may be authorized after... ex: NTLM PROCESS
		return Apache2::Const::HTTP_UNAUTHORIZED 	if $ret == Apache2::Const::HTTP_UNAUTHORIZED;
	}
	#Auth module said "Authentication failed"  -- User is not authentified
	return Apache2::Const::FORBIDDEN;
}
1;
