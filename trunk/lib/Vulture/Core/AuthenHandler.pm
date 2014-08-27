#file:Core/AuthenHandler.pm
#---------------------------------
#!/usr/bin/perl
package Core::AuthenHandler;

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::RequestIO  ();
use Apache2::Connection ();
use Apache2::Log;
use Apache2::Reload;
use Apache2::Request;
use Apache2::Access;
use Authen::Smb;

use Apache2::Const -compile => qw(OK HTTP_UNAUTHORIZED FORBIDDEN);

use Core::VultureUtils qw(&session &get_memcached &set_memcached &generate_random_string &log_auth_event &load_module);
use Core::ActionManager qw(&handle_action);
use Try::Tiny;

#USED FOR NTLM
sub get_nonce {
    my ( $self, $r, $log, $pdc, $bdc, $domain ) = @_;

    $self->{semkey}     = 23754;
    $self->{semtimeout} = 2;

    if ( $self->{semkey} ) {
        $log->debug("[$$] AuthenNTLM: We are going to lock if needed");
        try {
            $log->debug("Locking ...");
            local $SIG{ALRM} = sub { 
		$log->debug( "[$$] AuthenNTLM: timed out while waiting for lock (key = $self->{semkey})\n" );
                die;
            };
            alarm $self->{semtimeout};
            $self->{lock} = Lock->lock( $self->{semkey}, $log );
            alarm 0;
        }
	catch {
		$log->debug("[$$] AuthenNTLM: Problem during lock");
	}
    }
    if ( $self->{nonce} ) {
        $log->debug( "Auth_NTLM: get_nonce -> Reuse " . $self->{nonce} );
        return $self->{nonce};
    }

    my $nonce = '12345678';
    $log->debug("Auth_NTLM: Connect to pdc = $pdc bdc = $bdc domain = $domain");
    my $smbhandle =
      Authen::Smb::Valid_User_Connect( $pdc, $bdc, $domain, $nonce );
    if ( !$smbhandle ) {
        $log->debug(
            "Auth_NTLM: Connect to SMB Server failed (pdc = $pdc bdc = $bdc domain = $domain error = "
              . Authen::Smb::SMBlib_errno() . '/'
              . Authen::Smb::SMBlib_SMB_Error()
              . ") for "
              . $r->uri );
        return undef;
    }
    $log->debug("Auth_NTLM: get_nonce() -> $nonce");
    $self->{smbhandle} = $smbhandle;
    return $self->{nonce} = $nonce;
}

sub handler : method {

    my $class   = shift;
    my $r       = shift;
    my $log     = $r->pnotes('log');
    my $dbh     = $r->pnotes('dbh');
    my $app     = $r->pnotes('app');
    my $mc_conf = $r->pnotes('mc_conf');
    my $req     = Apache2::Request->new($r);

    my $intf = $r->pnotes('intf');
    
    my (%session_SSO);
    Core::VultureUtils::session( \%session_SSO, $intf->{sso_timeout},
        $r->pnotes('id_session_SSO'),
        $log, $mc_conf, $intf->{sso_update_access_time} );

    my ( $status, $password );
    my $user;
    my $token = '';
    my $service = $req->param('service');

    $log->debug("########## AuthenHandler ##########");

    #Basic authentification
    if (   ( $app and $app->{'auth_basic'} )
        or ( $intf and $intf->{'auth_basic'} ) )
        {
            $log->debug('Basic mode');
        ( $status, $password ) = $r->get_basic_auth_pw;
        $user = $r->user;
    }

    #Get user/password from URL or POST method
    elsif ( $r->method eq "POST" or $r->method eq "GET" ) {
        ( $user, $password, $token) = Core::AuthenHandler::getRequestData($req);
    }
    else {
        return Apache2::Const::HTTP_UNAUTHORIZED;
    }

    my $auth = ($app and defined $app->{'auth'} ) ? $app->{'auth'} : $intf->{'auth'};
    if (not $auth){
        # No auth required
        Core::AuthenHandler::validate_auth(
            $r, "Anonymous", "", $service,\%session_SSO,0);
        return Apache2::Const::OK;
    }

    my $ret = Apache2::Const::FORBIDDEN;

    # log authentication plugin
    my $module_name = "Auth::Auth_" . uc($auth->{auth_type});
    $log->debug("Load $module_name");
    Core::VultureUtils::load_module($module_name,'checkAuth');

    # try to authenticate user
    $ret = $module_name->checkAuth( $r, $log, $dbh, $app, 
        $user, $password,$auth->{id_method}, \%session_SSO, $class,
        Core::AuthenHandler::csrf_ok($token, \%session_SSO, $app, $intf));
    $log->debug(" Auth gave : " . ($ret==Apache2::Const::OK ? "OK" : "NOK") . "(RET = ".$ret.")");

    #Trigger action when change pass is needed / auth failed
    Core::AuthenHandler::auth_triggers ($r,$ret,$user,$password,$intf,$app);

    # Auth module: The authentication is successful"
    # -- User has been authentified
    if (defined $ret and $ret == scalar Apache2::Const::OK )
    {
        #Get new username and password
        $user = $r->pnotes('username'); 
        $password = $r->pnotes('password');
        $log->debug("Good user/password for $user");

        $log->debug('Validate SSO session');
        Core::AuthenHandler::validate_auth(
            $r,$user,$password,$service,\%session_SSO,1);
        return Apache2::Const::OK;
    }
    else {
        #Authentication failed for some reasons
        my (%users);
        %users = %{
            Core::VultureUtils::get_memcached( 'vulture_users_in',
                $mc_conf )
              or {}
          };

        Core::VultureUtils::log_auth_event($log, $app ? $app->{friendly_name} : '-', $user, 'connection_failed',
        "AuthenHandler" );

        $r->user('');
        $r->pnotes('username'=>undef);
        $log->warn("Login failed in AuthenHandler for user $user")
          if ( $password and $user );

        #Create error message if no auth_message
        unless ( $r->pnotes('auth_message') ) {
            $r->pnotes( 'auth_message' => "MISSING_USER" )     if $password;
            $r->pnotes( 'auth_message' => "MISSING_PASSWORD" ) if $user;
            $r->pnotes( 'auth_message' => "LOGIN_FAILED" )
              if ( $password and $user );
        }

        #Unfinite loop for basic auth
        if (   ( $app and $app->{'auth_basic'} )
            or ( $intf and $intf->{'auth_basic'} ) )
        {
            $log->warn(
                "Login failed (basic mode) in AuthenHandler for user $user")
              if ( $password and $user );
            $r->note_basic_auth_failure;
            return Apache2::Const::HTTP_UNAUTHORIZED;
        }
        else {
            #Needed for NTLM
            if ($ret == Apache2::Const::HTTP_UNAUTHORIZED)
            {
                $log->debug("Authentication failed, return HTTP_UNAUTHORIZED (we are probably using NTLM)");
                return Apache2::Const::HTTP_UNAUTHORIZED;
            }

            $log->debug("No user / password ... ask response handler to display the logon form");
            return Apache2::Const::OK;
        }
    }
}

#get the Data from Vulture login page
sub getRequestData {
    my ($req)      = @_;
    my $login    = $req->param('vulture_login')||'';
    my $password = $req->param('vulture_password')||'';
    my $token    = $req->param('vulture_token')||'';
    return ( $login, $password, $token );
}

sub csrf_ok {
    my ($token,$session_SSO,$app,$intf) = @_;
    return ( 
        # bypass csrf check when app don't use it
        ($app and ( 
                not $app->{'check_csrf'} or $app->{'auth_basic'}
            )
        )
        # bypass csrf check when intf don't use it and we don't have an app
        or (not $app and not $intf->{'check_csrf'})
        # check csrf token
        or (defined $session_SSO->{random_token} and $token eq $session_SSO->{random_token})
    );
}
sub cas_set_ticket{
    my ($r,$service,$session_SSO,$users) = @_;
    my $log = $r->pnotes('log');
    my $st = 'ST-' . Core::VultureUtils::generate_random_string(29);
    $log->debug("Creating new ticket");
    $users->{ $session_SSO->{username} }->{'ticket'}         = $st;
    $users->{ $session_SSO->{username} }->{'ticket_service'} = $service;
    $users->{ $session_SSO->{username} }->{'ticket_created'} = time();
    if ( $service =~ /\?/ ) {
        $r->pnotes( 'url_to_redirect' => $service . '&ticket=' . $st );
    }
    else {
        $r->pnotes( 'url_to_redirect' => $service . '?ticket=' . $st );
    }
}
sub validate_auth{
    my ($r,$user,$password,$service,$session_SSO,$notify) = @_;
    my $dbh     = $r->pnotes('dbh');
    my $log = $r->pnotes('log');
    my $mc_conf = $r->pnotes('mc_conf');
    my $app = $r->pnotes('app');
    $r->pnotes( 'username' => $user );
    $r->pnotes( 'password' => $password );

    # set credentials for this session
    $session_SSO->{username} = $user;
    $session_SSO->{is_auth} = 1;
    $r->user($user);
    
    #Setting Memcached table
    my (%users);
    %users = %{
        Core::VultureUtils::get_memcached( 'vulture_users_in',
            $mc_conf )
          or {}
      };
    $users{ $user } = { 'SSO' => $r->pnotes('id_session_SSO') };

    # log connection to app if required
    Core::VultureUtils::log_auth_event($log, $app ? $app->{friendly_name} : '-', $user, 'connection',
    "AuthenHandler" ) if ($notify);

    #Generate new service ticket if needed
    if ( defined $service ) {
        cas_set_ticket($r,$service,$session_SSO,\%users);
    }
    Core::VultureUtils::set_memcached('vulture_users_in',\%users,
        undef, $mc_conf );

   #Authentified, cookie is valid, let user go and check ACL (next step)
}
sub auth_triggers{
    my ($r,$ret,$user,$password,$intf,$app) = @_;
    my $log = $r->pnotes('log');
    my $dbh = $r->pnotes('dbh');

    my $auth_msg = $r->pnotes('auth_message') || '';
    $log->debug ("AuthenHandler: AUTH_MSG = " . $auth_msg);

    if ( $auth_msg eq ''){
        if ( (not defined $ret or $ret != scalar Apache2::Const::OK)
              and ($user or $password)){
            Core::ActionManager::handle_action( $r, $log, $dbh, $intf, $app,
                'LOGIN_FAILED', 'Login failed' );
        }
        else {
            return;
        }
    }
    $auth_msg = uc($auth_msg);
    #Trigger action when change pass is needed / auth failed
    Core::ActionManager::handle_action( $r, $log, $dbh, $intf, $app,
        'NEED_CHANGE_PASS', 'You need to change your password' )
      if ( $auth_msg eq 'NEED_CHANGE_PASS' );
    Core::ActionManager::handle_action( $r, $log, $dbh, $intf, $app,
        'ACCOUNT_LOCKED', 'You need to unlock your password' )
      if ( $auth_msg eq 'ACCOUNT_LOCKED' );
    Core::ActionManager::handle_action( $r, $log, $dbh, $intf, $app,
        'AUTH_SERVER_FAILURE', 'Vulture can\'t contact authentication server' )
      if ( $auth_msg eq 'AUTH_SERVER_FAILURE' );
}
1;
