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
use Apache::SSLLookup;

use Authen::Smb;

use Apache2::Const -compile => qw(OK HTTP_UNAUTHORIZED FORBIDDEN);

use Core::VultureUtils
  qw(&session &get_memcached &set_memcached &generate_random_string &notify &load_module);
use Core::ActionManager qw(&handle_action);

#USED FOR NTLM
sub get_nonce {
    my ( $self, $r, $log, $pdc, $bdc, $domain ) = @_;

    $self->{semkey}     = 23754;
    $self->{semtimeout} = 2;

    if ( $self->{semkey} ) {
        $log->debug("We are going to lock if needed");
        eval {
            $log->debug("Locking ...");
            local $SIG{ALRM} = sub {
                $log->debug( "[$$] AuthenNTLM: timed out"
                      . "while waiting for lock (key = $self->{semkey})\n" );
                die;
            };

            alarm $self->{semtimeout};
            $self->{lock} =
              Auth::Auth_NTLM::Lock->lock( $self->{semkey}, $log );
            alarm 0;
        };
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

    #my ($class, $r) = @_ ;
    my $class   = shift;
    my $r       = Apache::SSLLookup->new(shift);
    my $log     = $r->pnotes('log');
    my $dbh     = $r->pnotes('dbh');
    my $app     = $r->pnotes('app');
    my $mc_conf = $r->pnotes('mc_conf');
    my $req     = Apache2::Request->new($r);

    $log->error("App is missing in AuthenHandler") unless $app;
    my $intf = $r->pnotes('intf');
    
    my (%session_SSO);
    Core::VultureUtils::session( \%session_SSO, $intf->{sso_timeout},
        $r->pnotes('id_session_SSO'),
        $log, $mc_conf, $intf->{sso_update_access_time} );

    my ( $status, $password );
    my $user;
    my $token;
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
        ( $user, $password, $token) = Core::AuthenHandler::getRequestData($r);
    }
    else {
        return Apache2::Const::HTTP_UNAUTHORIZED;
    }

    # If user is logged in SSO, check if the sso contains all auths of the app
    # If it does, give a vulture_proxy cookie and go to AuthzHandler for a vulture_app cookie
    if ( $session_SSO{is_auth} and Core::AuthenHandler::check_sso_auths($r,\%session_SSO)){
        # Same auths
        $log->debug("User is already authorized to access this SSO");
        $session_SSO{$app->{name}}=$r->pnotes('id_session_app')
            if ( defined $app->{name} 
                and defined $r->pnotes('id_session_app') );
        Core::AuthenHandler::validate_auth(
            $r, $session_SSO{username}, $session_SSO{password},
            $service,\%session_SSO,0);
        return Apache2::Const::OK;
    }

    # Not authentified
    my $auths = defined( $app->{'auth'} ) ? $app->{'auth'} : $intf->{'auth'};
    # set AUTH_NAME value (can be modified by auth plugins also (ie. OTP,LOGIC..)
    my @auth_names = ();
    foreach my $row (@$auths){push(@auth_names,@$row[0]);}
    my $auth_name = join(", ",@auth_names);
    $r->pnotes("auth_name"=>$auth_name);

    $log->debug("Try to authenticate user to '$auth_name'");

    # Check type and use good auth module
    my $ret = Apache2::Const::FORBIDDEN;
    my $ntlm = undef;
    my $cas  = undef;
    my $ssl  = undef;

    # check single auths first
    foreach my $row (@$auths) {
        if ( @$row[1] eq "ntlm" ) {
            $ret = Core::AuthenHandler::multipleAuth( $r, $log, $dbh, $auths, $app, $user, $password,
                $class,\%session_SSO );
            $ntlm = 1;
            last;
        }
        elsif ( @$row[1] eq "cas" ) {
            $log->debug("CAS mode");
            $ret = Core::AuthenHandler::multipleAuth( $r, $log, $dbh, $auths, $app, $user, $password,
                $class,\%session_SSO );
            $cas = 1;
            last;
        }
        elsif ( @$row[1] eq "ssl" ) {
            if (defined $r->ssl_lookup('SSL_CLIENT_S_DN_CN')){
                my $ssl_user = $r->ssl_lookup('SSL_CLIENT_S_DN_CN');
                unless ($ssl_user){
                    $log->error("no client dn cn in ssl auth");
                }
                else{
                    $log->debug("SSL mode '$ssl_user'");
                    $r->pnotes(username=>$ssl_user);
                    $ret = Apache2::Const::OK;
                    $ssl=1;
                }
            }
        }
    }
    # general case : check auths will multipleauth
    $ret = Core::AuthenHandler::multipleAuth( 
        $r, $log, $dbh, $auths, $app, 
        $user, $password, 0,\%session_SSO
    ) if (
        # dont redo auth when we authentified in cas, ntlm or ssl
        not ( $cas or $ntlm or $ssl)
        and ( defined $user and $user ne '')
        and csrf_ok($token,\%session_SSO,$app,$intf)
    );
    $log->debug( "Return from auth => " . $r->pnotes('auth_message') )
        if defined $r->pnotes('auth_message');
    $log->debug(" AUth gave : " . ($ret==Apache2::Const::OK ? "OK" : "NOK"));

    #Trigger action when change pass is needed / auth failed
    Core::AuthenHandler::auth_triggers ($r,$ret,$user,$password,$intf,$app);

    if (defined $ret and $ret == scalar Apache2::Const::OK )
    {
        $log->debug("Good user/password");

        #Get new username and password ... ex : CAS
        $user = $r->pnotes('username') || $r->user() || $user ; 
        $password = $r->pnotes('password') || $password;

        $log->debug('Validate SSO session');
        $session_SSO{is_auth}  = 1;

        # set credentials for this session
        $session_SSO{username} = $user;
        $session_SSO{password} = $password;

        Core::AuthenHandler::validate_auth(
            $r,$user,$password,$service,\%session_SSO,1);
        return Apache2::Const::OK;
    }
    else {
        #Authentication failed for some reasons
        unless ($ntlm) {
            my (%users);
            %users = %{
                Core::VultureUtils::get_memcached( 'vulture_users_in',
                    $mc_conf )
                  or {}
              };

            Core::VultureUtils::notify( $dbh, undef, $user, 'connection_failed',
                scalar( keys %users ) );

            $r->user('');
            $log->warn("Login failed in AuthenHandler for user $user")
              if ( $password and $user );

            #Create error message if no auth_message
            unless ( $r->pnotes('auth_message') ) {
                $r->pnotes( 'auth_message' => "MISSING_USER" )     if $password;
                $r->pnotes( 'auth_message' => "MISSING_PASSWORD" ) if $user;
                $r->pnotes( 'auth_message' => "LOGIN_FAILED" )
                  if ( $password and $user );
            }
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
           #IF NTLM is used, we immediatly return the results of MultipleAuth();
            return $ret if ($ntlm);
            $log->debug(
"No user / password ... ask response handler to display the logon form"
            );
            return Apache2::Const::OK;
        }
    }
}

#get the Data from Vulture login page
sub getRequestData {
    my ($r)      = @_;
    my $req      = Apache2::Request->new($r);
    my $login    = $req->param('vulture_login')||'';
    my $password = $req->param('vulture_password')||'';
    my $token    = $req->param('vulture_token')||'';

    return ( $login, $password, $token );
}

sub csrf_ok {
    my ($token,$session_SSO,$app,$intf) = @_;
    return ( 
        # bypass csrf check when app don't use it
        (defined $app and ( 
                not $app->{'check_csrf'} or $app->{'auth_basic'}
            )
        )
        # bypass csrf check when intf don't use it and we don't have an app
        or (not defined $app and not $intf->{'check_csrf'})
        # check csrf token
        or (defined $session_SSO->{random_token} and $token eq $session_SSO->{random_token})
    );
}

sub multipleAuth {
    my (
        $r,    $log,      $dbh,   $auths, $app,
        $user, $password, $class, $session
    ) = @_;
    my $ret = Apache2::Const::FORBIDDEN;
    $log->debug("good old multiAuth");
    # row : name,type,id_method
    foreach my $row (@$auths) {
        my ($name,$type,$id_method)=@$row;
        if ($type eq 'ssl') {
            next;
        }
        my $module_name = "Auth::Auth_" . uc($type);
        $log->debug("Load $module_name");
        Core::VultureUtils::load_module($module_name,'checkAuth');
        # Try to authenticate with method
        $ret = $module_name->checkAuth( $r, $log, $dbh, $app, 
            $user, $password,$id_method, $session, $class);
        # Auth module: The authentication is successful"
        # -- User has been authentified
        return $ret if $ret == Apache2::Const::OK;
        # Auth module:The authentication is not authorized for the moment
        # -- It may be authorized after... ex: NTLM PROCESS
        return $ret if $ret == Apache2::Const::HTTP_UNAUTHORIZED;
    }
    #Auth module said "Authentication failed"  -- User is not authentified
    return Apache2::Const::FORBIDDEN;
}
sub check_sso_auths{
    my ($r,$session_SSO) = @_;
    my $log     = $r->pnotes('log');
    my $dbh     = $r->pnotes('dbh');
    my $app     = $r->pnotes('app');
    my $intf    = $r->pnotes('intf');
    my $mc_conf = $r->pnotes('mc_conf');

    $log->debug("User is logged in SSO. Check if auths are the same");
    my $diff_count = 0;
    #Foreach app where user is currently logged in
    foreach my $key ( keys %$session_SSO ) {
        $log->debug($key);
        #Reject bad app key
        my @wrong_keys =
          qw/is_auth username password last_access_time last_access_time _session_id random_token/;
        unless ( grep $_ eq $key, @wrong_keys ) {
            my $id_app = $session_SSO->{$key};
            my (%current_app);
            Core::VultureUtils::session( \%current_app, undef, $id_app,
                undef, $mc_conf );

            if ( $current_app{app_name} eq '' ) {
                Core::VultureUtils::session( \%current_app, undef,
                    $r->pnotes("id_session_app"),
                    undef, $mc_conf );
            }

#Getting all auths methods used previously to compare with current app auths
            my $query =
"SELECT auth.name, auth.auth_type, auth.id_method FROM app, auth_multiple, auth WHERE app.name = ? AND auth_multiple.app_id = app.id AND auth_multiple.auth_id = auth.id";
            $log->debug($query);
            my @auths = @{
                $dbh->selectall_arrayref( $query, undef,
                    $current_app{app_name})
              };
            my @current_auths =
              @{ defined( $app->{'auth'} )
                ? $app->{'auth'}
                : $intf->{'auth'} };
            my @difference = ();
            my %count      = ();
            my $element;
            foreach $element ( @auths, @current_auths ) {
                $count{ @$element[0] }++;
            }
            foreach $element ( keys %count ) {
                if ( int( $count{$element} ) <= 1 ) {
                    push( @{ \@difference }, $element );
                }
            }
            $log->debug("Before $diff_count");
            $diff_count += scalar @difference;
            $log->debug("Auth not in common $diff_count");
        }
        return  ( ($diff_count == 0) ? 1 : 0 );
    }
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
    my $mc_conf = $r->pnotes('mc_conf');
    $r->pnotes( 'username' => $user );
    $r->pnotes( 'password' => $password );

    #Setting Memcached table
    my (%users);
    %users = %{
        Core::VultureUtils::get_memcached( 'vulture_users_in',
            $mc_conf )
          or {}
      };
    $users{ $user } = { 'SSO' => $r->pnotes('id_session_SSO') };

    # log connection to app if required
    Core::VultureUtils::notify( $dbh, undef, $user, 'connection',
        scalar( keys %users ) ) if ($notify);

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
