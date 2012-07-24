#file:Core/TransHandlerv2.pm
#-------------------------
#!/usr/bin/perl
package Core::TransHandlerv2;

use strict;
use warnings;

use Apache2::Reload;
use Apache2::Response    ();
use Apache2::RequestRec  ();
use Apache2::RequestIO   ();
use Apache2::RequestUtil ();
use Apache::SSLLookup;
use Apache2::Const -compile =>
  qw(OK DECLINED FORBIDDEN REDIRECT DONE NOT_FOUND);

use Core::VultureUtils
  qw(&get_memcached_conf &get_app &get_intf &version_check &get_cookie &session &get_translations &get_style);
use Core::Log qw(&new &debug &error);
use Core::Config qw(&new &get_key);
use MIME::Base64;

use APR::URI;
use APR::Table;
use APR::SockAddr;

use DBI;

#All headers variables for SSL
my %headers_vars = (
    2  => 'SSL_CLIENT_I_DN',
    3  => 'SSL_CLIENT_M_SERIAL',
    4  => 'SSL_CLIENT_S_DN',
    5  => 'SSL_CLIENT_V_START',
    6  => 'SSL_CLIENT_V_END',
    7  => 'SSL_CLIENT_S_DN_C',
    8  => 'SSL_CLIENT_S_DN_ST',
    9  => 'SSL_CLIENT_S_DN_Email',
    10 => 'SSL_CLIENT_S_DN_L',
    11 => 'SSL_CLIENT_S_DN_O',
    12 => 'SSL_CLIENT_S_DN_OU',
    13 => 'SSL_CLIENT_S_DN_CN',
    14 => 'SSL_CLIENT_S_DN_T',
    15 => 'SSL_CLIENT_S_DN_I',
    16 => 'SSL_CLIENT_S_DN_G',
    17 => 'SSL_CLIENT_S_DN_S',
    18 => 'SSL_CLIENT_S_DN_D',
    19 => 'SSL_CLIENT_S_DN_UID',
);

sub handler {
    my $r            = Apache::SSLLookup->new(shift);
    my $uri          = $r->uri;
    my $unparsed_uri = $r->unparsed_uri;
    my $protocol     = $r->protocol();
    my $dbh          = DBI->connect( $r->dir_config('VultureDSNv3') );

    #Calling config functions
    my $config = Core::Config->new($dbh);

    #	my $mc_conf = $config->get_key('memcached');
    my $mc_conf = get_memcached_conf($dbh);

    #Calling log functions
    my $log = Core::Log->new($r);

    #Sending db handler to next Apache Handlers
    $r->pnotes( 'dbh'     => $dbh );
    $r->pnotes( 'log'     => $log );
    $r->pnotes( 'config'  => $config );
    $r->pnotes( 'mc_conf' => $mc_conf );

    $log->debug("########## TransHandler (mc : $mc_conf)##########");

    #Version check
    unless ( Core::VultureUtils::version_check($config) ) {
        $log->error(
"Database version is not up-to-date. Can't load Vulture. Please check versions"
        );
        return Apache2::Const::FORBIDDEN;
    }
    else {
        $log->debug("Your Vulture's database is up-to-date. Congratulations !");
    }
    my $cookie_app_name=$r->dir_config('VultureProxyCookieName');

    #If protocol is different from HTTP or HTTPS, reject the connexion
    if ( $protocol !~ /HTTP/ and $protocol !~ /HTTPS/ ) {
        $log->error("Rejecting bad protocol $protocol");
        return Apache2::Const::FORBIDDEN;
    }

    #If URI matches with app adress, get app and interface
    my $intf =
      Core::VultureUtils::get_intf( $log, $dbh, $r->dir_config('VultureID') );
    $r->pnotes( 'intf' => $intf ) if defined $intf;

    $log->debug( "url is " . $r->hostname . $unparsed_uri );
    my $app = Core::VultureUtils::get_app( $log, $r->hostname . $unparsed_uri,
        $dbh, $intf->{id} )
      if ( $unparsed_uri !~ /$cookie_app_name=([^;]*)/ );
    $r->pnotes( 'app' => $app ) if defined $app;

    #Plugin or Rewrite (according to URI)
    my $query =
'SELECT uri_pattern, type, options FROM plugin WHERE app_id = ? OR app_id IS NULL';
    $log->debug($query);
    my $plugins = $dbh->selectall_arrayref( $query, undef, $app->{id} );
    my $module_name;
    foreach my $row (@$plugins) {
        my $options;
        my @result;
        my $exp = @$row[0];

        if ( (@result) = ( $unparsed_uri =~ /$exp/ ) ) {
            $log->debug( "Pattern " . $exp . " matches with URI" );
            $module_name = 'Plugin::Plugin_' . uc( @$row[1] );
            if ( uc( @$row[1] ) eq "REWRITE" ) {
                $options = $row;
            }
            else {
                $options = @$row[2];
            }
            $options ||= \@result;
            $log->debug("Load $module_name");

            #Calling associated plugin
            eval {
                ( my $file = $module_name ) =~ s|::|/|g;
                require $file . '.pm';
                $module_name->import("plugin");
                1;
            } or do {
                my $error = $@;
            };

            #Get return
            my $ret =
              $module_name->plugin( $r, $log, $dbh, $intf, $app, $options );

#Return all code returns (means that OK from plugin will skip all of the TransHandler process)
            return $ret if defined $ret;
        }
    }

    #Rewrite content
    $query =
'SELECT pattern, type, options, options1 FROM plugincontent WHERE (app_id = ?  OR app_id IS NULL) ORDER BY type';
    $log->debug($query);
    $plugins = $dbh->selectall_arrayref( $query, undef, $app->{id} );
    my $i = 0;
    $log->debug("COOKIEDEBUG sending rewrite content");
    foreach my $row (@$plugins) {
        $log->debug( "COOKIEDEBUG type" . @$row[1] );
        $r->pnotes( 'type' . $i      => @$row[1] );
        $r->pnotes( 'exp' . $i       => @$row[0] );
        $r->pnotes( 'options_' . $i  => @$row[2] );
        $r->pnotes( 'options1_' . $i => @$row[3] );

        $i++;

    }
    if ( $r->pnotes('type0') ) {
        $module_name = 'Plugin::Plugin_REWRITE_CONTENT';

        $log->debug("Load $module_name");

        #Calling associated plugin
        eval {
            ( my $file = $module_name ) =~ s|::|/|g;
            require $file . '.pm';
            $module_name->import("plugin");
            1;
        } or do {
            my $error = $@;
        };

        my $ret = $module_name->plugin( $r, $log, $dbh, $intf, $app );
    }

    #Header input modify
    $query =
'SELECT pattern, type, options, options1 FROM pluginheader WHERE app_id = ? OR app_id IS NULL ORDER BY type';
    $log->debug($query);
    $plugins = $dbh->selectall_arrayref( $query, undef, $app->{id} );
    foreach my $row (@$plugins) {
        my $header   = @$row[0];
        my $type     = @$row[1];
        my $options  = @$row[2];
        my $options1 = @$row[3];
        my @result;
        $module_name = 'Plugin::Plugin_HEADER_INPUT';
        $log->debug("Load $module_name");
        $log->debug($header);

        #Calling associated plugin
        #Get return
        eval {
            ( my $file = $module_name ) =~ s|::|/|g;
            require $file . '.pm';
            $module_name->import("plugin");
            1;
        } or do {
            my $error = $@;
        };

        my $ret = $module_name->plugin(
            $r,      $log,  $dbh,     $intf, $app,
            $header, $type, $options, $options1
        );

    }

    #If application exists and is not down, check auth
    if (    $app
        and $app->{'up'}
        and ( $app->{'intf'} eq $r->dir_config('VultureID') ) )
    {
        my $proxy_url;
        if ( $uri =~ /^(http|https|ftp):\/\// ) {
            $proxy_url = $uri;
        }
        else {
            my $dir;
            my $hostname = $r->hostname;
            if ( $app->{name} =~ /$hostname\/?(.*)(\/*)$/ ) {
                $dir = $1;
            }
            if ( $uri =~ /^\/?$dir\/(.*)$/ ) {
                $uri = $1;
            }
            else { $uri = ''; }
            $log->debug("url: $app->{url} ; dir: $dir ; uri : $uri");
            $proxy_url = $app->{url} . "/" . $uri;
        }
        $log->debug("proxy = $proxy_url");

        #No authentication is needed
        my $auths = $app->{'auth'};
        if ( not defined @$auths or not @$auths ) {

            #Destroy useless handlers
            $r->set_handlers( PerlAuthenHandler => undef );
            $r->set_handlers( PerlAuthzHandler  => undef );
            $log->debug( "Setting pnotes 'url_to_mod_proxy' to " . $proxy_url )
              unless $r->pnotes('url_to_mod_proxy');
            $r->filename( "proxy:" . $proxy_url );
            $r->pnotes( 'url_to_mod_proxy' => $proxy_url )
              unless $r->pnotes('url_to_mod_proxy');

            #Getting headers to forward
            my $sth = $dbh->prepare(
                "SELECT name, type, value FROM header WHERE app_id= ?");
            $sth->execute( $app->{id} );
            while ( my ( $name, $type, $value ) = $sth->fetchrow ) {
                if ( $type eq "REMOTE_ADDR" ) {
                    $value = $r->connection->remote_ip;

                    #Nothing to do
                }
                elsif ( $type eq "CUSTOM" ) {

                    #Types related to SSL
                }
                else {
                    $value = $r->ssl_lookup($type);
                   # $value = $r->ssl_lookup( $headers_vars{$type} )
                   #   if ( exists $headers_vars{$type} );
                }

                #Try to push custom headers
                eval {
                    $r->headers_in->set( $name => $value );
                    $log->debug("Pushing custom header $name => $value");
                };
            }
            $sth->finish();

            return Apache2::Const::OK;
        }

        #Getting session app if exists. If not, creating one
        my ($id_app) = Core::VultureUtils::get_cookie( $r->headers_in->{Cookie},
            $r->dir_config('VultureAppCookieName') . '=([^;]*)' );
        my (%session_app);
        Core::VultureUtils::session( \%session_app, $app->{timeout}, $id_app,
            $log, $mc_conf, $app->{update_access_time} );
        $r->pnotes( 'id_session_app' => $id_app );

        # We have authorization for this app so let's go with mod_proxy
        if ( defined $session_app{is_auth} and $session_app{is_auth} == 1 ) {

            #Setting username && password for FixupHandler and ResponseHandler
            $r->pnotes( 'username' => $session_app{username} );
            $r->pnotes( 'password' => $session_app{password} );
            $r->user( $session_app{username} );
            $log->debug( "This app : "
                  . $r->hostname
                  . " is secured or display portal is on. User has a valid cookie for this app"
            );

            #Add Authorization header for htaccess
            if (    $app->{'sso'}->{'type'}
                and $app->{'sso'}->{'type'} eq "sso_forward_htaccess" )
            {
                $r->headers_in->set(
                    'Authorization' => "Basic "
                      . encode_base64(
                        $session_app{username} . ':' . $session_app{password}
                      )
                );
            }

            #Destroy useless handlers
            $r->set_handlers( PerlAuthenHandler => undef );
            $r->set_handlers( PerlAuthzHandler  => undef );

            #Mod_proxy with apache : user will not see anything
            if ( not defined $session_app{SSO_Forwarding} ) {
                $log->debug(
                    "Setting pnotes 'url_to_mod_proxy' to " . $proxy_url )
                  unless $r->pnotes('url_to_mod_proxy');
                $r->filename( "proxy:" . $proxy_url );
                $r->pnotes( 'url_to_mod_proxy' => $proxy_url )
                  unless $r->pnotes('url_to_mod_proxy');
            }

            #Getting headers to forward
            my $sth = $dbh->prepare(
                "SELECT name, type, value FROM header WHERE app_id= ?");
            $sth->execute( $app->{id} );
            while ( my ( $name, $type, $value ) = $sth->fetchrow ) {
                if ( $type eq "REMOTE_ADDR" ) {
                    $value = $r->connection->remote_ip;

                    #Nothing to do
                }
                elsif ( $type eq "CUSTOM" ) {

                    #Types related to SSL
                }
                else {
                    $value = $r->ssl_lookup($type);
#                    $value = $r->ssl_lookup( $headers_vars{$type} )
#                     if ( exists $headers_vars{$type} );
                }

                #Try to push custom headers
                eval {
                    $r->headers_in->set( $name => $value );
                    $log->debug("Pushing custom header $name => $value");
                };
            }
            $sth->finish();

            return Apache2::Const::OK;

#Not authentified in this app. Setting cookie for app. Redirecting to SSO Portal.
        }
        else {
            $log->debug( "App "
                  . $r->hostname
                  . " is secured and user is not authentified in app. Let's have fun with AuthenHandler / redirect to SSO Portal "
                  . $intf->{'sso_portal'} );
            $r->status(200);

            #Fill session for SSO Portal
            $session_app{app_name} = $app->{name};
            if ( $r->pnotes('url_to_redirect') ) {
                $session_app{url_to_redirect} = $r->pnotes('url_to_redirect');
            }
            else {
                $session_app{url_to_redirect} = $unparsed_uri;
            }

#Redirect to SSO Portal if $r->pnotes('url_to_mod_proxy') is not set by Rewrite engine
            if ( not $r->pnotes('url_to_mod_proxy') ) {
                my $incoming_uri = $app->{name};
                my $ssl          = 0;
                foreach my $row (@$auths) {
                    if ( uc( @$row[1] ) eq "SSL" ) {
                        $log->debug("SSL mode");
                        $ssl = 1;
                    }
                }
                $incoming_uri = $intf->{'sso_portal'}
                  if $intf->{'sso_portal'} and not $ssl;
                if ( $incoming_uri !~ /^(http|https):\/\/(.*)/ ) {

                    #Fake scheme for making APR::URI parse
                    $incoming_uri = 'http://' . $incoming_uri;
                }

                #Rewrite URI with scheme, port, path,...
                my $rewrite_uri = APR::URI->parse( $r->pool, $incoming_uri );
                $rewrite_uri->scheme('http');
                $rewrite_uri->scheme('https') if $r->is_https;
                $rewrite_uri->port( $r->get_server_port() );
                $rewrite_uri->path(
                    "/?$cookie_app_name=" . $session_app{_session_id} );

                #Set cookie
                #$r->err_headers_out->set('Location' => $rewrite_uri->unparse);
                my $dir;
                if ( $app->{name} =~ /\/(.*)/ ) {
                    $dir = $1;
                }
                $r->err_headers_out->add(
                    'Set-Cookie' => $r->dir_config('VultureAppCookieName') . "="
                      . $session_app{_session_id}
                      . "; path=/"
                      . $dir
                      . "; domain=."
                      . $r->hostname );

                #Redirect user to SSO portal
                $r->pnotes( 'response_content' =>
                      '<html><head><meta http-equiv="Refresh" content="0; url='
                      . $rewrite_uri->unparse
                      . '"/></head></html>' );
                $r->pnotes( 'response_content_type' => 'text/html' );

                $r->set_handlers( PerlAuthenHandler => undef );
                $r->set_handlers( PerlAuthzHandler  => undef );
                $r->set_handlers( PerlFixupHandler  => undef );
                return Apache2::Const::OK;

                #A plugin has send a $r->pnotes('url_to_mod_proxy') => proxify
            }
            else {

                #Destroy useless handlers
                $r->set_handlers( PerlAuthenHandler => undef );
                $r->set_handlers( PerlAuthzHandler  => undef );
                my $dir;
                if ( $app->{name} =~ /\/(.*)/ ) {
                    $dir = $1;
                }
                $r->err_headers_out->add(
                    'Set-Cookie' => $r->dir_config('VultureAppCookieName') . "="
                      . $session_app{_session_id}
                      . "; path=/"
                      . $dir
                      . "; domain=."
                      . $r->hostname );
                return Apache2::Const::OK;
            }
        }

        #SSO Portal
    }
    elsif (
        $r->hostname =~ $intf->{'sso_portal'}
        or (
            $unparsed_uri =~ /$cookie_app_name=([^;]*)/
            and Core::VultureUtils::get_app(
                $log, $r->hostname . $unparsed_uri,
                $dbh, $intf->{id}
            )
        )
      )
    {

        $log->debug('Entering SSO Portal mode.');

        #App coming from vulture itself
        if ( $unparsed_uri =~ /$cookie_app_name=([^;]*)/ ) {
            my $app_cookie_name = $1;
            my (%session_app);

            #Get app
            Core::VultureUtils::session( \%session_app, $app->{timeout},
                $app_cookie_name, $log, $mc_conf, $app->{update_access_time} );
            my $app =
              Core::VultureUtils::get_app( $log, $session_app{app_name}, $dbh,
                $intf->{id} );

            #Send app if exists.
            $r->pnotes( 'app' => $app ) if $app;
            $r->pnotes( 'id_session_app' => $app_cookie_name );
        }

        #Getting SSO session if exists.
        my $SSO_cookie_name = '';
        $SSO_cookie_name =
          Core::VultureUtils::get_cookie( $r->headers_in->{'Cookie'},
            $r->dir_config('VultureProxyCookieName') . '=([^;]*)' );
        $SSO_cookie_name ||= '';
        my (%session_SSO);

        Core::VultureUtils::session( \%session_SSO, $intf->{sso_timeout},
            $SSO_cookie_name, $log, $mc_conf, $intf->{sso_update_access_time} );

        #Get session id if not exists
        if ( $SSO_cookie_name ne $session_SSO{_session_id} ) {
            $log->debug("Replacing SSO id");
            $SSO_cookie_name = $session_SSO{_session_id};
        }

        my $dir = "";
        if ( $app->{name} =~ /\/(.*)/ ) {
            $dir = $1;
        }

        #Set cookie for SSO portal
        $r->err_headers_out->add(
                'Set-Cookie' => $r->dir_config('VultureProxyCookieName') . "="
              . $session_SSO{_session_id}
              . "; path=/"
              . $dir
              . "; domain=."
              . $r->hostname );

        $r->pnotes( 'id_session_SSO' => $SSO_cookie_name );

        #Destroy useless handlers
        $r->set_handlers( PerlFixupHandler => undef );

        return Apache2::Const::OK;

        #CAS Portal
    }
    elsif ( $r->hostname =~ $intf->{'cas_portal'} ) {
        return Apache2::Const::OK;

        #Application is down or unusable
    }
    elsif ( $app and defined $app->{'up'} and not $app->{'up'} ) {
        $log->error( 'Trying to redirect to '
              . $r->hostname
              . ' but failed because '
              . $r->hostname
              . ' is down' );
        $r->status(Apache2::Const::NOT_FOUND);

        #Custom error message
        my $translations =
          Core::VultureUtils::get_translations( $r, $log, $dbh, "APP_DOWN" );
        my $html =
          Core::VultureUtils::get_style( $r, $log, $dbh, $app, 'DOWN',
            'App is down', {}, $translations );
        $html |= '';
        $log->debug($html);
        $r->custom_response( Apache2::Const::NOT_FOUND, $html )
          if $html =~ /<body>.+<\/body>/;
        return Apache2::Const::NOT_FOUND;

        #Fail
    }
    else {
        $log->error( 'Trying to redirect to '
              . $r->hostname
              . ' but failed because '
              . $r->hostname
              . ' doesn\'t exist in Database' );
        $r->status(Apache2::Const::NOT_FOUND);
        return Apache2::Const::DONE;
    }
    return Apache2::Const::OK;
}
1;
