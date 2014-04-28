#file:Core/VultureUtils.pm
#-------------------------
#!/usr/bin/perl
package Core::VultureUtils;

use strict;
use warnings;

our $VERSION = '2.0.8';

BEGIN {
    use Exporter ();
    our @ISA = qw(Exporter);
    our @EXPORT_OK =
      qw(&get_memcached_conf &version_check &get_app &get_intf &session 
      &get_cookie &get_memcached &set_memcached &get_DB_object
      &get_LDAP_object &get_style &get_translations &generate_random_string 
      &notify &get_LDAP_field &get_SQL_field &load_module &is_JK &parse_set_cookie &parse_cookies
      &encrypt &decrypt &get_ua_object &get_http_request &get_app_cookies &get_mech_object);
}

use Apache::Session::Generate::MD5;
use Apache::Session::Flex;
use Apache2::Reload;

use Core::Config qw(&get_key);
use Core::Log qw(&new);

use DBI;

use Cache::Memcached;
use APR::Table;
use Math::Random::Secure qw(irand);

use Crypt::CBC;
use Crypt::OpenSSL::AES;
use MIME::Base64;

use HTTP::Request;
use LWP::UserAgent;
use Apache::SSLLookup;

our ($memd);

our %ssl_headers = (
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

sub version_check {
    my ($config) = @_;
    #Get config and compare with VERSION defined in the head of this file
    return ( $config->get_key('version') eq $VERSION );
}

sub get_memcached_conf {
    my ($config) = @_;
    my $var = $config->get_key('memcached');
    my @serv = ();
    for my $x ( split( ",", $var ) ) {
        $x =~ s/^\s+//;
        $x =~ s/\s+$//;
        push( @serv, $x );
    }
    return \@serv;
}

#get information stored in memcached
sub get_memcached {
    my ( $key, $mc ) = @_;
    my $memd = Cache::Memcached->new(
        servers            => $mc,
        debug              => 0,
        compress_threshold => 10_000,
    ) unless defined $memd;
    return $memd->get($key);
}

#set information into memcached
sub set_memcached {
    my ( $key, $value, $exptime, $mc ) = @_;
    my $memd = Cache::Memcached->new(
        servers            => $mc,
        debug              => 0,
        compress_threshold => 10_000,
    ) unless defined $memd;

    #limit expiration time to 6000
    $exptime = $exptime || 6_000;
    if ( $exptime > 6_000 ) {
        $exptime = 6_000;
    }

    return $memd->set( $key, $value, $exptime );
}

sub session {
    my ( $session, $timeout, $id, $log, $mc, $update_access_time, $n ) = @_;
    $update_access_time ||= 0;
    $n                  ||= 0;
    die if ( $n and int $n > 2 );    # avoid deep recursion

    eval {
        tie %{$session}, 'Apache::Session::Flex', $id,
          {
            Store     => 'Memcached',
            Lock      => 'Null',
            Generate  => 'MD5',
            Serialize => 'Storable',
            Servers   => $mc,
          };
    }
      or session( $session, $timeout, undef, $log, $mc, $update_access_time,
        int $n + 1 );

    #Session starting this time or previous session connection time was valid
    if (
        not defined $id
        or (    $update_access_time == 1
            and $timeout
            and $timeout > 0
            and ( time() - $session->{last_access_time} < $timeout )
            and ( $session->{'SSO_Forwarding'} ne 'FORWARD' )
            and ( $session->{'SSO_Forwarding'} ne 'LEARNING' ) )
      )
    {
        $session->{last_access_time} = time();
    }
    $session->{last_access_time} ||= 0;

    #Regenerate session if too old
    if (    defined $timeout
        and $timeout > 0
        and ( time() - $session->{last_access_time} > $timeout ) )
    {
        tied( %{$session} )->delete;
        session( $session, $timeout, undef, $log, $mc, $update_access_time,
            $n + 1 );
    }
    return $session;
}

sub get_cookie {
    my $cookie     = shift;
    my $expression = shift;
    my $ret;
    return undef if !$cookie or !$expression;
    if ( UNIVERSAL::isa( $expression, "ARRAY" ) ) {
        foreach ($expression) {
            return $ret if ( $ret = get_cookie( $cookie, $_ ) );
        }
    }
    if ( UNIVERSAL::isa( $cookie, "ARRAY" ) ) {
        foreach ($cookie) {
            return $ret if ( $ret = get_cookie( $_, $expression ) );
        }
    }
    ($ret) = ( $cookie =~ /$expression/ );
    return $ret;
}

sub get_app {
    my ( $log, $dbh,$mc_conf,$intf,$host ) = @_;
    my ( $query, $sth, $ref );
    return undef unless ( $host and $intf and $dbh );
    my $all_apps_key = "applist:$intf";
    my $apps = Core::VultureUtils::get_memcached($all_apps_key,$mc_conf);
    $log->debug("GET_APP: url is '$host'"); 
    unless (defined $apps){
#Getting app and wildcardsv
        $query =
    'SELECT app.id, app.name, app.alias, app.url, app.log_id, app.sso_forward_id AS sso_forward, app.logon_url, app.logout_url, intf.port, app.remote_proxy, app.up, app.auth_url,app.auth_basic, app.display_portal,app.check_csrf , app.canonicalise_url, app.timeout, app.update_access_time, app.sso_learning_ext, app.secondary_authentification_failure_options,app.Balancer_Activated, app.Balancer_Node,app.Balancer_Stickyness FROM app JOIN app_intf ON app.id = app_intf.app_id JOIN intf ON app_intf.intf_id = intf.id WHERE intf.id = ? ORDER BY app.name ASC';
        $log->debug($query);
        $sth = $dbh->prepare($query);
        $sth->execute($intf);
        $apps = $sth->fetchall_hashref('name');
        $sth->finish();
        $log->debug("set $all_apps_key in memcache");
        Core::VultureUtils::set_memcached($all_apps_key,$apps,60,$mc_conf);
    }else{
        $log->debug("got $all_apps_key from memcache");
    }
    # Convert appname and aliases into a single perl regex for each app.
    # (should be cached for performances improvement)
    # Match app with the deepest path, using name and alias for each application.
    # if we have two applications: appname.com, and appname.com/admin
    # appname.com/admin will be selected for url appname.com/admin/index.html.
    my $max_fields = -1;
    $host = "$host/" if not ($host =~ /\/$/);
    while ( my ( $name, $hashref ) = each(%$apps) ) {
        my $appreg = "$name $hashref->{alias}";
        $appreg =~ s/^\s+//g;
        $appreg =~ s/\s+$//g;
        $appreg =~ s/\s+/|/g;
        $appreg =~ s/([\.\/])/\\$1/g;
        $appreg =~ s/\*/\(\[a-zA-Z\\-0-9\]\+\)/g;
        $log->debug("GET_APP: test against ^($appreg)\\/");
        if ( $host =~ /^($appreg)\// ) {
            my $matched_name = $1;
            my $fi = 0;
            $fi++ while ( $matched_name =~ m/\//g );
            if ( $fi > $max_fields ) {
                $max_fields = $fi;
                $log->debug("GET_APP: selecting '$matched_name' ($fi)"); 
                $ref = $hashref;
                $ref->{name} = $matched_name;
            }
        }
    }
    # we still did'nt found the app
    return undef unless $ref->{id};
    $log->debug("GET_APP: found '$ref->{name}'"); 
    $ref->{'intf'} = $intf;
    #Use memcached if possible
    my $app_key = "$ref->{intf}-$ref->{name}:app";
    my $obj = Core::VultureUtils::get_memcached( $app_key, $mc_conf );
    if ($obj) {
        $log->debug("got memcached '$app_key'");
        $obj->{intf} = $intf;
        return $obj;
    }

#Getting auth
    $query =
' SELECT auth.name, auth.auth_type, auth.id_method,auth.id FROM auth JOIN app ON auth.id=app.auth_id WHERE app.id = ?';
    $sth = $dbh->prepare($query);
    $sth->execute($ref->{id});
    $ref->{'auth'} = $sth->fetchrow_hashref;
    $sth->finish();

#Getting ACL
    $query =
'SELECT acl.id, acl.name, auth.auth_type AS acl_type, auth.id_method FROM acl JOIN auth ON acl.auth_id = auth.id JOIN app ON acl.id = app.acl_id WHERE app.id = ?';
    $sth = $dbh->prepare($query);
    $sth->execute( $ref->{id} );
    $ref->{'acl'} = $sth->fetchrow_hashref;
    $sth->finish();

    #Getting actions
    $query =
"SELECT auth_server_failure_action, auth_server_failure_options, account_locked_action, account_locked_options, login_failed_action, login_failed_options, need_change_pass_action, need_change_pass_options, acl_failed_action, acl_failed_options FROM app WHERE app.id = ?";
    $sth = $dbh->prepare($query);
    $sth->execute( $ref->{id} );
    $ref->{'actions'} = $sth->fetchrow_hashref;
    $sth->finish();

    #Getting SSO
    $query =
"SELECT sso.type, sso.follow_get_redirect, sso.is_post, sso.verify_mech_cert FROM sso JOIN app ON sso.id = app.sso_forward_id WHERE app.id=?";
    $sth = $dbh->prepare($query);
    $sth->execute( $ref->{id} );
    $ref->{'sso'} = $sth->fetchrow_hashref;
    $sth->finish();

    $ref->{'is_jk'} = is_JK($log,$dbh,$ref->{id} );

    #Caching app if possible
    $log->debug("set memcached : '$app_key'");
    Core::VultureUtils::set_memcached( $app_key, $ref, 60, $mc_conf );
    return $ref;
}

sub get_intf {
    my ( $log, $dbh, $intf, $config, $mc_conf ) = @_;
    my ( $query, $sth, $ref );

    my $key = $config->get_key('name').":intf-$intf";
    $key =~ s/\s/_/g;
    my $obj = Core::VultureUtils::get_memcached($key,$mc_conf);
    if (defined $obj){
        $log->debug("got $key from memcached");
        return $obj;
    }
    #Getting intf
    $query =
"SELECT intf.id, ip, port, default_url, log_id, sso_portal, sso_timeout, ssl_conf.ssl_engine, ssl_conf.cert, ssl_conf.key, ssl_conf.ca, sso_update_access_time,check_csrf, cas_portal, cas_display_portal, cas_auth_basic AS auth_basic, cas_st_timeout, cas_redirect FROM intf JOIN ssl_conf ON ssl_conf.id = intf.ssl_configuration_id WHERE intf.id = ?";
    $sth = $dbh->prepare($query);
    $sth->execute($intf);
    $ref = $sth->fetchrow_hashref;
    $sth->finish();
#Getting auth (CAS)
    $query =
'SELECT auth.name, auth.auth_type, auth.id_method, auth.id FROM auth JOIN intf ON auth.id = intf.cas_auth_id WHERE intf.id = ?';
    $sth = $dbh->prepare($query);
    $sth->execute($ref->{id});
    $ref->{auth} = $sth->fetchrow_hashref;
    $sth->finish();

    #Getting actions
    $query =
"SELECT auth_server_failure_action, auth_server_failure_options, account_locked_action, account_locked_options, login_failed_action, login_failed_options, need_change_pass_action, need_change_pass_options FROM intf WHERE intf.id = ?";
    $log->debug($query);
    $sth = $dbh->prepare($query);
    $sth->execute( $ref->{id} );
    $ref->{'actions'} = $sth->fetchrow_hashref;
    $sth->finish();
    Core::VultureUtils::set_memcached( $key, $ref, 60, $mc_conf );
    $log->debug("save $key in memcached");
    return $ref;
}

#Getting DB object
sub get_DB_object {
    my ( $log, $dbh, $id_method ) = @_;
    my $query = "SELECT * FROM sql WHERE id = ?";
    my $sth   = $dbh->prepare($query);
    $log->debug($query);
    $sth->execute($id_method);
    my $ref = $sth->fetchrow_hashref;
    $sth->finish();

    #Let's connect to this new database and retrieve all fields
    if (not $ref){
        $log->error("Can't find DB object");
        return undef;
    }
    
    #Build a driver like "dbi:SQLite:dbname=/var/www/vulture/admin/db"
    my $dsn = 'dbi:' . $ref->{'driver'};
    if ( $ref->{'driver'} ne 'Oracle' ) {
        $dsn .= ':dbname=' . $ref->{'database'};
        if ( $ref->{'host'} ) {
            $dsn .= ':' . $ref->{'host'};
            if ( $ref->{'port'} ) {
                $dsn .= ':' . $ref->{'port'};
            }
        }
    }
    else {
        if ( $ref->{'host'} ) {
            $dsn .= '://' . $ref->{'host'};
            if ( $ref->{'port'} ) {
                $dsn .= ':' . $ref->{'port'};
            }
        }
        $dsn .= '/' . $ref->{'database'};
    }

    #my $dbi->{printError} = 0;
    my $dbi = DBI->connect( $dsn, $ref->{'user'}, $ref->{'password'});
    if ( not $dbi) {
        $log->debug("can't connect to secondary authentification");
    }
    return ( $dbi, $ref );
}

sub get_LDAP_object {
    my ( $log, $dbh, $id_method ) = @_;

    my $query =
"SELECT host, port, scheme, cacert_path, dn, password, base_dn, user_ou, user_scope, user_attr, user_filter, group_ou, group_scope, group_attr, group_filter, group_member, are_members_dn, url_attr, protocol, chpass_attr, user_account_locked_attr, user_mobile FROM ldap WHERE id = ?";
    $log->debug($query);
    my $sth = $dbh->prepare($query);
    $sth->execute($id_method);
    my (
        $ldap_server,       $ldap_port,
        $ldap_encrypt,      $ldap_cacert_path,
        $ldap_bind_dn,      $ldap_bind_password,
        $ldap_base_dn,      $ldap_user_ou,
        $ldap_user_scope,   $ldap_uid_attr,
        $ldap_user_filter,  $ldap_group_ou,
        $ldap_group_scope,  $ldap_group_attr,
        $ldap_group_filter, $ldap_group_member,
        $ldap_group_is_dn,  $ldap_url_attr,
        $ldap_protocol,     $ldap_chpass_attr,
        $ldap_account_locked_attr, $ldap_user_mobile
    ) = $sth->fetchrow;

    $ldap_cacert_path = "/var/www/vulture/conf/cacerts"
      if ( $ldap_cacert_path eq '' );
    $ldap_user_filter =
"(|(objectclass=posixAccount)(objectclass=inetOrgPerson)(objectclass=person))"
      if ( $ldap_user_filter eq '' );
    $ldap_group_filter =
"(|(objectclass=posixGroup)(objectclass=group)(objectclass=groupofuniquenames))"
      if ( $ldap_group_filter eq '' );

    my @servers;
    foreach ( split( /,\s*/, $ldap_server ) ) {
        push @servers, ( $ldap_encrypt eq "ldaps" ? "ldaps://" : "" ) . $_;
    }

    my $ldap;
    if ( $ldap_encrypt eq "ldaps" ) {
        $ldap = Net::LDAP->new(
            \@servers,
            port    => $ldap_port,
            version => $ldap_protocol,
            capath  => $ldap_cacert_path
        );
    }
    else {
        $ldap = Net::LDAP->new(
            \@servers,
            port    => $ldap_port,
            version => $ldap_protocol
        );
    }
    if ( $ldap_encrypt eq "start-tls" ) {
        $ldap->start_tls(
            verify => 'require',
            capath => $ldap_cacert_path
        );
    }
    if ( !$ldap ) {
        $log->error("LDAP connection to $ldap_server failed");
        return;
    }
    my $mesg = $ldap->bind( $ldap_bind_dn, password => $ldap_bind_password );

    if ( $mesg->code ) {
        $log->error("Unable to bind with $ldap_bind_dn on $ldap_server");
        return;
    }
    return (
        $ldap,              $ldap_url_attr,
        $ldap_uid_attr,     $ldap_user_ou,
        $ldap_group_ou,     $ldap_user_filter,
        $ldap_group_filter, $ldap_user_scope,
        $ldap_group_scope,  $ldap_base_dn,
        $ldap_group_member, $ldap_group_is_dn,
        $ldap_group_attr,   $ldap_chpass_attr,
        $ldap_account_locked_attr
    );
}

sub get_style {
    my ( $r, $log, $dbh, $app, $type, $title, $fields, $translations ) = @_;
    my ( $ref, $html );

    #return {} unless defined $app->{'id'};
    #Querying database for style
    my $intf_id = $r->dir_config('VultureID');
    my $query = " AS 'id_appearance', style_css.value AS css, style_image.image AS image, style_tpl.head as tpl_head, style_tpl.value AS tpl FROM app,intf, style_tpl LEFT JOIN style_style ON style_style.id = id_appearance LEFT JOIN style_css ON style_css.id = style_style.css_id LEFT JOIN style_image ON style_image.id = style_style.image_id ";
    if ($app and $app->{id}){
        $query = "SELECT app.appearance_id $query WHERE app.id='". $app->{id} ."'";
    }
    else{
        $query = "SELECT intf.appearance_id $query WHERE intf.id='$intf_id'";
    }
    $query .= " AND style_tpl.id=style_style.";
    my $tpl_types = {
        DOWN=>"app_down_tpl_id",
        LOGIN=>"login_tpl_id",
        ACL_FAILED=>"acl_tpl_id",
        DISPLAY_PORTAL=>"sso_portal_tpl_id",
        LEARNING=>"sso_learning_tpl_id",
        LOGOUT=>"logout_tpl_id",
        SSO_LOGIN=>"sso_login_tpl_id"
        };
    my $tpl_type = $tpl_types->{uc($type)}||'';
    unless ($tpl_type) {
        $log->debug( "get_style: unknown type (" . uc($type) . ")" );
        return;
    }
    $query .= $tpl_type; 
    $log->debug($query);
    my $sth = $dbh->prepare($query);
    $sth->execute;
    $ref = $sth->fetchrow_hashref;
    $sth->finish();

    #Headers
    ###################################
    $html = '<!DOCTYPE html><html><head>';
    $html .= ('<meta http-equiv="Content-Type" ' 
             .'content="text/html;charset=utf-8"/>');
    $html .= '<meta http-equiv="Content-Type" content="text/html;charset=utf-8"/>';
    $html .="<title>$title</title>";
    $html .= "<style type=\"text/css\">" . $ref->{css} . "</style>"
        if ( defined $ref->{css} );
    if ( defined $ref->{tpl_head} ){
        $html .= parse_template($r, $log, $dbh, $app,
            $ref->{tpl_head}, $translations, $fields, $ref->{image});
    }
    $html .= "</head><body>"; 

    #Parse template
    if ( defined $ref->{tpl} ) {
        $html .= parse_template($r, $log, $dbh, $app,
            $ref->{tpl}, $translations, $fields, $ref->{image});
    }
    $html .= '</body></html>';

    return $html;
}

sub parse_template{
    my ($r, $log, $dbh, $app,
        $template, $translations, $fields, $image) = @_;
    return join "", map {
        my ($directive) = $_ =~ /__(.+)__/s;
        if ($directive) {
            if ( $directive eq "IMAGE" ) {
                $_ =
                  "<img id=\"logo\" src=\"/static/"
                  . $image . "\" />"
                  if $image;
            }
            elsif ( $directive eq "APPNAME" ) {
                $_ = $app?$app->{name}:'';
            }
            elsif ($directive eq "LOGIN_NAME"){
                $_ = $r->pnotes("username");
            }
            elsif ($directive eq "LOGGED_AUTH"){
                my $intf = $r->pnotes('intf');
                my (%session_SSO);
                Core::VultureUtils::session( \%session_SSO, $intf->{sso_timeout},
                    $r->pnotes('id_session_SSO'),
                    $log, $r->pnotes('mc_conf'), $intf->{sso_update_access_time} );
                
                my $ok_auth = "{" . (join ",", map{  
                            "$1:\"" . js_escape($session_SSO{"auth_infos_$1"}{login}) .'"' if ($_ =~ /auth_infos_(\d+)/)
                            } grep {$_ =~ /^auth_infos_(\d+)$/}(keys %session_SSO)) . "}";

                my $auth = ($app and defined $app->{'auth'} ) ? $app->{'auth'} : $intf->{'auth'};
                if ( not $auth) {
                    $log->error("incorrect usage of LOGGED_AUTH");
                    $_ = $ok_auth;
                }else{
                    my $todo_auth = Core::VultureUtils::auth_to_string($dbh, $auth->{id});
                    $_ = "var ok_auth = $ok_auth; var todo_auth=$todo_auth;";
                }
            }
            elsif ( defined $fields->{$directive} ) {
                $_ = $fields->{$directive};
                #Custom translated string
            }
            elsif ( defined $translations->{$directive}
                and defined $translations->{$directive}{'translation'} )
            {
                $_ = $translations->{$directive}{'translation'};
            }
            else {
            }
        }
        else {
            $_ = $_;
        }
    } split( /(__.*?__)/s, $template );
}
sub get_translations {
    my ( $r, $log, $dbh, $message ) = @_;

    #Error message to translate / Form
    if ( !$r->headers_in->{'Accept-Language'} ) {
        $log->debug("get_translation: no Accept-Language header");
        return;
    }
    #Splitting Accept-Language headers
    # Prepare the list of client-acceptable languages
    my @arg_tab        = ();
    my $language_query = "country IN ( ";
    my $c              = 0;
    my %lang_qual;
    foreach my $tag ( split( /,/, $r->headers_in->{'Accept-Language'} ) ) {
        my ( $language, $quality ) = split( /\;/, $tag );
        if ($language eq '*' or not defined $quality){
            $quality = 1;
        }
        else{
            $quality =~ s/^q=//i;
            $quality = 1 if $quality eq '';
        }
        next if $quality <= 0 ;
        $log->debug("LANG : $language => $quality");

        my $lclang = lc($language);
        push( @arg_tab, $lclang);
        $language_query .= "," if $c > 0;
        $language_query .= " ? ";
        $lang_qual{$lclang}=$quality 
            if (!exists $lang_qual{$lclang} or $lang_qual{$lclang}<$quality);
        if ( $lclang =~ /^([^-]+)-([^-]+)$/ ) {
            $language_query .= ", ? , ? ";
            push( @arg_tab, $1 );
            push( @arg_tab, $2 );
            $lang_qual{$1}=$quality 
                if (!exists $lang_qual{$1} or $lang_qual{$1}<$quality);
            $lang_qual{$2}=$quality 
                if (!exists $lang_qual{$2} or $lang_qual{$2}<$quality);
        }
        $c++;
    }
    $language_query .= " ) ";

    #Message translation
    my $message_query = "message  IN ( 'USER', 'PASSWORD', 'APPLICATION','SUBMIT'";
    if ( defined $message and $message ne '' ) {
        $message_query .= ", ? ";
        push( @arg_tab, $message );
    }
    $message_query .= ")";
    my $query =
        "SELECT country, message, translation FROM localization WHERE "
      . $language_query . " AND "
      . $message_query;
    my $sth = $dbh->prepare($query);
    $c = 1;
    foreach my $par (@arg_tab) {
        $sth->bind_param( $c, $par );
        $c += 1;
    }
    $sth->execute();
    my $arref = $sth->fetchall_arrayref();
    my $href = {};
    my @msgs = ("USER","PASSWORD","APPLICATION");
    push(@msgs,$message)
        if (defined $message and $message ne '');
    foreach my $row (@{$arref}){
        my ($country_r, $msg_r, $trans_r) = @$row;
        my $qual = $lang_qual{$country_r};
        if (!exists $href->{$msg_r} or $href->{$msg_r}->{quality}<$qual){
            $href->{$msg_r} = {
                message => $msg_r,
                translation => $trans_r,
                quality => $qual
            };
        }
    }
    return $href;
}

sub generate_random_string {
    my $length_of_randomstring = shift;

    # the length of the random string to generate

    my @chars = ( 'a' .. 'z', 'A' .. 'Z', '0' .. '9', '-' );
    my $clen = @chars;
    my $random_string = '';
    foreach ( 1 .. $length_of_randomstring ) {
        $random_string .= $chars[ irand($clen) ];
    }
    return $random_string;
}

sub notify {
    my ( $dbh, $app_id, $user, $type, $info ) = @_;
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
      localtime();
    $year += 1900;
    $mon += 1;
    my $e_ts = "$year-$mon-$mday $hour:$min:$sec.0";

    #Filling database
    my $query =
"INSERT INTO event_logger ('app_id', 'user', 'event_type', 'timestamp', 'info') VALUES (?,?,?,?,?)";
    my $sth = $dbh->prepare($query);

    #Notify event to db
    $sth->execute( $app_id, $user, $type, $e_ts, undef );

    #Log active users
    $sth->execute( $app_id, $user, 'active_sessions', $e_ts, $info );
    $sth->finish();
}
sub get_SQL_field {
    my ($log,$dbh,$sql_id,$login,$field) = @_;
    my ( $new_dbh, $ref ) = get_DB_object( $log, $dbh, $sql_id );
    if (not $new_dbh or not $ref){
        $log->error("SQL: Unable to use sql method $sql_id");
        return undef;
    }
    my $qsql = ("SELECT $field FROM $ref->{'table'} "
     . "WHERE $ref->{'user_column'}=?");
    $log->debug($qsql);
    my $ssth = $new_dbh->prepare($qsql);
    $ssth->execute($login);
    my $result = $ssth->fetchrow;
    $ssth->finish();
    $new_dbh->disconnect();
    return ($result) if ($result);
    $log->error("unable to retreive $field of user $login in SQL");
    return undef;
 }

sub is_JK {
    my ($log,$dbh,$id)=@_;
    my $query = 'select count(*) from jk_worker_directives LEFT JOIN app ON app.id=jk_worker_directives.app_id where app.id=?';
    my $sth = $dbh->prepare($query);
    $sth->execute($id);
    return $sth->fetchrow > 0;
}

sub get_LDAP_field {
    my ($log, $dbh,$ldap_id,$login,$field) = @_;
    my (
        $ldap,              $ldap_url_attr,
        $ldap_uid_attr,     $ldap_user_ou,
        $ldap_group_ou,     $ldap_user_filter,
        $ldap_group_filter, $ldap_user_scope,
        $ldap_group_scope,  $ldap_base_dn,
        $ldap_group_member, $ldap_group_is_dn,
        $ldap_group_attr,   $ldap_chpass_attr,
        $ldap_account_locked_attr
    ) = Core::VultureUtils::get_LDAP_object( $log, $dbh, $ldap_id );
    unless ($ldap) {
        $log->error("LDAP: cannot get ldap object $ldap_id");
        return undef;
    }
    my $user = Net::LDAP::Util::escape_filter_value($login);
    my $filter = "(&"
          . $ldap_user_filter . "("
          . $ldap_uid_attr . "="
          . $user . "))";
    $log->debug( "[LDAP SEARCH] $field where $filter");
    my $result = $ldap->search(
               base => $ldap_user_ou ? $ldap_user_ou : $ldap_base_dn,
        scope  => $ldap_user_scope,
               filter => $filter,
        attrs => [$field]
    );
    $ldap->unbind;
    if (not $result->count ) {
        $log->error("LDAP: Unable to get $field for $user in LDAP");
        return undef;
    }
    return $result->entry->get_value($field);
}
sub load_module{
    my ($module_name,$func)= @_;
#load function from module
    eval {
    ( my $file = $module_name ) =~ s|::|/|g;
        require $file . '.pm';
        $module_name->import($func);
        1;
    } or do {
        my $error = $@;
        return $error;
    };
}
sub parse_set_cookie {
        my $sc = shift;
        my $i=0;
        my $tab = {};
        foreach my $v (split (';',$sc)) {
                if ($i eq 0) {
                        $i++;
                        ($tab->{"name"},$tab->{"value"}) = split ('=',$v);
                } else {
                        my ($t,$u) = split ('=',$v);
                        $tab->{trim($t)} = $u;
                }
        }
        return $tab;
}
sub parse_cookies{
        my $sc = shift;
        my $tab = {};
        foreach my $v (split (';',$sc)) {
            my ($t,$u) = split ('=',$v);
            $tab->{trim($t)} = $u;
        }
        return $tab;
}
sub trim{
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    return $string;
}
sub js_escape {
    my $arg = shift;
    $arg =~ s/\\/\\\\/g;
    $arg =~ s/\n/\\n/g;
    $arg =~ s/"/\\"/g;
    return $arg;
}
sub auth_to_string{
    my ($dbh, $auth_id) = @_;
    my $sth = $dbh->prepare("SELECT name, auth_type, id_method FROM auth WHERE id=?");
    $sth->execute($auth_id);
    my ($name, $type, $id_m) = $sth->fetchrow_array();
    $sth->finish();
    my ($op, $childs) = ('',''); 
    if ($type eq 'logic'){
        $sth = $dbh->prepare("SELECT op FROM logic WHERE id = ?");
        $sth->execute($id_m);
        ($op) = $sth->fetchrow_array;
        $sth->finish;
        $sth = $dbh->prepare("SELECT auth_id FROM logic_auths WHERE logic_id=?");
        $sth->execute($id_m);
        my @row = $sth->fetchrow_array;
        while (@row){
            $childs.= auth_to_string($dbh, $row[0]). ",";
            @row = $sth->fetchrow_array;
        }    
        $sth->finish();
    }
    $name = js_escape($name);
    my $json = "data: {title:\"$name\"}, metadata: { id: $auth_id, type: \"$type\"";
    $json .= ", op: \"$op\"" if $op;
    $json .= "}";
    $json .= " , children: [$childs]" if $childs;
    return "{$json}";
}
sub encrypt {
    my ( $r, $value_to_encrypt ) = @_;

    #Opening key file for encryption
    my $conf = $r->dir_config('VultureConfPath');
    open( my $fh, "<", $conf . 'aes-encrypt-key.key' )
      or die "cannot open < $conf aes-encrypt-key.key : $!";
    my @lines = <$fh>;
    my $key   = $lines[0];

    #Encrypting
    my $cipher = Crypt::CBC->new(
        -key    => $key,
        -cipher => "Crypt::OpenSSL::AES"

          #			-header => 'none'
    );
    my $value = $cipher->encrypt($value_to_encrypt);
    close $fh or die $!;
    return encode_base64($value);
}

sub decrypt {
    my ( $r, $value_to_decrypt ) = @_;

    #Opening key file for encryption
    my $conf = $r->dir_config('VultureConfPath');
    open( my $fh, "<", $conf . 'aes-encrypt-key.key' )
      or die "cannot open < $conf aes-encrypt-key.key : $!";
    my @lines = <$fh>;
    my $key   = $lines[0];

    #Encrypting
    my $cipher = Crypt::CBC->new(
        -key    => $key,
        -cipher => "Crypt::OpenSSL::AES"

          #			-header => 'none'
    );
    my $value = $cipher->decrypt(decode_base64($value_to_decrypt));
    close $fh or die $!;
    return $value;

}
sub get_ua_object {
    my ($r, $remote_proxy) = @_;
    my $config = $r->pnotes('config');
    my $ua = LWP::UserAgent->new;
    if ( $remote_proxy ne '' ) {
        $ua->proxy( [ 'http', 'https' ], $remote_proxy );
    }
    eval{
        $ua->ssl_opts ( verify_hostname => 1 );
    };
    my $SSL_ca_file = $config->get_key('SSL_ca_file')||'';
    if ($SSL_ca_file){
        eval{
            $ua->ssl_opts(SSL_ca_file => $SSL_ca_file);
        };
    }
    return $ua;
}
sub get_mech_object{
    my ($r, $remote_proxy,$sso_verify_mech_cert) = @_;
    my $config = $r->pnotes('config');
    my %ssl_opts = (
        verify_hostname => $sso_verify_mech_cert,
    );
    my $SSL_ca_file = $config->get_key('SSL_ca_file')||'';
    if ($SSL_ca_file){
        $ssl_opts{SSL_ca_file} = $SSL_ca_file;
    }
    my $mech = WWW::Mechanize::GZip->new(ssl_opts => \%ssl_opts);
    if ( $remote_proxy ne '' ) {
        if ( $remote_proxy =~ /(.*)\/$/ ) {
            $remote_proxy = $1;
        }
        $mech->proxy(['http', 'https'], $remote_proxy);
    }
    return $mech;
}
sub get_http_request{
    my ($r, $dbh, $app_id, $method, $url, $data) = @_;
    my $req = Apache::SSLLookup->new($r);
    my $http_req = HTTP::Request->new( $method, $url , undef, $data);

    #Setting headers
    $http_req->remove_header('User-Agent');
    $http_req->push_header('User-Agent' => $req->headers_in->{'User-Agent'});
    #Pushing cookies
    $http_req->remove_header( 'Cookie');
    $http_req->push_header( 'Cookie' => Core::VultureUtils::get_app_cookies($r));

    my $sth = $dbh->prepare("SELECT name, type, value FROM header WHERE app_id= ?");
    $sth->execute( $app_id );

    #Push specific headers to get the right form
    while ( my ( $h_name, $h_type, $h_value ) = $sth->fetchrow ) {
        if ( $h_type eq "REMOTE_ADDR" ) {
            $h_value = $r->connection->remote_ip;
            #Nothing to do
        }
        elsif ( $h_type eq "CUSTOM" ) {
            #Types related to SSL
        }
        else {
            $h_value = $req->ssl_lookup( $ssl_headers{$h_type} )
              if ( exists $ssl_headers{$h_type} );
        }
        #Try to push custom headers
        eval {
            $http_req->remove_header($h_name);
            $http_req->push_header($h_name => $h_value);
        };
    }
    return $http_req;
}
sub get_app_cookies{
    my ($r) = @_;
    my $cookies = $r->headers_in->{Cookie};
    my $cleaned_cookies = '';
    if ($cookies){
        foreach ( split( ';', $cookies ) ) {
            if (/([^,; ]+)=([^,;]*)/) {
                if (    $1 ne $r->dir_config('VultureAppCookieName')
                    and $1 ne $r->dir_config('VultureProxyCookieName') )
                {
                    $cleaned_cookies .= $1 . "=" . $2 . ";";
                }
            }
        }
    }
    return $cleaned_cookies;
}

1;
