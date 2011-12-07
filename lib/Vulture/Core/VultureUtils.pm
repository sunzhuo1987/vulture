#file:Core/VultureUtils.pm
#-------------------------
package Core::VultureUtils;
our $VERSION = '2.0.2';

BEGIN {
    use Exporter ();
    our @ISA = qw(Exporter);
    our @EXPORT_OK = qw(&version_check &get_app &get_intf &session &get_cookie &get_memcached &set_memcached &get_DB_object &get_LDAP_object &get_style &get_translations &generate_random_string &notify);
}

use Apache::Session::Generate::MD5;
use Apache::Session::Flex;
use Apache2::Reload;

use Core::Config qw(&get_key);

use DBI;

use Cache::Memcached;
use APR::Table;

our ($memd);

sub	version_check {
	my ($config) = @_;
	#Get config and compare with VERSION defined in the head of this file
	return ($config->get_key('version') eq $VERSION);
}

sub	get_memcached {
	my ($key) = @_; 
	my $memd = Cache::Memcached->new(
	  servers            => [ "127.0.0.1:9091" ],
	  debug              => 0,
	  compress_threshold => 10_000,
	) unless defined $memd;
	return $memd->get($key);
}

sub	set_memcached {
	my ($key, $value, $exptime) = @_; 
	my $memd = Cache::Memcached->new(
	  servers            => [ "127.0.0.1:9091" ],
	  debug              => 0,
	  compress_threshold => 10_000,
	) unless defined $memd;

	$exptime= $exptime || 6_000;
        if ( $exptime > 6_000 ) {
                $exptime= 6_000;
        }

	return $memd->set($key, $value, $exptime);
}

sub	session {
	my ($session, $timeout, $id, $log, $update_access_time, $n) = @_;

	die if ($n and $n > 2); # avoid deep recursion
#	eval {
#		tie %$session,'Apache::Session::Flex',$id,{
#							   Store => 'MySQL',
#							   Lock  => 'Null',
#							   Generate => 'MD5',
#							   Serialize => 'Base64',
#							   DataSource => 'dbi:SQLite2:dbname=/var/www/vulture/sql/sessions',
#							  }
#	} or session($session, $timeout, undef, $log, $update_access_time, $n + 1);
    eval {
        tie %{$session}, 'Apache::Session::Flex', $id, {
				          Store     => 'Memcached',
				          Lock      => 'Null',
				          Generate  => 'MD5',
				          Serialize => 'Storable',
				          Servers => '127.0.0.1:9091',
				         };
    } or session($session, $timeout, undef, $log, $update_access_time, $n + 1);
    
    #Session starting this time or previous session connection time was valid
    if(not defined $id or ($update_access_time == 1 and $timeout and $timeout > 0 and (time() - $session->{last_access_time} < $timeout))){
        $session->{last_access_time} = time();
    }
    
    #Regenerate session if too old
    if ($timeout and $timeout > 0 and (time() - $session->{last_access_time} > $timeout)){
        tied(%{$session})->delete();
        session($session, $timeout, undef, $log, $update_access_time, $n + 1);
    }
    
    return $session;
}

sub	get_cookie {
	my $cookie = shift;
	my $expression = shift;
	my $ret;

	return undef if !$cookie or !$expression;

	if (UNIVERSAL::isa($expression, "ARRAY")) {
		foreach ($expression) {
			if ($ret = get_cookie($cookie, $_)) {
				return $ret;
			}
		}
	}
	if (UNIVERSAL::isa($cookie, "ARRAY")) {
		foreach ($cookie) {
			if ($ret = get_cookie($_, $expression)) {
				return $ret;
			}
		}
	}

	($ret) = ($cookie =~ /$expression/);
	return $ret;
}

sub	get_app {
	my ($log, $host, $dbh, $intf) = @_;
    my ($query, $sth, $ref);
    
    #Getting app and wildcards
    return {} unless ($host and $intf and $dbh);
    $query = "SELECT app.id, app.name, app.alias, app.url, app.log_id, app.sso_forward_id AS sso_forward, app.logon_url, app.logout_url, intf.port, app.remote_proxy, app.up, app.auth_basic, app.display_portal, app.canonicalise_url, app.timeout, app.update_access_time FROM app, intf, app_intf WHERE intf.id = ? AND app_intf.intf_id = intf.id AND app.id = app_intf.app_id";
	$log->debug($query);
	$sth = $dbh->prepare($query);
	$sth->execute($intf);
    $apps = $sth->fetchall_hashref('name');
    $sth->finish();

    while ( my ($name, $hashref) = each(%$apps) ) {
        #Exact matching
        if ($name eq $host) {
            $ref = $apps->{$name};
            last;
        }
        
        #Wildcard
        my $cpy = $hashref->{alias};
        $cpy =~ s|\*|\(\.\*\)|g;
        if ($host =~ /$cpy/) {
            $ref = $apps->{$name};
            $ref->{name} = $host;
            last;
        }
    }
    return {} unless $ref->{id};
	
    #Getting auth
    $query = "SELECT auth.name, auth.auth_type, auth.id_method FROM auth, auth_multiple WHERE auth_multiple.app_id = ? AND auth_multiple.auth_id = auth.id";
    $log->debug($query);
    $ref->{'auth'} = $dbh->selectall_arrayref($query, undef, $ref->{id});

    #Getting ACL
    $query = "SELECT acl.id, acl.name, auth.auth_type AS acl_type, auth.id_method FROM acl, auth, app WHERE app.id = ? AND acl.id = app.acl_id AND auth.id = acl.auth_id";
    $log->debug($query);
    $sth = $dbh->prepare($query);
	$sth->execute($ref->{id});
	$ref->{'acl'} = $sth->fetchrow_hashref;
	$sth->finish();
    
    #Getting actions
    $query = "SELECT login_failed_action, login_failed_options, need_change_pass_action, need_change_pass_options, acl_failed_action, acl_failed_options FROM app WHERE app.id = ?";
    $log->debug($query);
    $sth = $dbh->prepare($query);
	$sth->execute($ref->{id});
    $ref->{'actions'} = $sth->fetchrow_hashref;
	$sth->finish();

	return $ref;
}


sub	get_intf {
	my ($log, $dbh, $intf) = @_;
    my ($query, $sth, $ref);
    
    #Getting intf
	$query = "SELECT id, ip, port, ssl_engine, log_id, sso_portal, sso_timeout, sso_update_access_time, cert, key, ca, cas_portal, cas_st_timeout FROM intf WHERE id = ?";
	$log->debug($query);
    $sth = $dbh->prepare($query);
	$sth->execute($intf);
	$ref = $sth->fetchrow_hashref;
	$sth->finish();
    
    #Getting auth (CAS)
    $query = "SELECT auth.name, auth.auth_type, auth.id_method FROM auth, intf_auth_multiple WHERE intf_auth_multiple.intf_id = ? AND intf_auth_multiple.auth_id = auth.id";
    $log->debug($query);
    $ref->{'auth'} = $dbh->selectall_arrayref($query, undef, $ref->{id});
	return $ref;
}

#Getting DB object
sub get_DB_object{
    my ($log, $dbh, $id_method) = @_;
    my $query = "SELECT * FROM sql WHERE id = ?";
    my $sth = $dbh->prepare($query);
    $log->debug($query);
    $sth->execute($id_method);
    my $ref = $sth->fetchrow_hashref;
    $sth->finish();

    #Let's connect to this new database and retrieve all fields
    if($ref){
	    #Build a driver like "dbi:SQLite:dbname=/var/www/vulture/admin/db"
	    my $dsn = 'dbi:'.$ref->{'driver'}.':dbname='.$ref->{'database'};
	    if($ref->{'host'}){
		    $dsn .=':'.$ref->{'host'};
		    if($ref->{'port'}){
			    $dsn .=':'.$ref->{'port'};
		    }
	    }
	    return (DBI->connect($dsn, $ref->{'user'}, $ref->{'password'}), $ref);
    }
    $log->error("Can't find DB object");
    return;
}

sub get_LDAP_object{
	my ($log, $dbh, $id_method) = @_;

	my $query = "SELECT host, port, scheme, cacert_path, dn, password, base_dn, user_ou, user_scope, user_attr, user_filter, group_ou, group_scope, group_attr, group_filter, group_member, are_members_dn, url_attr, protocol, chpass_attr FROM ldap WHERE id = ?";
	$log->debug($query);
	my $sth = $dbh->prepare($query);
	$sth->execute($id_method);
	my ($ldap_server, $ldap_port, $ldap_encrypt, $ldap_cacert_path, 
        $ldap_bind_dn, $ldap_bind_password, $ldap_base_dn, 
        $ldap_user_ou, $ldap_user_scope, $ldap_uid_attr, $ldap_user_filter, 
        $ldap_group_ou, $ldap_group_scope, $ldap_group_attr,
	    $ldap_group_filter, $ldap_group_member, $ldap_group_is_dn,
	    $ldap_url_attr, $ldap_protocol, $ldap_chpass_attr) = $sth->fetchrow;

	$ldap_cacert_path="/var/www/vulture/conf/cacerts" if ($ldap_cacert_path eq '');
	$ldap_user_filter = "(|(objectclass=posixAccount)(objectclass=inetOrgPerson)(objectclass=person))"
	  if ($ldap_user_filter eq '');
	$ldap_group_filter = "(|(objectclass=posixGroup)(objectclass=group)(objectclass=groupofuniquenames))"
	  if ($ldap_group_filter eq '');

	my @servers;
	foreach (split(/,\s*/, $ldap_server)) {
		push @servers, ($ldap_encrypt eq "ldaps" ? "ldaps://" : "") . $_ ;
	}

	my $ldap;
	if ( $ldap_encrypt eq "ldaps") {
		$ldap = Net::LDAP->new(\@servers,
				       port => $ldap_port,
				       version => $ldap_protocol,
				       capath => $ldap_cacert_path
				      );
	}
	else {
		$ldap = Net::LDAP->new(\@servers,
				       port => $ldap_port,
				       version => $ldap_protocol
				      );
	}
	if ($ldap_encrypt eq "start-tls") {
		$ldap->start_tls(
				verify => 'require',
				capath => $ldap_cacert_path
				);
	}
	if (!$ldap) {
		$log->error("LDAP connection to $ldap_server failed");
		return ;
	}
	my $mesg = $ldap->bind($ldap_bind_dn, password => $ldap_bind_password);

	if ($mesg->code) {
		$log->error("Unable to bind with $ldap_bind_dn on $ldap_server");
		return ;
	}
	return ($ldap, $ldap_url_attr, $ldap_uid_attr, $ldap_user_ou, $ldap_group_ou, $ldap_user_filter, $ldap_group_filter, $ldap_user_scope, $ldap_group_scope, $ldap_base_dn, $ldap_group_member, $ldap_group_is_dn, $ldap_group_attr, $ldap_chpass_attr);
}

sub get_style {
    my ($r, $log, $dbh, $app, $type, $title, $fields, $translations) = @_;
    my ($ref, $html);
    #
    # ONLY FOR SQLITE3
    #
    #return {} unless defined $app->{'id'};
    #Querying database for style
    my $intf_id = $r->dir_config('VultureID');
    my $query = "SELECT CASE WHEN app.appearance_id NOT NULL THEN app.appearance_id WHEN intf.appearance_id NOT NULL THEN intf.appearance_id ELSE '' END AS 'id_appearance', style_css.value AS css, style_image.image AS image, style_tpl.value AS tpl FROM app,intf, style_tpl LEFT JOIN style_style ON style_style.id = id_appearance LEFT JOIN style_css ON style_css.id = style_style.css_id LEFT JOIN style_image ON style_image.id = style_style.image_id WHERE ";
    
    #App id if not null
    $query .= "app.id= '".$app->{id}."' AND " if ($app->{id});
    $query .= "intf.id = '".$intf_id."' AND style_tpl.id = style_style.";
    if(uc($type) eq 'APP_DOWN'){
        $query .=  "app_down_tpl_id";
    } elsif(uc($type) eq 'LOGIN'){
        $query .= "login_tpl_id";
    } elsif(uc($type) eq 'ACL_FAILED'){
        $query .= "acl_tpl_id";
    } elsif(uc($type) eq 'DISPLAY_PORTAL'){
        $query .= "sso_portal_tpl_id";
    } elsif(uc($type) eq 'LEARNING'){
        $query .= "sso_learning_tpl_id";
    } elsif(uc($type) eq 'LOGOUT'){
        $query .= "logout_tpl_id";
    } else {
        return;
    }
    $log->debug($query);
    my $sth = $dbh->prepare($query);
    $sth->execute;
    $ref = $sth->fetchrow_hashref;
    $sth->finish();
    
    #Headers
    $html = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><title>'.$title.'</title>';
    $html .= "<style type=\"text/css\">".$ref->{css}."</style>" if (defined $ref->{css});
    $html .= "</head><body>";
    
    #Parse template
    if(defined $ref->{tpl}){
        $log->debug("Parse template");
        $html .= join "",map {
            my ($directive) = $_ =~ /__(.+)__/s;
            if ($directive){
                if ($directive eq "IMAGE"){
                    $_ = "<img id=\"logo\" src=\"/static/".$ref->{image}."\" />" if $ref->{image};
                } elsif (defined $fields->{$directive}){
                    $_ = $fields->{$directive};
                #Custom translated string
                } elsif (defined $translations->{$directive} and defined $translations->{$directive}{'translation'}){
                    $_ = $translations->{$directive}{'translation'};
                } else {
                }
            } else {
                $_ = $_;        
            }
        } split (/(__.*?__)/s, $ref->{tpl});
    }    
    $html .= '</body></html>';
    
	return $html;
}

sub get_translations {
    my ($r, $log, $dbh, $message) = @_;
        #Error message to translate / Form
    if($r->headers_in->{'Accept-Language'}){
        #Splitting Accept-Language headers
        # Prepare the list of client-acceptable languages
        my @languages = ();
        foreach my $tag (split(/,/, $r->headers_in->{'Accept-Language'})) {
            my ($language, $quality) = split(/\;/, $tag);
            $quality =~ s/^q=//i if $quality;
            $quality = 1 unless $quality;
            next if $quality <= 0;
            # We want to force the wildcard to be last
            $quality = 0 if ($language eq '*');
            # Pushing lowercase language here saves processing later
            push(@languages, { quality => $quality,
            language => $language,
            lclanguage => lc($language) });
        }
        @languages = sort { $b->{quality} <=> $a->{quality} } @languages;

        my $currentLanguage;

        foreach my $tag (@languages){
        
            #Querying data for language accepted by the server
            my $query = "SELECT count(*) FROM localization WHERE country = '".$tag->{lclanguage}."'";
            if ($tag->{lclanguage} =~ /^([^-]+)-([^-]+)$/){
                $query .= " OR country = '".$1."' OR country = '".$2."'";
            }
            $log->debug($query);
            if ($dbh->selectrow_array($query)){
                $currentLanguage = $tag->{lclanguage};
                last;
            }
        }
        my $language_query = "country = '".$currentLanguage."'";
        if ($currentLanguage =~ /^([^-]+)-([^-]+)$/){
            $language_query .= " OR country = '".$1."' OR country = '".$2."'";
        }
        
        #Message translation
        my $message_query = "message = 'USER' OR message = 'PASSWORD' OR message = 'APPLICATION'";
        $message_query .= " OR message = '".$message."'" if defined $message;

        my $query = "SELECT message, translation FROM localization WHERE (".$message_query.") AND (".$language_query.")";        
        $log->debug($query);

        return $dbh->selectall_hashref($query,'message');
    }
}

sub generate_random_string
{
	my $length_of_randomstring=shift;
    # the length of the random string to generate

	my @chars=('a'..'z','A'..'Z','0'..'9','-');
	my $random_string;
	foreach (1..$length_of_randomstring) 
	{
		# rand @chars will generate a random 
		# number between 0 and scalar @chars
		$random_string.=$chars[rand @chars];
	}
	return $random_string;
}

sub notify {
    my ($dbh, $app_id, $user, $type, $info) = @_;
    #Filling database
    my $query = "INSERT INTO event_logger ('app_id', 'user', 'event_type', 'timestamp', 'info') VALUES (?,?,?,?,?)";
    my $sth = $dbh->prepare($query);
    #Notify event to db
    $sth->execute($app_id, $user, $type, time, undef);
    #Log active users
    $sth->execute($app_id, $user, 'active_sessions', time, $info);
    $sth->finish();
}
1;