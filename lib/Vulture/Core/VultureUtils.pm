#file:Core/VultureUtils.pm
#-------------------------
package Core::VultureUtils;
our $VERSION = '2.0';

BEGIN {
    use Exporter ();
    @ISA = qw(Exporter);
    @EXPORT_OK = qw(&version_check &get_app &get_intf &session &get_cookie &get_memcached &set_memcached &getDB_object &getLDAP_object &getStyle &getTranslations &generate_random_string);
}

use Apache::Session::Generate::MD5;
use Apache::Session::Flex;
use DBI;
use Apache2::Log;
use Apache2::Reload;
use Cache::Memcached;
use APR::Table;

our ($memd);

sub	version_check {
	my ($dbh, $log) = @_;
	
	#Querying database and compare with VERSION defined in the head of this file
	$query = "SELECT count(*) FROM conf WHERE var='version' AND value='".$VERSION."'";
	#$log->debug($query);
	return ($dbh->selectrow_array($query));
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

    #Getting app
    my $query = "SELECT app.id,name, url, app.log_id, logon_url, logout_url,intf.port, intf.remote_proxy, up, auth_basic, display_portal, canonicalise_url, sso_forward_id AS sso_forward, timeout, update_access_time FROM app, intf, app_intf WHERE app_intf.intf_id='".$intf."' AND app.id = app_intf.app_id AND app.name = '".$host."' AND intf.id='".$intf."'";
	#$log->debug($query);
	$sth = $dbh->prepare($query);
	$sth->execute;
	my $ref = $sth->fetchrow_hashref;
	$sth->finish();

    #Getting auth
    my $query = "SELECT auth.name, auth.auth_type, auth.id_method FROM auth, auth_multiple WHERE auth_multiple.app_id = '".$ref->{id}."' AND auth_multiple.auth_id = auth.id";
    $ref->{'auth'} = $dbh->selectall_arrayref($query);

    #Getting ACL
    $query = "SELECT acl.id, acl.name, auth.auth_type AS acl_type, auth.id_method FROM acl, auth, app WHERE app.id = '".$ref->{id}."' AND acl.id = app.acl_id AND auth.id = acl.auth_id";
    $sth = $dbh->prepare($query);
	$sth->execute;
	$ref->{'acl'} = $sth->fetchrow_hashref;
	$sth->finish();

	return $ref;
}


sub	get_intf {
	my ($log, $dbh, $intf) = @_;

	my $query = "SELECT id, ip, port, ssl_engine, log_id, sso_portal, cert, key, ca FROM intf WHERE id='".$intf."'";
	$sth = $dbh->prepare($query);
	$sth->execute;
	my $ref = $sth->fetchrow_hashref;
	$sth->finish();
	return $ref;
}

#Getting DB object
sub getDB_object{
    my ($log, $dbh, $id_method) = @_;
    my $query = "SELECT * FROM sql WHERE id='".$id_method."'";
    my $sth = $dbh->prepare($query);
    $log->debug($query);
    $sth->execute;
    my $ref = $sth->fetchrow_hashref;
    $sth->finish();

    #Let's connect to this new database and retrieve all fields
    if($ref){
	    #Build a driver like this one "dbi:SQLite:dbname=/var/www/vulture/admin/db"
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

sub getLDAP_object{
	my ($log, $dbh, $id_method) = @_;

	my $query = "SELECT host, port, scheme, cacert_path, dn, password, base_dn, user_scope, user_attr, user_filter, group_scope, group_attr, group_filter, group_member, are_members_dn, url_attr, protocol FROM ldap WHERE id='".$id_method."'";
	$log->debug($query);
	my $sth = $dbh->prepare($query);
	$sth->execute;
	my ($ldap_server, $ldap_port, $ldap_encrypt, $ldap_cacert_path, $ldap_bind_dn,
	    $ldap_bind_password, $ldap_base_dn, $ldap_user_scope, $ldap_uid_attr,
	    $ldap_user_filter, $ldap_group_scope, $ldap_group_attr,
	    $ldap_group_filter, $ldap_group_member, $ldap_group_is_dn,
	    $ldap_url_attr, $ldap_protocol) = $sth->fetchrow;

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
	return ($ldap, $ldap_url_attr, $ldap_uid_attr, $ldap_user_filter, $ldap_group_filter, $ldap_user_scope, $ldap_group_scope, $ldap_base_dn, $ldap_group_member, $ldap_group_is_dn, $ldap_group_attr);
}

sub getStyle {
    my ($r, $log, $dbh, $app, $type) = @_;
    
    #
    # ONLY FOR SQLITE3
    #
    
    #Querying database for style
    my $intf_id = $r->dir_config('VultureID');
	my $query = "SELECT CASE WHEN app.style_id NOT NULL THEN app.style_id WHEN intf.style_id NOT NULL THEN intf.style_id ELSE '' END AS 'id_style', style_style.name, style_css.value AS css, style_image.image AS image, style_tpl.value AS tpl FROM app,intf, style_tpl_mapping, style_tpl LEFT JOIN style_style ON style_style.id = id_style LEFT JOIN style_css ON style_css.id = style_style.css_id LEFT JOIN style_image ON style_image.id = style_style.image_id WHERE app.id= ".$app->{id}." AND intf.id = ".$intf_id." AND style_tpl_mapping.style_id = id_style AND style_tpl.id = style_tpl_mapping.tpl_id AND style_tpl.type = '".uc($type)."'";
    $log->debug($query);
    $sth = $dbh->prepare($query);
	$sth->execute;
	my $ref = $sth->fetchrow_hashref;
	$sth->finish();
	return $ref;
}

sub getTranslations {
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
            my $query = "SELECT count(*) FROM style_translation WHERE country = '".$tag->{lclanguage}."'";
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
        my $message_query = "message = 'USER' OR message = 'PASSWORD'";
        $message_query .= " OR message = '".$message."'" if defined $message;

        my $query = "SELECT message, translation FROM style_translation WHERE (".$message_query.") AND (".$language_query.")";        
        $log->debug($query);

        $translated_messages = $dbh->selectall_hashref($query,'message');
        return $translated_messages;
    }
}

sub generate_random_string
{
	my $length_of_randomstring=shift;# the length of 
			 # the random string to generate

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

1;
