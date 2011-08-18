#file:Core/VultureUtils.pm
#-------------------------
package Core::VultureUtils;
our $VERSION = '2.0';

BEGIN {
    use Exporter ();
    @ISA = qw(Exporter);
    @EXPORT_OK = qw(&version_check &get_app &get_intf &session &get_cookie &get_memcached &set_memcached);
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
	) if not defined $memd;

	return $memd->get($key);
}

sub	set_memcached {
	my ($key, $value, $exptime) = @_; 
	my $memd = Cache::Memcached->new(
	  servers            => [ "127.0.0.1:9091" ],
	  debug              => 0,
	  compress_threshold => 10_000,
	) if not defined $memd;

	$exptime= $exptime || 6_000;
        if ( $exptime > 6_000 ) {
                $exptime= 6_000;
        }


	return $memd->set($key, $value, $exptime);
}

sub	session {
	my ($session, $timeout, $id, $log, $n) = @_;

	die if ($n and $n > 2); # avoid deep recursion
#	eval {
#		tie %$session,'Apache::Session::Flex',$id,{
#							   Store => 'MySQL',
#							   Lock  => 'Null',
#							   Generate => 'MD5',
#							   Serialize => 'Base64',
#							   DataSource => 'dbi:SQLite2:dbname=/var/www/vulture/sql/sessions',
#							  }
#	} or session($session, $timeout, undef, $n + 1);
    eval {
        tie %{$session}, 'Apache::Session::Flex', $id, {
				          Store     => 'Memcached',
				          Lock      => 'Null',
				          Generate  => 'MD5',
				          Serialize => 'Storable',
				          Servers => '127.0.0.1:9091',
				         };
    } or session($session, $timeout, undef, $log, $n + 1);

	#Debug for eval
	$log->debug ($@) if ($@ and $log);

	#$session->{date} = time() if (!$session->{posted});
	#undef $session->{posted} if ($timeout and time() - $session->{date} > $timeout);
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
	my $query = "SELECT app.id,name, url, app.log_id, logon_url, logout_url,intf.remote_proxy, up, auth_basic, display_portal FROM app, intf WHERE app.intf_id='".$intf."' AND app.name = '".$host."' AND intf.id='".$intf."'";
	#$log->debug($query);
	$sth = $dbh->prepare($query);
	$sth->execute;
	my $ref = $sth->fetchrow_hashref;
	$sth->finish();

    #Getting auth
    my $query = "SELECT auth.name, auth.auth_type, auth.id_method FROM auth, auth_multiple WHERE auth_multiple.app_id = '".$ref->{id}."' AND auth_multiple.auth_id = auth.id";
    $ref->{'auth'} = $dbh->selectall_arrayref($query);

    #Getting ACL
    $query = "SELECT acl.id, acl.name, auth.auth_type AS acl_type, id_method FROM acl, auth, app WHERE app.id = '".$ref->{id}."' AND acl.id = app.acl_id AND auth.id = acl.auth_id";
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
1;
