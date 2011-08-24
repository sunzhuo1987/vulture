#file:Auth/Auth_RADIUS.pm
#---------------------------------
package Auth::Auth_RADIUS;

use Apache2::Reload;
use Apache2::Log;

use DBI;

use Authen::Radius;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkAuth{
	my ($package_name, $r, $log, $dbh, $app, $user, $password, $id_method) = @_;

	$log->debug("########## Auth_RADIUS ##########");

	my ($log, $app, $dbh, $session) = @_;

	my $query = "SELECT host, port, secret, timeout, url_attr FROM radius WHERE id='".$id_method."'";
	my $sth = $dbh->prepare($query);
	$sth->execute();
	my ($host, $port, $secret, $timeout, $url_attr) = $sth->fetchrow;
	my $radius = Authen::Radius->new(
					 Host => $host.":".$port,
					 Secret => $secret,
					 TimeOut => $timeout
					);
	return Apache2::Const::FORBIDDEN if (!defined $radius);
	if ($radius->check_pwd($user,$password))
		{
		if (defined $url_attr) {
			Authen::Radius->load_dictionary();
			for $a ($radius->get_attributes) {
				$log->debug("Attribut list". $a->{'Name'});
				if ($a->{'Name'} eq $url_attr ) {
					$r->pnotes('url_to_mod_proxy' => $a->{'Value'});
					$log->debug($user . " routed to ". $a->{'Value'} ." via mod_proxy");
				}
			}
		}
		return Apache2::Const::OK;
	}
}
1;
