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

	my $query = "SELECT host, port, secret, timeout, url_attr FROM radius WHERE id= ?";
	my $sth = $dbh->prepare($query);
	$sth->execute($id_method);
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
					$r->pnotes('response_content') = '<html><head><meta http-equiv="Refresh" content="0; url='.$a->{'Value'}.'"></head></html>';
					$log->debug($user . " routed to ". $a->{'Value'});
				}
			}
    }
		return Apache2::Const::OK;
	}
    return Apache2::Const::FORBIDDEN;
}
1;
