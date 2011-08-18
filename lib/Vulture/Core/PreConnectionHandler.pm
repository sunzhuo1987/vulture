#file:Core/PreConnectionHandler.pm
#-------------------------
package Core::PreConnectionHandler;

use Apache2::Connection ();
use Apache2::Reload;

use DBI;

use Apache2::Const -compile => qw(FORBIDDEN OK);

#General IP blacklisting
sub handler {
	warn "PreConnectionHandler";
	my $c = shift;
	my $ip = $c->remote_ip if defined($c);

	#Querying database
	my $dbh = DBI->connect("dbi:SQLite:dbname=/var/www/vulture/www/db");
	my $query = "SELECT count(*) FROM blackip WHERE ip=? AND app_id IS NULL";
	if ($dbh->selectrow_array(($query, undef, $ip))){ 
		warn "	IP $ip is blocked by PreConnectionHandler\n";
	 	return Apache2::Const::FORBIDDEN;	
	} else {
		warn "	White IP $ip by PreConnectionHandler\n";
		return Apache2::Const::OK;
	}
}

1;
