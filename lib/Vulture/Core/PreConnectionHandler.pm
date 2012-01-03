#file:Core/PreConnectionHandler.pm
#-------------------------
package Core::PreConnectionHandler;

use Apache2::Connection ();
use Apache2::Reload;

use DBI;

use Apache2::Const -compile => qw(FORBIDDEN OK);

#General IP blacklisting
sub handler {
	warn "########## PreConnectionHandler ##########";
	my $c = shift;
	
	#if we can't get the remote IP, refuse connection
	unless (defined $c and $c->remote_ip){
	    warn "Can't read remote ip\n";
	    return Apache2::Const::FORBIDDEN;
	}

	#Querying database
	my $dbh = DBI->connect("dbi:SQLite:dbname=/var/www/vulture/admin/db");
	my $query = "SELECT count(*) FROM blackip WHERE ip=? AND app_id IS NULL";
	#refuse connection from  global blackIP
	if (not $dbh or $dbh->selectrow_array(($query, undef, $c->remote_ip))){ 
		warn 'IP '.$c->remote_ip.' is blocked by PreConnectionHandler\n';
	 	return Apache2::Const::FORBIDDEN;	
	} else {
		warn 'White IP '.$c->remote_ip.' by PreConnectionHandler\n';
		return Apache2::Const::OK;
	}
}

1;
