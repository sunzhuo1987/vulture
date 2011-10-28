#file:Core/AccessHandler.pm
#-------------------------
package Core::AccessHandler;

use Apache2::RequestRec ();
use Apache2::Reload;
use Apache2::Log;

use DBI;

use Apache2::Const -compile => qw(FORBIDDEN OK);

#Particular IP blacklisting (in Application) (different from PreConnectionHandler (global blacklisting))
sub handler {
	my $r = shift;
	my $log = $r->pnotes('log');

	$log->debug("########## AccessHandler ##########");

	my $c = $r->connection(); 
	
	unless (defined $c and $c->remote_ip){
	    warn "Can't read remote ip\n";
	    return Apache2::Const::FORBIDDEN;
	}
	
	my $dbh = $r->pnotes('dbh');
	my $app_id = $r->pnotes('app')->{'id'} if defined($r->pnotes('app'));

	my $query = "SELECT count(*) FROM blackip WHERE ip=? AND app_id=?";
	if (not $dbh or not $app_id or $dbh->selectrow_array(($query, undef, $c->remote_ip, $app_id))){
		$log->error('IP '.$c->remote_ip.' is blocked\n');
	 	return Apache2::Const::FORBIDDEN;	
	} else {
		$log->debug('White IP '.$c->remote_ip);
		$r->status(200);
		return Apache2::Const::OK;
	}
}
1;
