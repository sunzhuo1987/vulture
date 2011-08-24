#file:Core/AccessHandler.pm
#-------------------------
package Core::AccessHandler;

use Apache2::RequestRec ();
use Apache2::Reload;
use Apache2::Log;

use DBI;

use Apache2::Const -compile => qw(FORBIDDEN OK);

use Data::Dumper;

#Particular IP blacklisting (in Application) (different from PreConnectionHandler (global blacklisting))
sub handler {
	my $r = shift;
	my $log = $r->pnotes('log');

	$log->debug("########## AccessHandler ##########");

	my $c = $r->connection(); 
	my $ip = $c->remote_ip if defined($c);
	my $dbh = $r->pnotes('dbh');
	my $app_id = $r->pnotes('app')->{'id'} if defined($r->pnotes('app'));

	my $query = "SELECT count(*) FROM blackip WHERE ip=? AND app_id=?";
	if ($dbh->selectrow_array(($query, undef, $ip, $app_id))){
		$log->error("IP $ip is blocked\n");
	 	return Apache2::Const::FORBIDDEN;	
	} else {
		$log->debug("White IP $ip");
		$r->status(200);
		return Apache2::Const::OK;
	}
}
1;
