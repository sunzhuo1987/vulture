#file:ACL/ACL_SQL.pm
#---------------------------------
package ACL::ACL_SQL;

use Apache2::Reload;
use Apache2::Log;

use DBI;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkACL{
	my ($package_name, $r, $log, $dbh, $app, $user, $id_method) = @_;

	$log->debug("########## ACL_SQL ##########");

	my $query = "SELECT count(*) FROM userok,acl_userok WHERE acl_userok.acl_id = ? AND userok.user=?";
	$log->debug($query);

	if ($dbh->selectrow_array(($query, undef, $app->{'acl'}->{'id'}, $user))){
		return Apache2::Const::OK;
	} else {
		return Apache2::Const::FORBIDDEN;	
	}
}
1;
