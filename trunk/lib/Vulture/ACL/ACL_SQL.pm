#file:ACL/ACL_SQL.pm
#---------------------------------
#!/usr/bin/perl

package ACL::ACL_SQL;

use strict;
use warnings;

use Apache2::Reload;
use Apache2::Log;

use DBI;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkACL{
	my ($package_name, $r, $log, $dbh, $app, $user, $id_method) = @_;

	$log->debug("########## ACL_SQL ##########");

	my $query = "SELECT count(*) FROM userok,acl_userok WHERE userok.user = ? AND acl_userok.userok_id = userok.id AND acl_id = ?";
	$log->debug($query);

	if ($dbh->selectrow_array(($query, undef, $user,$app->{'acl'}->{'id'}))){
		return Apache2::Const::OK;
	} else {
		return Apache2::Const::FORBIDDEN;	
	}
}
1;
