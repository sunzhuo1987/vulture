#file:Auth/Auth_SQL.pm
#---------------------------------
package Auth::Auth_SQL;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Connection ();
use Apache2::Log;
use Apache2::Reload;

use Digest::MD5 qw(md5_hex md5_base64);
use Digest::SHA1  qw(sha1_hex sha1_base64);

use DBI;

use Apache2::Const -compile => qw(OK FORBIDDEN);

use Core::VultureUtils qw(&getDB_object);

sub checkAuth{
	my ($package_name, $r, $log, $dbh, $app, $user, $password, $id_method) = @_;	

	$log->debug("########## Auth_SQL ##########");

	my ($new_dbh, $ref) = getDB_object($log, $dbh, $id_method);
    if($new_dbh and $ref){		
		#Password encryption
		if ($ref->{'pass_algo'} eq "plain") {
			#Nothing to do
		} elsif ($ref->{'pass_algo'} eq "sha1") {
			$password = sha1_hex($password);
		} elsif ($ref->{'pass_algo'} eq "md5") {
			$password = md5_hex($password);
		}

		#Checking credentials
		my $query = "SELECT count(*) FROM ".$ref->{'table'}." WHERE ".$ref->{'user_column'}."=? AND ".$ref->{'pass_column'}."=?";
		$log->debug($query."=>".$user."=>".$password);
		if ($new_dbh->selectrow_array($query, undef, $user, $password)){
			$log->debug("User is ok for Auth_SQL;");
		 	return Apache2::Const::OK;	
		} else {
			$log->debug("User is bad for Auth_SQL;");
			return Apache2::Const::FORBIDDEN;
		}
	}
	return Apache2::Const::FORBIDDEN;
}
1;
