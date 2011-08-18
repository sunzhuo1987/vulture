#file:Auth/Auth_SQL.pm
#---------------------------------
package Auth::Auth_SQL;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Connection ();
use Apache2::Log;
use Apache2::Reload;

use Data::Dumper;

use Digest::MD5 qw(md5_hex md5_base64);
use Digest::SHA1  qw(sha1_hex sha1_base64);

use DBI;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkAuth{
	my ($package_name, $r, $log, $dbh, $app, $user, $password, $id_method) = @_;	

	$log->debug("########## Auth_SQL ##########");

	my $query = "SELECT * FROM sql WHERE id='".$id_method."'";
	my $sth = $dbh->prepare($query);
	$log->debug($query);
	$sth->execute;
	my $ref = $sth->fetchrow_hashref;
	$sth->finish();
	
	#We know where to select user to check credentials. Let's connect to this new database and check if user exists
	if($ref){
		#Build a driver like this one dbi:SQLite:dbname=/home/pquetelart/vulture2/trunk/www/db
		my $dsn = 'dbi:'.$ref->{'driver'}.':dbname='.$ref->{'database'};
		if($ref->{'host'}){
			$dsn .=':'.$ref->{'host'};
			if($ref->{'port'}){
				$dsn .=':'.$ref->{'port'};
			}
		}
		my $new_dbh = DBI->connect($dsn, $ref->{'user'}, $ref->{'password'});
		
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
