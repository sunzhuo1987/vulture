#file:Auth/Auth_EXAMPLE.pm
#---------------------------------
package Auth::Auth_EXAMPLE;

use Apache2::Reload;
use Apache2::Log;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkAuth{
	my ($package_name, $r, $log, $dbh, $app, $user, $password, $id_method) = @_;

	$log->debug("########## Auth_EXAMPLE ##########");

	if($USER_OK){
	 	return Apache2::Const::OK;	
	} else {
		return Apache2::Const::FORBIDDEN
	}
}
1;
