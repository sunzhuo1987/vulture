#file:Auth/Auth_NTLM.pm
#---------------------------------
package Auth::Auth_NTLM;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Connection ();
use Apache2::Log;
use Apache2::Reload;
use Apache2::Access;
use Authen::Smb;

use Data::Dumper;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkAuth{
	my ($package_name, $r, $log, $dbh, $app, $user, $password, $id_method) = @_;	

	$log->debug("########## Auth_NTLM ##########");

	my $query = "SELECT * FROM ntlm WHERE id='".$id_method."'";
        my $sth = $dbh->prepare($query);
        $log->debug($query);
        $sth->execute;
        my $ref = $sth->fetchrow_hashref;
        $sth->finish();

	$log->debug("########## Auth_NTLM -> ".$ref->{'name'}." ##########");

	my $domain      = $ref->{'domain'};
	my $pdc         = $ref->{'primary_dc'};
	my $bdc         = $ref->{'secondary_dc'};
	my $protocol    = $ref->{'protocol'};

	my $authResult = Authen::Smb::authen($user, $password, $pdc, $bdc, $domain);

	if ( $authResult == Authen::Smb::NO_ERROR ) {
		$log->debug("User is ok for Auth_NTLM;");
		$r->user($user);
 		return Apache2::Const::OK;
	}
	else {
		$log->debug("User is bad for Auth_NTLM;");
		return Apache2::Const::FORBIDDEN;
	}
}
1;
